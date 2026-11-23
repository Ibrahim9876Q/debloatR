use crate::{
    actions,
    scan::{Monitor, Row, mem, stamp, wide},
    trend::Identity,
};
use std::{
    cmp::Ordering,
    collections::VecDeque,
    mem::zeroed,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::LibraryLoader::GetModuleHandleW,
    UI::{Controls::*, WindowsAndMessaging::*},
};

const NAV: i32 = 10;
const SEARCH: i32 = 21;
const TABLE: i32 = 22;
const SORT: i32 = 23;
const ORDER: i32 = 24;
const REPORT: i32 = 25;
const INTERVAL: i32 = 26;
const SUMMARY: i32 = 27;
const HEADER: i32 = 28;
const TITLE: i32 = 29;
const STATUS: i32 = 30;
const SEARCH_LABEL: i32 = 31;
const ACTION: i32 = 40;
const EVENT: u32 = WM_APP + 1;
const LAYOUT: u32 = WM_APP + 2;
const START: i32 = 45;
const INTRO: i32 = 46;
const NAV_NAMES: [&str; 6] = [
    "Processes",
    "Leak watch",
    "Discrepancies",
    "Action log",
    "Metric guide",
    "Scan results",
];
const ACTIONS: [&str; 5] = [
    "Open location",
    "Copy path",
    "Request close",
    "End process",
    "Uninstall...",
];
const SORTS: [&str; 5] = ["Name", "PID", "Private WS", "Total WS", "Private bytes"];
const WHITE: u32 = 0xffffff;
fn set(w: HWND, s: &str) {
    unsafe {
        SetWindowTextW(w, wide(s).as_ptr());
    }
}
fn get(w: HWND) -> String {
    unsafe {
        let mut b = vec![0; GetWindowTextLengthW(w) as usize + 1];
        let n = GetWindowTextW(w, b.as_mut_ptr(), b.len() as i32);
        String::from_utf16_lossy(&b[..n as usize])
    }
}
fn draw(dc: HDC, r: &RECT, s: &str, selected: bool, flags: u32) {
    unsafe {
        let (fg, bg) = if selected {
            (0, WHITE_BRUSH)
        } else {
            (WHITE, BLACK_BRUSH)
        };
        FillRect(dc, r, GetStockObject(bg) as _);
        SetTextColor(dc, fg);
        SetBkMode(dc, TRANSPARENT as _);
        let mut rect = *r;
        rect.left += 4;
        rect.right -= 4;
        DrawTextW(
            dc,
            wide(s).as_ptr(),
            -1,
            &mut rect,
            flags | DT_NOPREFIX | DT_SINGLELINE | DT_VCENTER,
        );
    }
}
unsafe extern "system" fn proc(w: HWND, msg: u32, a: usize, b: isize) -> isize {
    unsafe {
        match msg {
            WM_COMMAND => {
                let id = (a & 65535) as i32;
                let code = a >> 16;
                if (id == SEARCH && code == EN_CHANGE as usize) || (id != SEARCH && code == 0) {
                    PostMessageW(w, EVENT, id as usize, 0);
                }
                0
            }
            WM_SIZE => {
                PostMessageW(w, LAYOUT, 0, 0);
                0
            }
            WM_GETMINMAXINFO => {
                let m = &mut *(b as *mut MINMAXINFO);
                m.ptMinTrackSize = POINT { x: 850, y: 570 };
                0
            }
            WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX => {
                let dc = a as HDC;
                SetTextColor(dc, WHITE);
                SetBkColor(dc, 0);
                GetStockObject(BLACK_BRUSH) as isize
            }
            WM_DRAWITEM => {
                let d = &*(b as *const DRAWITEMSTRUCT);
                let selected = d.itemState & ODS_SELECTED != 0;
                if d.CtlID == TABLE as u32 {
                    if d.itemID != u32::MAX {
                        let n = SendMessageW(d.hwndItem, LB_GETTEXTLEN, d.itemID as usize, 0);
                        if n >= 0 {
                            let mut buf = vec![0; n as usize + 1];
                            SendMessageW(
                                d.hwndItem,
                                LB_GETTEXT,
                                d.itemID as usize,
                                buf.as_mut_ptr() as isize,
                            );
                            let text = String::from_utf16_lossy(&buf[..n as usize]);
                            let width = d.rcItem.right - d.rcItem.left;
                            for ((left, right), cell) in
                                [(0, 25), (25, 34), (34, 49), (49, 64), (64, 80), (80, 100)]
                                    .into_iter()
                                    .zip(text.split('\t'))
                            {
                                let mut rect = d.rcItem;
                                rect.left += width * left / 100;
                                rect.right = d.rcItem.left + width * right / 100;
                                draw(d.hDC, &rect, cell, selected, DT_LEFT | DT_END_ELLIPSIS);
                            }
                        }
                    }
                } else {
                    draw(d.hDC, &d.rcItem, &get(d.hwndItem), selected, DT_CENTER);
                    FrameRect(d.hDC, &d.rcItem, GetStockObject(GRAY_BRUSH) as _);
                }
                if d.itemState & ODS_FOCUS != 0 {
                    let mut r = d.rcItem;
                    InflateRect(&mut r, -2, -2);
                    DrawFocusRect(d.hDC, &r);
                }
                1
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(w, msg, a, b),
        }
    }
}
fn compare(a: &Row, b: &Row, col: usize, desc: bool) -> Ordering {
    let order = match col {
        0 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        1 => a.pid.cmp(&b.pid),
        _ => {
            let field = |r: &Row| [r.private, r.ws, r.commit][col - 2];
            match (field(a), field(b)) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => return Ordering::Less,
                (None, Some(_)) => return Ordering::Greater,
                _ => Ordering::Equal,
            }
        }
    };
    if desc { order.reverse() } else { order }
}
struct App {
    w: HWND,
    font: HFONT,
    monitor: Monitor,
    page: usize,
    interval: usize,
    sort: usize,
    desc: bool,
    displayed: Vec<(u32, Option<Identity>)>,
    log: VecDeque<String>,
    notice: String,
}
impl App {
    fn item(&self, id: i32) -> HWND {
        unsafe { GetDlgItem(self.w, id) }
    }
    fn create(&self, class: &str, s: &str, id: i32, style: u32) {
        unsafe {
            let h = CreateWindowExW(
                0,
                wide(class).as_ptr(),
                wide(s).as_ptr(),
                WS_CHILD | style,
                0,
                0,
                1,
                1,
                self.w,
                id as usize as _,
                GetModuleHandleW(null()),
                null(),
            );
            assert!(!h.is_null(), "Unable to create {class}");
            SendMessageW(h, WM_SETFONT, self.font as usize, 0);
        }
    }
    fn init(&self) {
        for (id, label) in [
            (TITLE, "debloatR"),
            (SUMMARY, ""),
            (HEADER, "Process"),
            (STATUS, ""),
            (SEARCH_LABEL, "Search processes"),
        ] {
            self.create("STATIC", label, id, 0)
        }
        for (i, n) in NAV_NAMES.iter().enumerate() {
            self.button(NAV + i as i32, n)
        }
        self.create("STATIC","See which apps use your memory, check for sustained growth, and review background activity.",INTRO,0);
        for (i, label) in [
            "PID",
            "Private working set",
            "Total working set",
            "Private bytes",
        ]
        .iter()
        .enumerate()
        {
            self.create("STATIC", label, 50 + i as i32, 0);
        }
        self.button(START, "Scan device");
        self.button(INTERVAL, "Sample: 5 s");
        self.button(SORT, "Sort: Private WS");
        self.button(ORDER, "Descending");
        for (i, n) in ACTIONS.iter().enumerate() {
            self.button(ACTION + i as i32, n)
        }
        self.create(
            "EDIT",
            "",
            SEARCH,
            WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
        );
        unsafe {
            SendMessageW(
                self.item(SEARCH),
                EM_SETCUEBANNER,
                1,
                wide("Search name or PID").as_ptr() as isize,
            );
        }
        self.create(
            "LISTBOX",
            "",
            TABLE,
            WS_VSCROLL
                | WS_BORDER
                | WS_TABSTOP
                | (LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS | LBS_NOTIFY) as u32,
        );
        unsafe {
            SendMessageW(self.item(TABLE), LB_SETITEMHEIGHT, 0, 21);
        }
        self.create(
            "EDIT",
            "",
            REPORT,
            WS_BORDER
                | WS_TABSTOP
                | WS_VSCROLL
                | (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32,
        );
    }
    fn button(&self, id: i32, s: &str) {
        self.create("BUTTON", s, id, WS_TABSTOP | BS_OWNERDRAW as u32)
    }
    fn place(&self, id: i32, x: i32, y: i32, w: i32, h: i32, show: bool) {
        unsafe {
            let c = self.item(id);
            if show {
                MoveWindow(c, x, y, w, h, 1);
                ShowWindow(c, SW_SHOWNA);
            } else {
                ShowWindow(c, SW_HIDE);
            }
        }
    }
    fn layout(&self) {
        unsafe {
            let mut r = zeroed();
            GetClientRect(self.w, &mut r);
            let (w, h) = (r.right, r.bottom);
            let landing = self.page == 6;
            self.place(INTRO, 32, h / 2 - 60, w - 64, 52, landing);
            self.place(START, 32, h / 2, 160, 42, landing);
            if landing {
                self.place(TITLE, 32, h / 2 - 120, 400, 50, true);
                return;
            }
            let p = self.page == 0;
            self.place(TITLE, 16, 1, w - 190, 40, true);
            self.place(INTERVAL, w - 160, 8, 144, 27, true);
            self.place(SUMMARY, 16, 42, w - 32, 84, true);
            for (i, n) in NAV_NAMES.iter().enumerate() {
                let id = NAV + i as i32;
                set(
                    self.item(id),
                    &if self.page == i {
                        format!("●  {n}")
                    } else {
                        n.to_string()
                    },
                );
                self.place(
                    id,
                    16 + i as i32 * ((w - 32) / 6),
                    133,
                    (w - 48) / 6,
                    29,
                    true,
                );
            }
            self.place(SEARCH_LABEL, 16, 178, 149, 22, p);
            self.place(SEARCH, 165, 174, (w - 479).min(360), 27, p);
            self.place(SORT, w - 301, 174, 168, 27, p);
            self.place(ORDER, w - 127, 174, 111, 27, p);
            self.place(HEADER, 20, 211, (w - 50) / 4, 22, p);
            for (i, pct) in [25, 34, 49, 64].into_iter().enumerate() {
                self.place(
                    50 + i as i32,
                    20 + (w - 50) * pct / 100,
                    211,
                    (w - 50) * 14 / 100,
                    22,
                    p,
                );
            }
            self.place(TABLE, 16, 234, w - 32, h - 310, p);
            self.place(REPORT, 16, 176, w - 32, h - 221, !p);
            for i in 0..5 {
                self.place(ACTION + i, 16 + i * 148, h - 66, 140, 29, p);
            }
            self.place(STATUS, 16, h - 28, w - 32, 23, true);
        }
    }
    fn selected(&self) -> Option<&Row> {
        let pos = unsafe { SendMessageW(self.item(TABLE), LB_GETCURSEL, 0, 0) };
        let key = self.displayed.get(pos as usize)?;
        self.monitor.rows.iter().find(|r| (r.pid, r.id) == *key)
    }
    fn refresh(&mut self, chosen: Option<Identity>) {
        let m = &self.monitor;
        let s = &m.system;
        if self.page == 6 {
            return;
        }
        set(
            self.item(SUMMARY),
            &format!(
                "Physical memory     {} in use     ·     {} available\r\nInstalled     {}     ·     Usable     {}\r\nCommitted memory     {} of {}\r\nMeasured private memory     {} across {} of {} processes",
                mem(s.used),
                mem(s.available),
                mem(s.installed),
                mem(s.usable),
                mem(s.commit),
                mem(s.limit),
                mem(m.sum),
                m.measured,
                m.rows.len()
            ),
        );
        set(
            self.item(STATUS),
            &format!(
                "{}  |  {}",
                m.sampled,
                if self.notice.is_empty() {
                    &m.comparison
                } else {
                    &self.notice
                }
            ),
        );
        if self.page == 0 {
            self.table(chosen);
            return;
        }
        let content = match self.page {
            5 => crate::review::report(m),
            1 => {
                let mut lines = vec![
                    "LEAK WATCH  /  private-byte growth".into(),
                    "Counters can suggest a leak. Caches and legitimate workloads can also grow."
                        .into(),
                    String::new(),
                ];
                let mut waiting = 0;
                let mut flags = 0;
                for r in &m.rows {
                    if let Some(h) = m.history(r) {
                        if !h.ready() {
                            waiting += 1
                        }
                        if let Some(f) = h.finding() {
                            flags += 1;
                            lines.push(format!("{}  PID {}\r\n{}\r\n", r.name, r.pid, f));
                        }
                    }
                }
                lines.push(format!(
                    "{flags} suspected  /  {waiting} collecting history  /  {} untracked",
                    m.rows.iter().filter(|r| m.history(r).is_none()).count()
                ));
                lines.push(
                    "Requires 7 observations, 60 seconds and growth across three windows.".into(),
                );
                lines.push("\r\nKERNEL POOLS  /  system-wide growth".into());
                for (i, n) in ["Paged", "Nonpaged"].iter().enumerate() {
                    let h = &m.pools[i];
                    let available = [s.paged, s.nonpaged][i].is_some();
                    lines.push(format!(
                        "{n}: {}",
                        h.finding().unwrap_or_else(|| if !available {
                            "unknown"
                        } else if h.ready() {
                            "no sustained growth"
                        } else {
                            "collecting history"
                        }
                        .into())
                    ))
                }
                lines.join("\r\n")
            }
            2 => {
                let mut lines=vec![format!("SYSTEM MEMORY  /  outside measured private working sets\r\n{}\r\n",mem(m.residual())),format!("System cache {}    Paged pool {}    Nonpaged pool {}",mem(s.cache),mem(s.paged),mem(s.nonpaged)),format!("Compression process private working set {} (estimate of store footprint).",mem(s.compression)),
                "Shared pages appear in multiple working sets. Unique shared total: unknown.".into(),
                "Cache includes standby pages; paged pool includes nonresident allocations.".into(),
                "These figures overlap. The residual includes shared pages and inaccessible processes.".into(),
                "\r\nPROCESS ENUMERATION  /  current scan".into(),m.comparison.clone(),
                format!("{} rows have a measurement or identity error.",m.rows.iter().filter(|r|!r.status.is_empty()).count()),
                "One-source PIDs are retried next scan. Access failures alone do not count.".into(),
                "Task Manager > Details > PID. Right-click a column header to select PID.".into(),
                "User-mode snapshots can miss activity. A RAM gap cannot identify a hidden app.".into(),
                "\r\nPERSISTENT DISCREPANCIES  /  session observations".into()];
                lines.insert(1, crate::review::attribution(m));
                if m.records.is_empty() {
                    lines.push("None confirmed on consecutive complete scans.".into())
                } else {
                    lines.extend(m.records.iter().cloned())
                }
                lines.join("\r\n")
            }
            4 => GUIDE.replace("\n", "\r\n"),
            _ => {
                if self.log.is_empty() {
                    "ACTION LOG\r\n\r\nNo actions this session.".into()
                } else {
                    self.log
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\r\n\r\n")
                }
            }
        };
        let report = self.item(REPORT);
        if get(report) != content {
            unsafe {
                let first = SendMessageW(report, EM_GETFIRSTVISIBLELINE, 0, 0);
                set(report, &content);
                SendMessageW(report, EM_LINESCROLL, 0, first);
            }
        }
    }
    fn table(&mut self, chosen: Option<Identity>) {
        let q = get(self.item(SEARCH)).to_lowercase();
        let rows = &self.monitor.rows;
        let mut indices: Vec<_> = (0..rows.len())
            .filter(|i| {
                let r = &rows[*i];
                r.name.to_lowercase().contains(&q) || r.pid.to_string().contains(&q)
            })
            .collect();
        indices.sort_by(|a, b| {
            compare(&rows[*a], &rows[*b], self.sort, self.desc)
                .then(rows[*a].pid.cmp(&rows[*b].pid))
        });
        let w = self.item(TABLE);
        unsafe {
            let top = SendMessageW(w, LB_GETTOPINDEX, 0, 0);
            SendMessageW(w, WM_SETREDRAW, 0, 0);
            SendMessageW(w, LB_RESETCONTENT, 0, 0);
            self.displayed.clear();
            for (pos, i) in indices.iter().enumerate() {
                let r = &rows[*i];
                self.displayed.push((r.pid, r.id));
                let name = r.name.chars().take(28).collect::<String>();
                let line = format!(
                    "{name}\t{}\t{}\t{}\t{}\t{}",
                    r.pid,
                    mem(r.private),
                    mem(r.ws),
                    mem(r.commit),
                    r.status
                );
                SendMessageW(w, LB_ADDSTRING, 0, wide(&line).as_ptr() as isize);
                if chosen.is_some() && chosen == r.id {
                    SendMessageW(w, LB_SETCURSEL, pos, 0);
                }
            }
            SendMessageW(w, LB_SETTOPINDEX, top.max(0) as usize, 0);
            SendMessageW(w, WM_SETREDRAW, 1, 0);
            InvalidateRect(w, null(), 1);
        }
    }
    fn ask(&self, s: &str) -> bool {
        unsafe {
            MessageBoxW(
                self.w,
                wide(s).as_ptr(),
                wide("debloatR | Confirm action").as_ptr(),
                MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
            ) == IDYES
        }
    }
    fn action(&mut self, n: usize) {
        let selected = self.selected().map(|r| (r.name.clone(), r.pid, r.id));
        let target = selected
            .as_ref()
            .map(|(name, pid, _)| format!("{name} (PID {pid})"))
            .unwrap_or_else(|| "no selection".into());
        let result = (|| {
            let (_, _, id) = selected.ok_or("Select a process first")?;
            let id = id.ok_or("Process identity unavailable")?;
            match n{
                0=>actions::location(id),1=>actions::copy(id,self.w),2=>actions::close(id),
                3=>if self.ask(&format!("End {target}?\n\nEnding this process can release RAM immediately. Unsaved work may be lost.")){actions::end(id)}else{Ok("Cancelled".into())},
                _=>{let u=actions::uninstaller(id)?;if self.ask(&format!("Launch the registered uninstaller for {}?\n\nSelected: {target}\nCommand: {}\n\nUninstalling removes the app from this machine.",u.name,u.command)){actions::uninstall(id,&u)}else{Ok("Cancelled".into())}}
            }
        })();
        let detail = result.unwrap_or_else(|e| format!("Failed: {e}"));
        self.notice = format!("{}: {detail}", ACTIONS[n]);
        self.log.push_front(format!(
            "{}  |  {}  |  {target}\r\n{detail}",
            stamp(),
            ACTIONS[n]
        ));
        self.log.truncate(128);
    }
    fn event(&mut self, id: i32) {
        let chosen = self.selected().and_then(|r| r.id);
        match id {
            START => {
                self.monitor.sample();
                self.page = 5;
                self.layout();
                unsafe {
                    SetTimer(self.w, 1, 5000, None);
                }
            }
            10..=15 => {
                self.page = (id - NAV) as usize;
                self.layout();
            }
            SORT => {
                self.sort = (self.sort + 1) % 5;
                self.desc = self.sort >= 2;
                set(self.item(SORT), &format!("Sort: {}", SORTS[self.sort]));
            }
            ORDER => self.desc = !self.desc,
            INTERVAL => {
                self.interval = match self.interval {
                    5 => 10,
                    10 => 30,
                    30 => 2,
                    _ => 5,
                };
                unsafe {
                    SetTimer(self.w, 1, (self.interval * 1000) as u32, None);
                }
                set(self.item(INTERVAL), &format!("Sample: {} s", self.interval));
            }
            SEARCH => {}
            40..=44 => self.action((id - ACTION) as usize),
            _ => return,
        }
        set(
            self.item(ORDER),
            if self.desc { "Descending" } else { "Ascending" },
        );
        self.refresh(chosen);
    }
}
pub fn run() {
    unsafe {
        let class = wide("DebloatRMonitorWindow");
        let instance = GetModuleHandleW(null());
        let wc = WNDCLASSW {
            lpfnWndProc: Some(proc),
            hInstance: instance,
            lpszClassName: class.as_ptr(),
            hbrBackground: GetStockObject(BLACK_BRUSH) as _,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            ..zeroed()
        };
        RegisterClassW(&wc);
        let w = CreateWindowExW(
            WS_EX_CONTROLPARENT,
            class.as_ptr(),
            wide("debloatR | Memory monitor").as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1040,
            720,
            null_mut(),
            null_mut(),
            instance,
            null(),
        );
        assert!(!w.is_null(), "Window creation failed");
        let font = CreateFontW(
            -16,
            0,
            0,
            0,
            400,
            0,
            0,
            0,
            1,
            0,
            0,
            5,
            0,
            wide("Segoe UI").as_ptr(),
        );
        let mut app = App {
            w,
            font,
            monitor: Monitor::new(),
            page: 6,
            interval: 5,
            sort: 2,
            desc: true,
            displayed: vec![],
            log: VecDeque::new(),
            notice: String::new(),
        };
        app.init();
        let heading = CreateFontW(
            -30,
            0,
            0,
            0,
            600,
            0,
            0,
            0,
            1,
            0,
            0,
            5,
            0,
            wide("Segoe UI").as_ptr(),
        );
        SendMessageW(app.item(TITLE), WM_SETFONT, heading as usize, 0);
        app.layout();

        ShowWindow(w, SW_SHOWNORMAL);

        let mut msg = zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if msg.hwnd == w {
                match msg.message {
                    EVENT => {
                        app.event(msg.wParam as i32);
                        continue;
                    }
                    LAYOUT => {
                        if IsIconic(w) == 0 {
                            let id = app.selected().and_then(|r| r.id);
                            app.layout();
                            app.refresh(id)
                        }
                        continue;
                    }
                    WM_TIMER => {
                        let chosen = app.selected().and_then(|r| r.id);
                        app.monitor.sample();
                        if IsIconic(w) == 0 {
                            app.refresh(chosen)
                        } else {
                            app.displayed.clear();
                        }
                        continue;
                    }
                    _ => {}
                }
            }
            if IsDialogMessageW(w, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        DeleteObject(heading as _);
        DeleteObject(font as _);
    }
}

const GUIDE: &str = "READING THE COUNTERS

Installed     Physical memory fitted to the machine.
Usable        RAM Windows can manage after hardware reservations.
Available     RAM Windows can give to an app immediately, including standby pages.
In use        Usable RAM minus available RAM.
Commit        Memory Windows has promised to back with RAM or paging files.
Commit limit  Current system-wide capacity for that promise.

PRIVATE WS    Resident RAM unique to this process.
TOTAL WS      All RAM resident for this process, including shareable pages.
PRIVATE BYTES Private committed allocation, including pages outside RAM.
              Subtract private WS from total WS for this process's shareable footprint.
              Summing total working sets can count the same physical page repeatedly.

Unknown       Windows could not provide that measurement during this scan.
MiB           1,048,576 bytes.

Select a process and request close to let it save work. End process can release RAM
immediately and lose unsaved work. Uninstall launches the registered removal program.";
