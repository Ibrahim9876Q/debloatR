use crate::scan::{Monitor, mem};
use std::collections::HashSet;
use windows_sys::Win32::{Foundation::HWND, UI::WindowsAndMessaging::*};

unsafe extern "system" fn collect(hwnd: HWND, data: isize) -> i32 {
    unsafe {
        if IsWindowVisible(hwnd) != 0 && GetWindow(hwnd, GW_OWNER).is_null() {
            let mut pid = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            (*(data as *mut HashSet<u32>)).insert(pid);
        }
    }
    1
}

pub fn report(m: &Monitor) -> String {
    let mut windows = HashSet::<u32>::new();
    let mut foreground = 0;
    unsafe {
        EnumWindows(Some(collect), (&mut windows as *mut HashSet<u32>) as isize);
        GetWindowThreadProcessId(GetForegroundWindow(), &mut foreground);
    }
    let mut lines = vec![
        "Memory comparison".to_owned(),
        format!(
            "Windows reports {} in use. Measured processes account for {} in private resident pages.",
            mem(m.system.used),
            mem(m.sum)
        ),
    ];
    lines.push(match m.residual(){
        Some(0)=>"The measured totals match at this sample.".into(),
        Some(n)=>format!("{} falls outside that sum. Shared pages, Windows itself, and inaccessible processes can explain the difference.",mem(Some(n))),
        None=>"The available measurements do not support an exact comparison.".into()
    });
    let flags = m
        .trends
        .0
        .values()
        .filter(|h| h.finding().is_some())
        .count();
    lines.push(if flags > 0 {
        format!("{flags} suspected growth patterns. Open Leak watch for the observations.")
    } else if m.trends.0.values().any(|h| h.ready()) {
        "No sustained growth detected in eligible histories.".into()
    } else {
        "Collecting leak history. The first assessment needs at least one minute.".into()
    });
    let mut rows: Vec<_> = m
        .rows
        .iter()
        .filter(|r| {
            r.private.is_some()
                && r.id.is_some()
                && r.pid != std::process::id()
                && r.pid != foreground
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.private));
    let optional = [
        "chrome.exe",
        "firefox.exe",
        "msedge.exe",
        "brave.exe",
        "spotify.exe",
        "discord.exe",
        "steam.exe",
        "slack.exe",
        "code.exe",
        "ms-teams.exe",
        "zoom.exe",
        "onedrive.exe",
        "telegram.exe",
        "vlc.exe",
    ];
    let visible_apps: HashSet<_> = m
        .rows
        .iter()
        .filter(|r| windows.contains(&r.pid))
        .map(|r| r.name.to_ascii_lowercase())
        .collect();
    for (visible, title, advice) in [
        (
            true,
            "Apps you could close",
            "Save your work, then quit an app you have finished using.",
        ),
        (
            false,
            "Optional background activity",
            "These recognized apps have no visible main window. Review their tray or startup settings if you do not need them.",
        ),
    ] {
        lines.extend([String::new(), title.into(), advice.into()]);
        let mut seen = HashSet::new();
        for r in &rows {
            let name = r.name.to_ascii_lowercase();
            if windows.contains(&r.pid) == visible
                && (visible || !visible_apps.contains(&name))
                && optional.contains(&name.as_str())
                && seen.insert(name)
            {
                lines.push(format!("{}    {}    PID {}", r.name, mem(r.private), r.pid));
                if seen.len() == 5 {
                    break;
                }
            }
        }
        if seen.is_empty() {
            lines.push("No recognized candidates in this scan.".into());
        }
    }
    lines.join("\r\n")
}
