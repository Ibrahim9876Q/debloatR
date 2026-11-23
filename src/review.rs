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

fn owner(m: &Monitor, r: &crate::scan::Row) -> String {
    let mut label = format!("{}  ·  PID {}", r.name, r.pid);
    if let Some(names) = m.hosts.get(&r.pid) {
        label.push_str(&format!("  ·  services: {}", names.join(", ")))
    }
    label
}
pub fn attribution(m: &Monitor) -> String {
    let mut lines = vec!["Suspected leak sources".into()];
    let mut flags = 0;
    for r in &m.rows {
        let Some(f) = m.history(r).and_then(|h| h.finding()) else {
            continue;
        };
        flags += 1;
        lines.push(format!("{}\r\nPrivate committed memory: {f}", owner(m, r)));
        let handle = r.id.and_then(|id| crate::scan::checked(id, 0x100000).ok());
        let optional = handle
            .as_ref()
            .zip(r.id)
            .is_some_and(|(h, id)| crate::actions::protect(h, id).is_ok());
        if let Some(path) = handle.as_ref().and_then(|h| crate::actions::path(h).ok()) {
            lines.push(path.display().to_string());
        }
        lines.push(if m.hosts.contains_key(&r.pid){"Review the listed services. These counters only identify the host process."}else if !optional{"Protected or unverified identity. Leave this process running."}else{"If you recognize this app and have finished using it, save work and quit from its own window. Find its PID in Processes for cleanup controls."}.into());
    }
    for (name, h) in ["Paged kernel pool", "Nonpaged kernel pool"]
        .into_iter()
        .zip(&m.pools)
    {
        if let Some(f) = h.finding() {
            flags += 1;
            lines.push(format!(
                "{name}: {f}\r\nSystem-wide growth. The responsible driver is unknown."
            ));
        }
    }
    if flags == 0 {
        lines.push(
            if m.rows
                .iter()
                .filter_map(|r| m.history(r))
                .any(|h| h.ready())
            {
                "No sustained growth detected in eligible histories."
            } else {
                "Collecting history. A first assessment requires at least one minute."
            }
            .into(),
        );
    }
    lines.push("\r\nLargest measured private RAM owners".into());
    let mut ranked = m
        .rows
        .iter()
        .filter_map(|r| Some((r.private?, r)))
        .collect::<Vec<_>>();
    ranked.sort_by_key(|(bytes, _)| std::cmp::Reverse(*bytes));
    for (v, r) in ranked.iter().take(6) {
        lines.push(format!("{}    {}", mem(Some(*v)), owner(m, r)));
    }
    let extra: Vec<_> = ranked.iter().filter(|(_, r)| r.counter_private).collect();
    let total = extra.iter().map(|(v, _)| *v).sum();
    lines.push(format!("\r\nPerformance counters supplied {} additional private measurements ({}), already included in the process sum.",extra.len(),mem(Some(total))));
    for (v, r) in extra.iter().take(5) {
        lines.push(format!("{}    {}", mem(Some(*v)), owner(m, r)));
    }
    lines.push("\r\nLargest shareable resident footprints outside the private sum".into());
    let mut shared = m
        .rows
        .iter()
        .filter_map(|r| Some((r.ws?.checked_sub(r.private?)?, r)))
        .filter(|(v, _)| *v > 0)
        .collect::<Vec<_>>();
    shared.sort_by_key(|(bytes, _)| std::cmp::Reverse(*bytes));
    for (v, r) in shared.into_iter().take(5) {
        lines.push(format!("{}    {}", mem(Some(v)), owner(m, r)));
    }
    lines.push("Shared pages can appear under multiple PIDs. Cache, pools and shared pages have no unique process attribution here.".into());
    lines.join("\r\n")
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
    lines.insert(0, attribution(m));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        scan::Row,
        trend::{Identity, MIB},
    };
    #[test]
    fn names_counter_only_service_growth_without_enabling_cleanup() {
        let mut m = Monitor::new();
        let pid = 8123;
        let id = Identity { pid, born: 42 };
        m.rows.push(Row {
            name: "testhost.exe".into(),
            pid,
            counter_id: Some(id),
            ..Default::default()
        });
        m.hosts.insert(pid, vec!["ExampleService".into()]);
        for i in 0..7 {
            m.counter_trends
                .update(i * 10, [(id, (20 + i * 2) * MIB)].into_iter());
        }
        let result = attribution(&m);
        assert!(result.contains("testhost.exe  ·  PID 8123  ·  services: ExampleService"));
        assert!(result.contains("+12.00 MiB/min"));
        assert!(result.contains("only identify the host process"));
        assert!(m.rows[0].id.is_none());
    }
}
