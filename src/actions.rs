use crate::{
    scan::{Handle, checked, err},
    trend::Identity,
};
use std::{
    ffi::OsString,
    os::windows::{ffi::OsStringExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
};
use windows_sys::Win32::{
    Foundation::*,
    System::{DataExchange::*, Memory::*, Threading::*},
    UI::WindowsAndMessaging::*,
};
use winreg::{RegKey, enums::*};

fn path(h: &Handle) -> Result<PathBuf, String> {
    let mut buf = vec![0; 32768];
    let mut size = buf.len() as u32;
    unsafe {
        if QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut size) == 0 {
            return Err(err());
        }
    }
    Ok(OsString::from_wide(&buf[..size as usize]).into())
}
fn protect(h: &Handle, id: Identity) -> Result<(), String> {
    let mut critical = 0;
    if id.pid <= 4 || id.pid == std::process::id() {
        return Err("Protected process".into());
    }
    if unsafe { IsProcessCritical(h.0, &mut critical) } == 0 {
        return Err(format!("Critical status unknown: {}", err()));
    }
    let p = path(h)?;
    let win = std::env::var_os("SystemRoot").ok_or("Windows directory unavailable")?;
    if critical != 0
        || p.to_string_lossy()
            .to_lowercase()
            .starts_with(&format!("{}\\", Path::new(&win).display()).to_lowercase())
    {
        return Err("Windows component or critical process is protected".into());
    }
    Ok(())
}
fn process_handle(id: Identity, rights: u32) -> Result<Handle, String> {
    checked(id, rights | SYNCHRONIZE_RIGHT)
}
const SYNCHRONIZE_RIGHT: u32 = 0x100000;

pub fn end(id: Identity) -> Result<String, String> {
    let h = process_handle(id, PROCESS_TERMINATE)?;
    protect(&h, id)?;
    if unsafe { TerminateProcess(h.0, 1) } == 0 {
        Err(err())
    } else {
        Ok("Termination requested".into())
    }
}
pub fn location(id: Identity) -> Result<String, String> {
    let h = process_handle(id, 0)?;
    let p = path(&h)?;
    let explorer =
        PathBuf::from(std::env::var_os("SystemRoot").ok_or("Windows directory unavailable")?)
            .join("explorer.exe");
    Command::new(explorer)
        .raw_arg(format!("/select,\"{}\"", p.display()))
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(format!("Opened {}", p.display()))
}
pub fn copy(id: Identity, owner: HWND) -> Result<String, String> {
    let p = path(&process_handle(id, 0)?)?;
    use std::os::windows::ffi::OsStrExt;
    let data: Vec<_> = p.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        if OpenClipboard(owner) == 0 {
            return Err(err());
        }
        let result = (|| {
            let h = GlobalAlloc(GMEM_MOVEABLE, data.len() * 2);
            if h.is_null() {
                return Err(err());
            }
            let dest = GlobalLock(h);
            if dest.is_null() {
                let e = err();
                GlobalFree(h);
                return Err(e);
            }
            std::ptr::copy_nonoverlapping(data.as_ptr(), dest.cast(), data.len());
            GlobalUnlock(h);
            if EmptyClipboard() == 0 || SetClipboardData(13, h).is_null() {
                let e = err();
                GlobalFree(h);
                return Err(e);
            }
            Ok(format!("Copied {}", p.display()))
        })();
        CloseClipboard();
        result
    }
}
struct CloseRequest {
    pid: u32,
    posted: usize,
    failed: usize,
}
unsafe extern "system" fn visit(w: HWND, param: isize) -> i32 {
    unsafe {
        let r = &mut *(param as *mut CloseRequest);
        let mut pid = 0;
        GetWindowThreadProcessId(w, &mut pid);
        if pid == r.pid && IsWindowVisible(w) != 0 && GetWindow(w, GW_OWNER).is_null() {
            if PostMessageW(w, WM_CLOSE, 0, 0) != 0 {
                r.posted += 1
            } else {
                r.failed += 1
            }
        }
        1
    }
}
pub fn close(id: Identity) -> Result<String, String> {
    let h = process_handle(id, 0)?;
    protect(&h, id)?;
    let mut r = CloseRequest {
        pid: id.pid,
        posted: 0,
        failed: 0,
    };
    if unsafe { EnumWindows(Some(visit), (&mut r as *mut CloseRequest) as isize) } == 0 {
        return Err(err());
    }
    if r.posted == 0 {
        return Err(format!(
            "No eligible window accepted WM_CLOSE ({} failed)",
            r.failed
        ));
    }
    Ok(format!(
        "Requested close on {} window(s), {} failed. The app may prompt to save.",
        r.posted, r.failed
    ))
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Uninstaller {
    pub name: String,
    pub command: String,
}
pub fn uninstaller(id: Identity) -> Result<Uninstaller, String> {
    let p = path(&process_handle(id, 0)?)?;
    let parent = p.parent().ok_or("No parent directory")?;
    let norm = |s: &str| {
        s.trim()
            .trim_matches('"')
            .trim_end_matches('\\')
            .to_lowercase()
    };
    let folder = norm(&parent.to_string_lossy());
    if parent.parent().is_none()
        || [
            "ProgramFiles",
            "ProgramFiles(x86)",
            "SystemRoot",
            "LOCALAPPDATA",
            "APPDATA",
            "USERPROFILE",
        ]
        .iter()
        .filter_map(std::env::var_os)
        .any(|v| norm(&v.to_string_lossy()) == folder)
    {
        return Err("Shared installation directory; inspect the file location manually".into());
    }
    let mut matches = Vec::new();
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                KEY_READ | view,
            ) else {
                continue;
            };
            for key in root.enum_keys().flatten() {
                let Ok(k) = root.open_subkey(key) else {
                    continue;
                };
                let loc: String = k.get_value("InstallLocation").unwrap_or_default();
                if norm(&loc) != folder {
                    continue;
                }
                let (Ok(name), Ok(command)) = (
                    k.get_value::<String, _>("DisplayName"),
                    k.get_value::<String, _>("UninstallString"),
                ) else {
                    continue;
                };
                let u = Uninstaller { name, command };
                if !matches.contains(&u) {
                    matches.push(u)
                }
            }
        }
    }
    if matches.len() != 1 {
        return Err(format!(
            "{} matching registered uninstallers. Inspect the file location or use Windows Installed apps.",
            matches.len()
        ));
    }
    Ok(matches.remove(0))
}
pub fn uninstall(id: Identity, confirmed: &Uninstaller) -> Result<String, String> {
    if &uninstaller(id)? != confirmed {
        return Err("Registration changed; inspect again".into());
    }
    let cmd = confirmed.command.trim();
    let (exe, args) = if let Some(s) = cmd.strip_prefix('"') {
        s.split_once('"').ok_or("Invalid registered command")?
    } else {
        cmd.split_once(char::is_whitespace).unwrap_or((cmd, ""))
    };
    let mut exe = PathBuf::from(exe);
    if exe.to_string_lossy().eq_ignore_ascii_case("msiexec.exe")
        || exe.to_string_lossy().eq_ignore_ascii_case("msiexec")
    {
        exe = PathBuf::from(std::env::var_os("SystemRoot").ok_or("Windows directory unavailable")?)
            .join(r"System32\msiexec.exe");
    }
    if !exe.is_absolute()
        || !exe
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
        || !exe.is_file()
    {
        return Err("Registered executable path is ambiguous or unavailable".into());
    }
    let _h = process_handle(id, 0)?;
    Command::new(exe)
        .raw_arg(args.trim_start())
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "Launched the registered uninstaller for {}",
        confirmed.name
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_selection_cannot_end_replacement() {
        let mut child = Command::new("cmd.exe")
            .args(["/d", "/c", "ping -n 30 127.0.0.1 >nul"])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();
        let pid = child.id();
        let h = crate::scan::open(pid, 0).unwrap();
        let id = Identity {
            pid,
            born: crate::scan::born(&h).unwrap() + 1,
        };
        let result = end(id);
        let alive = child.try_wait().unwrap().is_none();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(result.unwrap_err().contains("PID reused"));
        assert!(alive);
    }
}
