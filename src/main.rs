#![cfg_attr(windows, windows_subsystem = "windows")]
#[cfg(windows)]
mod actions;
#[cfg(target_os = "macos")]
mod mac;
#[cfg(windows)]
mod review;
#[cfg(windows)]
mod scan;
mod trend;
#[cfg(windows)]
mod ui;
fn main() {
    #[cfg(windows)]
    ui::run();
    #[cfg(target_os = "macos")]
    mac::run();
}
