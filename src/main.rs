#![cfg_attr(windows, windows_subsystem = "windows")]
#[cfg(windows)]
mod actions;
#[cfg(windows)]
mod scan;
mod trend;
#[cfg(windows)]
mod ui;
#[cfg(target_os="macos")]
mod mac;
fn main() {
    #[cfg(windows)]
    ui::run();
    #[cfg(target_os="macos")]
    mac::run();
}
