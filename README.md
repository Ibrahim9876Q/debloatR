# debloatR

A black-and-white desktop RAM analyzer for Windows 11 and macOS 13 or later. Choose **Scan device** to measure system and process memory. Results update while the app collects growth history.

## Run

Download **debloatR.exe** from the [latest release](https://github.com/Ibrahim9876Q/debloatR/releases/latest) and launch it. The executable is unsigned. To build the same program on x64 Windows, install stable Rust with its Windows linker. The default MSVC toolchain uses Visual Studio Build Tools with **Desktop development with C++**. This release was built with stable Rust's x86_64-pc-windows-gnu toolchain.

```powershell
git clone https://github.com/Ibrahim9876Q/debloatR.git
cd debloatR
cargo build --release --locked
.\target\release\debloatR.exe
```

If Rust is already installed but missing from this PowerShell session's PATH, run `$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"` first.

## macOS

Download **debloatR-macOS.zip** from the latest release, unzip it and open **debloatR.app**. The universal application supports Apple silicon and Intel. It is ad-hoc signed and has no Apple notarization. To build locally on a Mac with Xcode Command Line Tools and stable Rust installed:

```sh
git clone https://github.com/Ibrahim9876Q/debloatR.git
cd debloatR
bash macos/build.sh
open target/mac/debloatR.app
```

The native SwiftUI window uses a Rust scanner to enumerate processes and read physical footprints via libproc. It compares measured footprints with system use and watches each PID and process start time for sustained growth. Recommendations identify inactive regular apps and accessory apps. Review these in the app itself or in Activity Monitor. Windows cleanup controls, pool metrics and enumeration discrepancies are Windows-specific.

## Read a Windows scan

**Suspected leak sources** appears in Scan results and Discrepancies. Each finding names the image and PID, shows the private-commit trend, and resolves the executable path when permitted. Windows service names come from the Service Control Manager. A shared service host can contain several services, so the scan only attributes growth to the host. Kernel pool growth likewise has no per-driver attribution here.

Both views rank measured private RAM owners and per-process shareable resident footprints. A second pass through Windows performance counters matches process IDs and image names to recover missing private working sets. Counter-only private-commit histories use PID and the raw process start tick independently of handle-based histories. These measurements grant no cleanup permissions. Shared footprints overlap across apps.

**Scan results** compares system in-use RAM with the measured private working sets. It reports the difference and checks growth over time regardless of the size of the gap. Recommendations show the largest recognized optional apps with visible windows and recognized background apps. Unknown processes and system services receive no close suggestion. An app may still be doing useful work without a window.

**Processes** starts with the largest private working sets. Search by image name or PID. Click **Sort** to cycle through the five columns and **Ascending/Descending** to reverse the order. Unknown measurements sort last. Click **Sample** to cycle through 5, 10, 30 and 2 seconds. The monitor waits for Windows messages between scans and skips table and report refreshes while minimized.

| Measurement | Meaning |
| --- | --- |
| Installed / usable RAM | Physical memory fitted to the machine / RAM Windows can manage. Hardware reservations can account for the difference. |
| In use / available | Usable RAM minus immediately available RAM / pages Windows can reuse immediately, including standby memory. |
| Commit / limit | Memory Windows has promised to back / the current system-wide commit ceiling. Both RAM and paging files contribute to capacity. |
| Private working set | Physical memory resident exclusively for one process. The dashboard sums known values and gives the measured and enumerated process counts. |
| Total working set | All resident pages in one process, including shareable pages. Subtract its private working set to estimate its resident shareable footprint. The same pages can appear in several rows. |
| Private bytes | Private committed memory for the process, including pages outside RAM. Leak watch tracks this value. |
| Cache / paged / nonpaged pools | System cache includes standby pages and the system working set. Paged kernel allocations can leave RAM. Nonpaged kernel allocations stay resident. |
| Compression | Private working set of the Windows Memory Compression process, when its performance counter is available. This estimates the store footprint. The precise compressed payload and savings are unknown. |
| Outside measured private working sets | In-use RAM minus the measured private working set sum. This residual includes shared pages, system allocations and inaccessible processes. Cache, pools and compression can overlap other figures. |

Values are in MiB (1,048,576 bytes). Each scan spans a short period. A missing counter, denied handle, exited process, or inconsistent subtraction displays **unknown**. Process memory comes from [GetProcessMemoryInfo and EX2](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex2). Older Windows builds may provide only total working set and private bytes. System counters use [GetPerformanceInfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-performance_information) and GetPhysicallyInstalledSystemMemory. Compression uses a locale-independent PDH counter.

## Investigate growth and discrepancies

**Leak watch** keeps up to 61 observations and ten minutes per process, bounded to 32,768 live histories. The identity is PID plus the exact creation FILETIME. A missing measurement, exit, replacement, or sampling gap over 90 seconds restarts its history. The detector needs at least seven samples and 60 seconds. It requires a gain of at least 1 MiB in each of three consecutive sample windows, at least 6 MiB overall, at least 1 MiB/min, and net gain of at least 70% of the total up-and-down movement. Graphs show 13 points scaled to each history. Paged and nonpaged pools get separate histories. Legitimate caches can meet these thresholds, and slow leaks can fall below them. Pool growth alone cannot identify a driver.

**Discrepancies** compares Tool Help's process snapshot with PSAPI's EnumProcesses. The PSAPI buffer grows until the returned list fits. A one-source PID must have a verified creation time and appear on the same side of two consecutive complete scans. Incomplete scans break the streak. Denied identity lookups are counted separately. The last 128 confirmed episodes include the source, timestamps and identity. To cross-check, open **Task Manager → Details** and look under **PID**. A process can exit before you get there. These user-mode APIs cannot establish that the OS reported every program, and a memory residual is insufficient evidence of a hidden process.

## Act on a selection

**Open location** selects the executable in Explorer. **Copy path** copies its full path. **Request close** sends WM_CLOSE to eligible visible top-level windows and lets the app handle saving. A successful request means Windows accepted the message. **End process** asks for separate confirmation, can lose unsaved work and can release RAM immediately.

**Uninstall** looks on demand for a unique registered uninstall command whose InstallLocation matches the executable's parent directory, across user/machine and 32/64-bit registry views. Review the displayed app and command before confirming. Uninstalling removes software from the machine. Ambiguous registrations, Store apps, nested executable locations and unsupported command forms may require **Settings → Apps → Installed apps**. Launch success records the handoff to the uninstaller. Its completion and any elevation prompt belong to that program.

Actions re-open the target and compare its creation time. Termination uses that same verified handle. Close and end refuse critical processes, Windows-directory components, the monitor itself and targets whose protection status cannot be verified. Access failures leave the monitor running. The action log retains 128 entries in memory. Cleanup is manual. The monitor has no driver, service, working-set trimming, cache flushing or executable-deletion feature.

## Verify

```powershell
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
.\scripts\measure.ps1
```

The measurement script launches a fresh release instance, warms it for six seconds, takes 12 private-working-set samples per phase, and measures CPU time across each entire phase. It verifies the window's minimized state. Machine CPU percentage divides the process's CPU time by elapsed time and logical processor count. Closing the monitor discards its session history.

### Version 0.1.0 reference measurements and Windows checks

Measured on Windows 11 Home x64 build 26200, AMD Ryzen 5 7600X, 12 logical processors, 32 GiB installed RAM, Rust 1.100.0 stable GNU release build. The Processes view used the default 5-second interval throughout. Each phase sampled private working set 12 times at 5-second intervals.

| Window state | Elapsed | Mean private working set (range) | Average machine CPU | CPU as % of one core |
| --- | ---: | ---: | ---: | ---: |
| Visible | 60.11 s | 6.59 MiB (6.23–6.92) | 0.030% | 0.364% |
| Minimized | 60.11 s | 6.95 MiB (6.92–6.98) | 0.024% | 0.286% |

These measurements describe one run on a live desktop with roughly 400 processes. Sampling continues while minimized and the process keeps its history and allocated buffers.

Formatting, strict Clippy, eight tests and the release build passed. Windows checks exercised enumeration, partial access, compression, all five views, PID search, sorting, interval changes, clipboard path copying and the action log. A disposable growing process triggered a live finding over 65 seconds (20.9 to 88.1 MiB, +61.96 MiB/min). Disposable windows exercised graceful close, cancellation and confirmation of termination, and a harmless registered uninstall command. Permanent removal of installed software was not exercised. Persistent enumeration discrepancies were tested with synthetic observations. A live driver leak was not observed.


