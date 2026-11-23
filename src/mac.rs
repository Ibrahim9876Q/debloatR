use crate::trend::{Identity, Trends};
use serde_json::json;
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

pub fn run() {
    let mut system = System::new();
    let mut trends = Trends::default();
    let clock = Instant::now();
    loop {
        system.refresh_memory();
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing(),
        );
        let mut rows = Vec::new();
        let mut values = Vec::new();
        for (pid, process) in system.processes() {
            let pid = pid.as_u32();
            let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
            let ok = unsafe {
                libc::proc_pid_rusage(
                    pid as i32,
                    libc::RUSAGE_INFO_V2,
                    (&mut info as *mut libc::rusage_info_v2).cast(),
                )
            } == 0;
            let id = Identity {
                pid,
                born: info.ri_proc_start_abstime,
            };
            if ok {
                values.push((id, info.ri_phys_footprint));
            }
            rows.push((
                id,
                process.name().to_string_lossy().into_owned(),
                ok.then_some(info.ri_phys_footprint),
            ));
        }
        trends.update(clock.elapsed().as_secs(), values.into_iter());
        let rows:Vec<_> = rows.into_iter().map(|(id,name,bytes)|{
            let h=trends.0.get(&id);
            json!({"id":id.pid,"name":name,"bytes":bytes,"finding":h.and_then(|h|h.finding()),"ready":h.is_some_and(|h|h.ready())})
        }).collect();
        let result = json!({"used":system.used_memory(),"total":system.total_memory(),"rows":rows});
        if writeln!(io::stdout().lock(), "{result}").is_err() {
            break;
        }
        if std::env::args().any(|a| a == "--once") {
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}
