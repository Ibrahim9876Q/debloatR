use crate::trend::{History, Identity, MIB, Trends};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    io,
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::*,
    System::{
        Diagnostics::ToolHelp::*, Performance::*, ProcessStatus::*, SystemInformation::*,
        Threading::*,
    },
};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
pub fn err() -> String {
    io::Error::last_os_error().to_string()
}
pub struct Handle(pub HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
pub fn open(pid: u32, rights: u32) -> Result<Handle, String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | rights, 0, pid);
        if h.is_null() {
            Err(err())
        } else {
            Ok(Handle(h))
        }
    }
}
fn ticks(f: FILETIME) -> u64 {
    (f.dwHighDateTime as u64) << 32 | f.dwLowDateTime as u64
}
pub fn born(h: &Handle) -> Result<u64, String> {
    unsafe {
        let (mut c, mut e, mut k, mut u) = (zeroed(), zeroed(), zeroed(), zeroed());
        if GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) == 0 {
            Err(err())
        } else {
            Ok(ticks(c))
        }
    }
}
pub fn checked(id: Identity, rights: u32) -> Result<Handle, String> {
    let h = open(id.pid, rights)?;
    if born(&h)? != id.born {
        return Err("Selection has expired (PID reused)".into());
    }
    match unsafe { WaitForSingleObject(h.0, 0) } {
        WAIT_TIMEOUT => Ok(h),
        WAIT_OBJECT_0 => Err("Process has exited".into()),
        _ => Err(err()),
    }
}
pub fn stamp() -> String {
    unsafe {
        let mut t = zeroed();
        GetLocalTime(&mut t);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
        )
    }
}

#[derive(Default, Clone, Debug)]
pub struct Row {
    pub pid: u32,
    pub name: String,
    pub id: Option<Identity>,
    pub private: Option<u64>,
    pub ws: Option<u64>,
    pub commit: Option<u64>,
    pub status: String,
    pub counter_private: bool,
    pub counter_id: Option<Identity>,
}
fn measure(pid: u32, name: String, cutoff: u64) -> Row {
    let mut r = Row {
        pid,
        name,
        ..Default::default()
    };
    let result = (|| -> Result<(), String> {
        let h = open(pid, 0)?;
        let created = born(&h)?;
        if created > cutoff {
            return Err("Changed during snapshot".into());
        }
        r.id = Some(Identity { pid, born: created });
        unsafe {
            let mut m: PROCESS_MEMORY_COUNTERS_EX2 = zeroed();
            m.PrivateWorkingSetSize = usize::MAX;
            m.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32;
            if K32GetProcessMemoryInfo(
                h.0,
                (&mut m as *mut PROCESS_MEMORY_COUNTERS_EX2).cast(),
                m.cb,
            ) == 0
            {
                m.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
                if K32GetProcessMemoryInfo(
                    h.0,
                    (&mut m as *mut PROCESS_MEMORY_COUNTERS_EX2).cast(),
                    m.cb,
                ) == 0
                {
                    return Err(err());
                }
            } else if m.PrivateWorkingSetSize != usize::MAX {
                r.private = Some(m.PrivateWorkingSetSize as u64)
            }
            r.ws = Some(m.WorkingSetSize as u64);
            r.commit = Some(m.PrivateUsage as u64);
        }
        Ok(())
    })();
    if let Err(e) = result {
        r.status = e
    }
    r
}
fn toolhelp() -> Result<BTreeMap<u32, String>, String> {
    unsafe {
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h == INVALID_HANDLE_VALUE {
            return Err(err());
        }
        let h = Handle(h);
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(h.0, &mut e) == 0 {
            return Err(err());
        }
        let mut out = BTreeMap::new();
        loop {
            out.insert(
                e.th32ProcessID,
                String::from_utf16_lossy(
                    &e.szExeFile[..e
                        .szExeFile
                        .iter()
                        .position(|x| *x == 0)
                        .unwrap_or(e.szExeFile.len())],
                ),
            );
            if Process32NextW(h.0, &mut e) == 0 {
                if GetLastError() != ERROR_NO_MORE_FILES {
                    return Err(err());
                }
                break;
            }
        }
        Ok(out)
    }
}
fn psapi() -> Result<HashSet<u32>, String> {
    let mut p = vec![0; 1024];
    loop {
        let mut bytes = 0;
        let size = (p.len() * 4) as u32;
        if unsafe { K32EnumProcesses(p.as_mut_ptr(), size, &mut bytes) } == 0 {
            return Err(err());
        }
        if bytes < size {
            p.truncate(bytes as usize / 4);
            return Ok(p.into_iter().collect());
        }
        if p.len() >= 1 << 20 {
            return Err("PSAPI snapshot exceeded buffer limit".into());
        }
        p.resize(p.len() * 2, 0);
    }
}
pub fn mem(v: Option<u64>) -> String {
    v.map(|n| format!("{:.1} MiB", n as f64 / MIB as f64))
        .unwrap_or_else(|| "unknown".into())
}
fn counter_values(counter: isize) -> Option<HashMap<String, u64>> {
    unsafe {
        let (mut bytes, mut count) = (0, 0);
        if counter == 0
            || PdhGetRawCounterArrayW(counter, &mut bytes, &mut count, null_mut()) != PDH_MORE_DATA
            || bytes > 16 * 1024 * 1024
        {
            return None;
        }
        let mut storage = vec![0u64; (bytes as usize).div_ceil(8)];
        let ptr = storage.as_mut_ptr().cast::<PDH_RAW_COUNTER_ITEM_W>();
        if PdhGetRawCounterArrayW(counter, &mut bytes, &mut count, ptr) != 0 {
            return None;
        }
        let mut values = HashMap::new();
        let mut ambiguous = HashSet::new();
        for item in std::slice::from_raw_parts(ptr, count as usize) {
            if item.RawValue.CStatus > 1 || item.RawValue.FirstValue < 0 || item.szName.is_null() {
                continue;
            }
            let mut len = 0;
            while *item.szName.add(len) != 0 {
                len += 1
            }
            let name = String::from_utf16_lossy(std::slice::from_raw_parts(item.szName, len));
            if values
                .insert(name.clone(), item.RawValue.FirstValue as u64)
                .is_some()
            {
                ambiguous.insert(name);
            }
        }
        values.retain(|name, _| !ambiguous.contains(name));
        Some(values)
    }
}
pub struct Compression {
    ids: isize,
    private_ws: isize,
    commit: isize,
    started: isize,
    collected: bool,
    query: isize,
    counter: isize,
}
impl Compression {
    fn new() -> Self {
        unsafe {
            let mut s = Self {
                query: 0,
                counter: 0,
                ids: 0,
                private_ws: 0,
                commit: 0,
                started: 0,
                collected: false,
            };
            if PdhOpenQueryW(null(), 0, &mut s.query) == 0 {
                for (name, counter) in [
                    (r"\Process(*)\ID Process", &mut s.ids),
                    (r"\Process(*)\Private Bytes", &mut s.commit),
                    (r"\Process(*)\Elapsed Time", &mut s.started),
                    (r"\Process(*)\Working Set - Private", &mut s.private_ws),
                ] {
                    PdhAddEnglishCounterW(s.query, wide(name).as_ptr(), 0, counter);
                }
                PdhAddEnglishCounterW(
                    s.query,
                    wide(r"\Process(Memory Compression)\Working Set - Private").as_ptr(),
                    0,
                    &mut s.counter,
                );
            }
            s
        }
    }
    fn read(&mut self) -> Option<u64> {
        unsafe {
            let mut raw = zeroed();
            self.collected = self.query != 0 && PdhCollectQueryData(self.query) == 0;
            (self.collected
                && self.counter != 0
                && PdhGetRawCounterValue(self.counter, null_mut(), &mut raw) == 0
                && raw.CStatus <= 1)
                .then_some(raw.FirstValue as u64)
        }
    }
}
impl Drop for Compression {
    fn drop(&mut self) {
        if self.query != 0 {
            unsafe {
                PdhCloseQuery(self.query);
            }
        }
    }
}

#[derive(Default)]
pub struct System {
    pub installed: Option<u64>,
    pub usable: Option<u64>,
    pub used: Option<u64>,
    pub available: Option<u64>,
    pub commit: Option<u64>,
    pub limit: Option<u64>,
    pub cache: Option<u64>,
    pub paged: Option<u64>,
    pub nonpaged: Option<u64>,
    pub compression: Option<u64>,
}
impl System {
    fn read(c: &mut Compression) -> Self {
        unsafe {
            let mut s = Self {
                compression: c.read(),
                ..Default::default()
            };
            let mut kb = 0;
            if GetPhysicallyInstalledSystemMemory(&mut kb) != 0 {
                s.installed = Some(kb * 1024)
            }
            let mut p: PERFORMANCE_INFORMATION = zeroed();
            if K32GetPerformanceInfo(&mut p, size_of::<PERFORMANCE_INFORMATION>() as u32) != 0 {
                let bytes = |n: usize| Some(n as u64 * p.PageSize as u64);
                s.usable = bytes(p.PhysicalTotal);
                s.available = bytes(p.PhysicalAvailable);
                s.used = bytes(p.PhysicalTotal - p.PhysicalAvailable);
                s.commit = bytes(p.CommitTotal);
                s.limit = bytes(p.CommitLimit);
                s.cache = bytes(p.SystemCache);
                s.paged = bytes(p.KernelPaged);
                s.nonpaged = bytes(p.KernelNonpaged);
            }
            s
        }
    }
}
struct Evidence {
    first: String,
    count: u32,
}
fn service_hosts() -> HashMap<u32, Vec<String>> {
    use windows_sys::Win32::System::Services::*;
    let mut hosts: HashMap<u32, Vec<String>> = HashMap::new();
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            return hosts;
        }
        let mut storage = vec![0u64; 32768];
        let mut resume = 0;
        loop {
            let (mut bytes, mut returned) = (0, 0);
            let ok = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                storage.as_mut_ptr().cast(),
                262144,
                &mut bytes,
                &mut returned,
                &mut resume,
                null(),
            );
            let more = ok == 0 && GetLastError() == ERROR_MORE_DATA;
            if ok == 0 && !more {
                break;
            }
            for entry in std::slice::from_raw_parts(
                storage.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                returned as usize,
            ) {
                let name = entry.lpServiceName;
                let mut len = 0;
                while *name.add(len) != 0 {
                    len += 1
                }
                hosts
                    .entry(entry.ServiceStatusProcess.dwProcessId)
                    .or_default()
                    .push(String::from_utf16_lossy(std::slice::from_raw_parts(
                        name, len,
                    )));
            }
            if !more || returned == 0 {
                break;
            }
        }
        CloseServiceHandle(scm);
    }
    hosts
}
pub struct Monitor {
    pub hosts: HashMap<u32, Vec<String>>,
    start: Instant,
    c: Compression,
    pub system: System,
    pub rows: Vec<Row>,
    pub trends: Trends,
    pub(crate) counter_trends: Trends,
    pub pools: [History; 2],
    pending: HashMap<(Identity, bool), Evidence>,
    pub records: VecDeque<String>,
    pub comparison: String,
    pub sampled: String,
    pub sum: Option<u64>,
    pub measured: usize,
}
impl Monitor {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            start: Instant::now(),
            c: Compression::new(),
            system: System::default(),
            rows: vec![],
            trends: Trends::default(),
            counter_trends: Trends::default(),
            pools: Default::default(),
            pending: Default::default(),
            records: Default::default(),
            comparison: String::new(),
            sampled: String::new(),
            sum: None,
            measured: 0,
        }
    }
    pub fn sample(&mut self) {
        let sec = self.start.elapsed().as_secs();
        self.sampled = stamp();
        self.system = System::read(&mut self.c);
        let cutoff = unsafe {
            let mut f = zeroed();
            GetSystemTimePreciseAsFileTime(&mut f);
            ticks(f)
        };
        self.hosts = service_hosts();
        let a = toolhelp();
        let b = psapi();
        let mut names = a.as_ref().cloned().unwrap_or_default();
        if let Ok(ids) = &b {
            for pid in ids {
                names.entry(*pid).or_insert_with(|| "<name unknown>".into());
            }
        }
        self.rows = names
            .into_iter()
            .map(|(p, n)| measure(p, n, cutoff))
            .collect();
        if self.c.collected
            && let (Some(ids), Some(sizes)) = (
                counter_values(self.c.ids),
                counter_values(self.c.private_ws),
            )
        {
            let commits = counter_values(self.c.commit).unwrap_or_default();
            let starts = counter_values(self.c.started).unwrap_or_default();
            let by_pid: HashMap<_, _> = ids
                .iter()
                .filter_map(|(instance, pid)| {
                    let image = instance
                        .rsplit_once('#')
                        .filter(|(_, suffix)| suffix.parse::<u32>().is_ok())
                        .map_or(instance.as_str(), |(base, _)| base);
                    Some((
                        u32::try_from(*pid).ok()?,
                        (image, *sizes.get(instance)?, instance),
                    ))
                })
                .collect();
            for row in &mut self.rows {
                if (row.private.is_none() || row.commit.is_none())
                    && row.pid != 0
                    && let Some((image, bytes, instance)) = by_pid.get(&row.pid)
                    && row
                        .name
                        .trim_end_matches(".exe")
                        .eq_ignore_ascii_case(image)
                {
                    if row.private.is_none() {
                        row.private = Some(*bytes);
                        row.counter_private = true;
                    }
                    if row.commit.is_none()
                        && let (Some(&value), Some(&start)) =
                            (commits.get(*instance), starts.get(*instance))
                        && start > 0
                    {
                        row.commit = Some(value);
                        row.counter_id = Some(Identity {
                            pid: row.pid,
                            born: start,
                        });
                    }
                }
            }
        }
        let private = self.rows.iter().filter_map(|r| r.private);
        self.measured = private.clone().count();
        self.sum = (self.measured > 0).then(|| private.sum());
        self.trends.update(
            sec,
            self.rows
                .iter()
                .filter(|r| r.counter_id.is_none())
                .filter_map(|r| Some((r.id?, r.commit?))),
        );
        self.counter_trends.update(
            sec,
            self.rows
                .iter()
                .filter_map(|r| Some((r.counter_id?, r.commit?))),
        );
        for (h, v) in self
            .pools
            .iter_mut()
            .zip([self.system.paged, self.system.nonpaged])
        {
            if let Some(v) = v {
                h.add(sec, v)
            } else {
                *h = History::default()
            }
        }
        self.compare_sources(a, b);
    }
    fn compare_sources(
        &mut self,
        a: Result<BTreeMap<u32, String>, String>,
        b: Result<HashSet<u32>, String>,
    ) {
        let mut next = HashMap::new();
        self.comparison = match (a, b) {
            (Ok(a), Ok(b)) => {
                let mut unverified = 0;
                for r in &self.rows {
                    let left = a.contains_key(&r.pid);
                    if left == b.contains(&r.pid) {
                        continue;
                    }
                    let Some(id) = r.id else {
                        unverified += 1;
                        continue;
                    };
                    let key = (id, left);
                    let mut e = self.pending.remove(&key).unwrap_or_else(|| Evidence {
                        first: self.sampled.clone(),
                        count: 0,
                    });
                    e.count += 1;
                    if e.count == 2 {
                        self.records.push_front(format!("{}  PID {}  {}\r\n    {} only on two complete scans, first {}. Creation FILETIME {}.",self.sampled,id.pid,r.name,if left{"Tool Help"}else{"PSAPI"},e.first,id.born));
                        self.records.truncate(128)
                    }
                    next.insert(key, e);
                }
                format!(
                    "Tool Help {}  /  PSAPI {}  /  one-source PIDs {}  /  identity unavailable {}",
                    a.len(),
                    b.len(),
                    next.len() + unverified,
                    unverified
                )
            }
            (a, b) => format!(
                "Incomplete snapshot. Tool Help: {}. PSAPI: {}. Retry next scan.",
                a.err().unwrap_or_else(|| "OK".into()),
                b.err().unwrap_or_else(|| "OK".into())
            ),
        };
        self.pending = next;
    }
    pub fn history(&self, r: &Row) -> Option<&History> {
        if let Some(id) = r.counter_id {
            self.counter_trends.0.get(&id)
        } else {
            self.trends.0.get(&r.id?)
        }
    }
    pub fn residual(&self) -> Option<u64> {
        self.system.used?.checked_sub(self.sum?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discrepancy_requires_repeated_complete_observations_of_same_identity() {
        let mut m = Monitor::new();
        let pid = 83;
        m.rows.push(Row {
            pid,
            name: "fixture".into(),
            ..Default::default()
        });
        let left = || Ok(BTreeMap::from([(pid, "fixture".into())]));
        let right = || Ok(HashSet::new());
        m.compare_sources(left(), right());
        m.compare_sources(left(), right());
        assert!(m.records.is_empty() && m.pending.is_empty());
        m.rows[0].id = Some(Identity { pid, born: 1 });
        m.compare_sources(left(), right());
        m.compare_sources(Err("partial".into()), right());
        m.compare_sources(left(), right());
        m.rows[0].id = Some(Identity { pid, born: 2 });
        m.compare_sources(left(), right());
        assert!(m.records.is_empty());
        m.compare_sources(left(), right());
        assert_eq!(m.records.len(), 1);
        m.compare_sources(left(), Ok(HashSet::from([pid])));
        assert!(m.pending.is_empty());
    }
    #[test]
    fn inaccessible_is_unknown() {
        let r = measure(0, "Idle".into(), u64::MAX);
        assert!(r.private.is_none() && r.ws.is_none() && r.commit.is_none() && r.id.is_none());
        assert_eq!(mem(r.private), "unknown")
    }
    #[test]
    fn live_sample() {
        let mut m = Monitor::new();
        m.sample();
        assert!(m.system.used.is_some());
        let r = m.rows.iter().find(|r| r.pid == std::process::id()).unwrap();
        assert!(r.private.unwrap() > 0);
        assert!(m.comparison.contains("PSAPI"));
        println!(
            "{}; private={} of {} rows; compression={}",
            m.comparison,
            m.measured,
            m.rows.len(),
            mem(m.system.compression)
        );
    }
}
