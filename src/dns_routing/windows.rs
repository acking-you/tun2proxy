//! Attribute shared Dnscache questions to their original caller, not svchost.
//! ETW is observational: this session never changes DNS settings or the cache.

use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, GetLastError, WAIT_OBJECT_0},
        System::{
            Diagnostics::Etw::*,
            Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject},
        },
    },
    core::GUID,
};

const DNS_PROVIDER: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
const CHECKPOINT_PROVIDER: GUID = GUID::from_u128(0xf49c4833_7d74_4781_869c_bdb5e23601cb);
const ORIGIN_TTL: Duration = Duration::from_secs(30);
const MAX_ORIGINS: usize = 4096;
const INVALID_TRACE: u64 = usize::MAX as u64;

#[derive(Hash, Eq, PartialEq, Clone)]
struct Question {
    name: String,
    kind: u16,
}
impl Question {
    fn new(name: &str, kind: u16) -> Self {
        Self {
            name: name.trim_end_matches('.').to_ascii_lowercase(),
            kind,
        }
    }
}
struct Origin {
    pid: u32,
    at: Instant,
}
#[derive(Default)]
struct State {
    marker_id: u64,
    queries: Mutex<HashMap<Question, Origin>>,
    delivered: AtomicU64,
    changed: Notify,
}

fn same_guid(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

impl State {
    fn record(&self, question: Question, pid: u32, now: Instant) {
        if pid == 0 {
            return;
        }
        let mut entries = self.queries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_ORIGINS {
            entries.retain(|_, origin| now.saturating_duration_since(origin.at) < ORIGIN_TTL);
            if entries.len() >= MAX_ORIGINS
                && let Some(oldest) = entries.iter().min_by_key(|(_, v)| v.at).map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        // Keep the most recent caller; a name is never a permanent bypass rule.
        entries.insert(question, Origin { pid, at: now });
    }
    fn pid(&self, question: &Question, now: Instant) -> Option<u32> {
        let entries = self.queries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .get(question)
            .filter(|origin| now.saturating_duration_since(origin.at) < ORIGIN_TTL)
            .map(|origin| origin.pid)
    }
}

// ETW payload fields are packed, not naturally aligned. Decode from byte slices
// and accept only the manifest versions whose layouts we understand.
fn wide(data: &mut &[u8]) -> Option<String> {
    let end = data.chunks_exact(2).position(|c| c == [0, 0])?;
    let units = data[..end * 2]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect::<Vec<_>>();
    *data = &data[(end + 1) * 2..];
    String::from_utf16(&units).ok()
}
fn number(data: &mut &[u8]) -> Option<u32> {
    let value = u32::from_le_bytes(data.get(..4)?.try_into().ok()?);
    *data = &data[4..];
    Some(value)
}
fn origin(id: u16, version: u8, header_pid: u32, mut data: &[u8]) -> Option<(Question, u32)> {
    if !matches!((id, version), (3006, 0) | (3010, 1)) {
        return None;
    }
    let name = wide(&mut data)?;
    let kind = u16::try_from(number(&mut data)?).ok()?;
    let pid = if id == 3010 {
        wide(&mut data)?;
        number(&mut data)?
    } else {
        header_pid
    };
    Some((Question::new(&name, kind), pid))
}

unsafe extern "system" fn event(record: *mut EVENT_RECORD) {
    // SAFETY: ProcessTrace owns the record/data for this callback. Context is an
    // Arc-backed State kept alive until CloseTrace and the consumer join finish.
    let record = unsafe { &*record };
    if record.UserContext.is_null() || record.UserData.is_null() {
        return;
    }
    let state = unsafe { &*record.UserContext.cast::<State>() };
    let bytes = unsafe { std::slice::from_raw_parts(record.UserData.cast::<u8>(), usize::from(record.UserDataLength)) };
    if same_guid(record.EventHeader.ProviderId, CHECKPOINT_PROVIDER) && record.EventHeader.ProcessId == std::process::id() {
        if record.EventHeader.EventDescriptor.Id == 1
            && let Ok(bytes) = <[u8; 16]>::try_from(bytes)
            && u64::from_le_bytes(bytes[..8].try_into().expect("fixed-size checkpoint")) == state.marker_id
        {
            let value = u64::from_le_bytes(bytes[8..].try_into().expect("fixed-size checkpoint"));
            state.delivered.fetch_max(value, Ordering::Release);
            state.changed.notify_waiters();
        }
    } else if same_guid(record.EventHeader.ProviderId, DNS_PROVIDER) {
        let descriptor = record.EventHeader.EventDescriptor;
        if let Some((question, pid)) = origin(descriptor.Id, descriptor.Version, record.EventHeader.ProcessId, bytes) {
            state.record(question, pid, Instant::now());
        }
    }
}

#[repr(C)]
struct Properties {
    value: EVENT_TRACE_PROPERTIES,
    name: [u16; 128],
}
impl Default for Properties {
    fn default() -> Self {
        let mut properties = Self {
            value: EVENT_TRACE_PROPERTIES::default(),
            name: [0; 128],
        };
        properties.value.Wnode.BufferSize = std::mem::size_of::<Self>() as u32;
        properties.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // QPC preserves ordering across wall-clock corrections (ProcessTrace
        // orders records by their timestamps before invoking the callbacks).
        properties.value.Wnode.ClientContext = 1;
        properties.value.BufferSize = 64;
        properties.value.MinimumBuffers = 2;
        properties.value.MaximumBuffers = 4;
        properties.value.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        properties.value.FlushTimer = 1;
        properties.value.LoggerNameOffset = std::mem::offset_of!(Self, name) as u32;
        properties
    }
}
fn check(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn check_start(status: u32, operation: &str) -> io::Result<()> {
    check(status).map_err(|error| io::Error::other(format!("{operation} for Windows DNS attribution: {error}")))
}

fn trace_owner(name: &str) -> Option<u32> {
    let suffix = name.strip_prefix("CipherRelay-DNS-")?;
    let (pid, sequence) = suffix.split_once('-')?;
    let pid = pid.parse::<u32>().ok().filter(|pid| *pid != 0)?;
    sequence.parse::<u64>().ok()?;
    Some(pid)
}

/// Real-time ETW sessions outlive an abruptly terminated controller. Repeated
/// crashes/upgrades must not exhaust Windows' logger/provider slots. Only our
/// exact session names with a provably absent owner are eligible for cleanup.
fn reclaim_orphaned_traces() -> io::Result<usize> {
    #[repr(C)]
    struct QueryProperties {
        value: EVENT_TRACE_PROPERTIES,
        name: [u16; 1024],
        file: [u16; 1024],
    }
    let mut count = 64;
    let mut entries;
    loop {
        entries = (0..count)
            .map(|_| {
                let mut entry = Box::new(QueryProperties {
                    value: EVENT_TRACE_PROPERTIES::default(),
                    name: [0; 1024],
                    file: [0; 1024],
                });
                entry.value.Wnode.BufferSize = std::mem::size_of::<QueryProperties>() as u32;
                entry.value.LoggerNameOffset = std::mem::offset_of!(QueryProperties, name) as u32;
                entry.value.LogFileNameOffset = std::mem::offset_of!(QueryProperties, file) as u32;
                entry
            })
            .collect::<Vec<_>>();
        let mut pointers = entries.iter_mut().map(|entry| &mut entry.value as *mut _).collect::<Vec<_>>();
        let mut needed = 0;
        // SAFETY: every pointer identifies a stable, writable allocation with
        // enough space for both names; QueryAllTraces fills at most count rows.
        let status = unsafe { QueryAllTracesW(pointers.as_mut_ptr(), count, &mut needed) };
        if status == ERROR_MORE_DATA && needed > count && needed <= 1024 {
            count = needed;
            continue;
        }
        check(status)?;
        entries.truncate(needed as usize);
        break;
    }
    let mut reclaimed = 0;
    for entry in entries {
        let length = entry.name.iter().position(|unit| *unit == 0).unwrap_or(entry.name.len());
        let name = String::from_utf16_lossy(&entry.name[..length]);
        let Some(pid) = trace_owner(&name) else { continue };
        // Access denied is not proof of death (protected processes and other
        // users can be inaccessible). A reused, live PID is left alone too.
        // SAFETY: the returned owned handle is closed immediately when valid.
        let absent = unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid);
            if handle.is_null() {
                GetLastError() == ERROR_INVALID_PARAMETER
            } else {
                // Windows can retain an exited process object while another
                // observer still holds a handle. Existence alone is not life.
                let exited = WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
                CloseHandle(handle);
                exited
            }
        };
        if !absent {
            continue;
        }
        let mut properties = Properties::default();
        // SAFETY: entry.name is NUL-terminated by the enumeration, and the
        // queried logger handle addresses this exact session, not a replacement.
        let handle = CONTROLTRACE_HANDLE {
            Value: unsafe { entry.value.Wnode.Anonymous1.HistoricalContext },
        };
        check(unsafe { ControlTraceW(handle, entry.name.as_ptr(), &mut properties.value, EVENT_TRACE_CONTROL_STOP) })?;
        reclaimed += 1;
        log::info!("Reclaimed orphaned Windows DNS trace {name} after owner pid {pid} exited");
    }
    Ok(reclaimed)
}

struct Trace {
    control: CONTROLTRACE_HANDLE,
    reader: PROCESSTRACE_HANDLE,
    marker: REGHANDLE,
    consumer: Option<std::thread::JoinHandle<()>>,
    state: Arc<State>,
    sequence: AtomicU64,
    healthy: AtomicBool,
    flush_slot: tokio::sync::Mutex<()>,
}

impl Trace {
    fn start() -> io::Result<Self> {
        if let Err(error) = reclaim_orphaned_traces() {
            log::warn!("Could not inspect stale Windows DNS traces: {error}");
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let marker_id = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("CipherRelay-DNS-{}-{marker_id}\0", std::process::id());
        let name = name.encode_utf16().collect::<Vec<_>>();
        let mut properties = Properties::default();
        let mut control = CONTROLTRACE_HANDLE::default();
        // SAFETY: name is NUL-terminated, properties includes the name buffer.
        // A collision is an error: never attach to or stop someone else's trace.
        check_start(
            unsafe { StartTraceW(&mut control, name.as_ptr(), &mut properties.value) },
            "StartTraceW",
        )?;
        let mut trace = Self {
            control,
            reader: PROCESSTRACE_HANDLE { Value: INVALID_TRACE },
            marker: 0,
            consumer: None,
            state: Arc::new(State {
                marker_id,
                ..Default::default()
            }),
            sequence: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
            flush_slot: tokio::sync::Mutex::new(()),
        };
        #[repr(C)]
        struct Filter {
            include: bool,
            reserved: u8,
            count: u16,
            events: [u16; 2],
        }
        let filter = Filter {
            include: true,
            reserved: 0,
            count: 2,
            events: [3006, 3010],
        };
        let mut descriptor = EVENT_FILTER_DESCRIPTOR {
            Ptr: (&filter as *const Filter) as u64,
            Size: std::mem::size_of::<Filter>() as u32,
            Type: EVENT_FILTER_TYPE_EVENT_ID,
        };
        let parameters = ENABLE_TRACE_PARAMETERS {
            Version: 2,
            EnableFilterDesc: &mut descriptor,
            FilterDescCount: 1,
            ..Default::default()
        };
        // Timeout=0 would return before the providers are enabled. Wait for
        // activation so neither the first DNS event nor our checkpoint is lost.
        // SAFETY: EnableTraceEx2 copies the filter during this synchronous call.
        check_start(
            unsafe {
                EnableTraceEx2(
                    control,
                    &DNS_PROVIDER,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    5,
                    u64::MAX,
                    0,
                    1_000,
                    &parameters,
                )
            },
            "EnableTraceEx2(DNS)",
        )?;
        // A checkpoint in the same ordered event stream lets a query wait for
        // preceding DNS events without a polling thread or fixed per-query sleep.
        check_start(
            unsafe { EventRegister(&CHECKPOINT_PROVIDER, None, std::ptr::null(), &mut trace.marker) },
            "EventRegister(checkpoint)",
        )?;
        check_start(
            unsafe {
                EnableTraceEx2(
                    control,
                    &CHECKPOINT_PROVIDER,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    5,
                    u64::MAX,
                    0,
                    1_000,
                    std::ptr::null(),
                )
            },
            "EnableTraceEx2(checkpoint)",
        )?;
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: name.as_ptr().cast_mut(),
            Context: Arc::as_ptr(&trace.state).cast_mut().cast(),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event);
        // SAFETY: OpenTrace copies the configuration. State survives the reader.
        trace.reader = unsafe { OpenTraceW(&mut logfile) };
        if trace.reader.Value == INVALID_TRACE {
            return Err(io::Error::last_os_error());
        }
        let reader = trace.reader;
        let state = trace.state.clone();
        trace.consumer = Some(std::thread::Builder::new().name("dns-query-origins".into()).spawn(move || {
            // SAFETY: reader is owned by Trace, which closes it before joining us.
            let result = unsafe { ProcessTrace(&reader, 1, std::ptr::null(), std::ptr::null()) };
            if result != 0 {
                log::debug!("DNS event consumer ended: {}", io::Error::from_raw_os_error(result as i32));
            }
            drop((state, name));
        })?);
        Ok(trace)
    }

    fn checkpoint(&self, sequence: u64) -> io::Result<()> {
        let payload = [self.state.marker_id, sequence];
        let descriptor = EVENT_DESCRIPTOR {
            Id: 1,
            Level: 4,
            Keyword: 1,
            ..Default::default()
        };
        let data = EVENT_DATA_DESCRIPTOR {
            Ptr: payload.as_ptr() as u64,
            Size: std::mem::size_of_val(&payload) as u32,
            ..Default::default()
        };
        let mut properties = Properties::default();
        // SAFETY: registration/control handles belong to this live Trace; all
        // mutable output buffers are local to this call, not shared across tasks.
        check(unsafe { EventWrite(self.marker, &descriptor, 1, &data) })?;
        check(unsafe { ControlTraceW(self.control, std::ptr::null(), &mut properties.value, EVENT_TRACE_CONTROL_FLUSH) })?;
        if properties.value.EventsLost != 0 || properties.value.RealTimeBuffersLost != 0 {
            return Err(io::Error::other("DNS event stream lost events"));
        }
        Ok(())
    }

    async fn synchronize(self: &Arc<Self>) -> io::Result<()> {
        let observed = self.sequence.load(Ordering::Acquire);
        let _slot = self.flush_slot.lock().await;
        // A checkpoint issued after this request started also fences its DNS
        // event. Share that checkpoint with queued callers instead of flushing
        // once per question during a browser's concurrent DNS burst.
        if self.state.delivered.load(Ordering::Acquire) > observed {
            return Ok(());
        }
        let sequence = self.sequence.fetch_add(1, Ordering::AcqRel) + 1;
        let trace = self.clone();
        tokio::task::spawn_blocking(move || trace.checkpoint(sequence))
            .await
            .map_err(io::Error::other)??;
        loop {
            let notified = self.state.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.delivered.load(Ordering::Acquire) >= sequence {
                return Ok(());
            }
            notified.await;
        }
    }
}
impl Drop for Trace {
    fn drop(&mut self) {
        let mut properties = Properties::default();
        // SAFETY: only our successfully created session is stopped. Closing the
        // reader unblocks ProcessTrace; joining precedes release of its context.
        unsafe {
            ControlTraceW(self.control, std::ptr::null(), &mut properties.value, EVENT_TRACE_CONTROL_STOP);
            if self.reader.Value != INVALID_TRACE {
                CloseTrace(self.reader);
            }
            if self.marker != 0 {
                EventUnregister(self.marker);
            }
        }
        if let Some(consumer) = self.consumer.take() {
            let _ = consumer.join();
        }
    }
}

#[derive(Clone)]
pub(crate) struct QueryOrigins(Arc<Trace>);
impl QueryOrigins {
    pub async fn start() -> io::Result<Self> {
        let trace = Arc::new(tokio::task::spawn_blocking(Trace::start).await.map_err(io::Error::other)??);
        tokio::time::timeout(Duration::from_secs(1), trace.synchronize())
            .await
            .map_err(io::Error::other)??;
        log::info!("Windows DNS caller attribution enabled for all process bypass rules");
        Ok(Self(trace))
    }
    pub async fn bypass(&self, request: &[u8], processes: &crate::ProcessBypass) -> crate::Result<bool> {
        // Keep the trace alive for runtime rule changes, but avoid checkpoints
        // and process snapshots while no caller can match the policy.
        if !processes.is_configured() {
            return Ok(false);
        }
        let message = crate::dns::parse_data_to_dns_message(request, false)?;
        let query = crate::dns::validate_dns_query(&message)?;
        let question = Question::new(&query.name().to_ascii(), query.query_type().into());
        if let Err(error) = tokio::time::timeout(Duration::from_secs(1), self.0.synchronize())
            .await
            .map_err(io::Error::other)
            .and_then(|r| r)
        {
            if self.0.healthy.swap(false, Ordering::Relaxed) {
                log::warn!("Windows DNS caller attribution unavailable; socket ownership still applies: {error}");
            }
            return Ok(false);
        }
        if !self.0.healthy.swap(true, Ordering::Relaxed) {
            log::info!("Windows DNS caller attribution recovered");
        }
        let Some(pid) = self.0.state.pid(&question, Instant::now()) else {
            return Ok(false);
        };
        let identities = tokio::task::spawn_blocking(move || crate::process::dns_process_names(pid))
            .await
            .map_err(io::Error::other)?;
        let bypass = crate::process::matches_policy(processes, &identities);
        log::log!(
            if bypass { log::Level::Info } else { log::Level::Debug },
            "DNS caller: name={}, type={}, pid={pid}, identities={identities:?}, bypass={bypass}",
            question.name,
            question.kind
        );
        Ok(bypass)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orphan_cleanup_only_recognizes_exact_owned_session_names() {
        assert_eq!(trace_owner("CipherRelay-DNS-1234-0"), Some(1234));
        for name in [
            "Other-DNS-1234-0",
            "CipherRelay-DNS-0-1",
            "CipherRelay-DNS-1234",
            "CipherRelay-DNS-1234-0-extra",
        ] {
            assert_eq!(trace_owner(name), None, "{name}");
        }
    }

    #[tokio::test]
    #[ignore = "requires Windows administrator ETW access; does not alter routes or DNS settings"]
    async fn real_windows_dns_trace_can_start_and_stop_repeatedly() {
        for _ in 0..3 {
            let origins = QueryOrigins::start().await.expect("DNS attribution must start");
            origins.0.synchronize().await.expect("DNS checkpoint must arrive");
            drop(origins);
        }
    }

    #[test]
    #[ignore = "helper process for real_windows_dns_recovers_orphan_without_stopping_live_owner"]
    fn dns_crash_fixture() {
        let Some(marker) = std::env::var_os("CIPHERRELAY_DNS_CRASH_FIXTURE") else {
            return;
        };
        let _trace = Trace::start().unwrap();
        std::fs::write(marker, b"ready").unwrap();
        // Deliberately bypass Drop, exactly as ExitProcess or a crash does.
        std::process::exit(77);
    }

    #[tokio::test]
    #[ignore = "requires Windows administrator ETW access; does not alter routes or DNS settings"]
    async fn real_windows_dns_recovers_orphan_without_stopping_live_owner() {
        let live = QueryOrigins::start().await.unwrap();
        let marker = std::env::temp_dir().join(format!("dns-crash-fixture-{}.ready", std::process::id()));
        struct Fixture {
            child: std::process::Child,
            marker: std::path::PathBuf,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let _ = std::fs::remove_file(&self.marker);
                let _ = reclaim_orphaned_traces();
            }
        }
        let mut fixture = Fixture {
            child: std::process::Command::new(std::env::current_exe().unwrap())
                .args(["dns_crash_fixture", "--ignored", "--nocapture"])
                .env("CIPHERRELAY_DNS_CRASH_FIXTURE", &marker)
                .spawn()
                .unwrap(),
            marker: marker.clone(),
        };
        let child_id = fixture.child.id();
        assert_eq!(fixture.child.wait().unwrap().code(), Some(77));
        assert_eq!(std::fs::read(&marker).unwrap(), b"ready");
        std::fs::remove_file(marker).unwrap();
        let name = format!("CipherRelay-DNS-{child_id}-0\0").encode_utf16().collect::<Vec<_>>();
        let query = || {
            let mut properties = Properties::default();
            unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    name.as_ptr(),
                    &mut properties.value,
                    EVENT_TRACE_CONTROL_QUERY,
                )
            }
        };
        assert_eq!(query(), 0, "The child left a real ETW session behind");
        assert!(reclaim_orphaned_traces().unwrap() >= 1);
        assert_ne!(query(), 0, "The orphan session was reclaimed");
        live.0.synchronize().await.expect("The live owner's trace must be preserved");
        drop(QueryOrigins::start().await.unwrap());
    }

    #[tokio::test]
    #[ignore = "requires Windows administrator ETW access; makes external DNS queries, without changing networking"]
    async fn real_windows_dns_events_preserve_child_pid_and_runtime_policy() {
        use std::io::{BufRead, Write};
        use std::process::{Command, Stdio};
        // Exercise immediate checkpoints without logging or sleeps masking the
        // provider-enable race. Each iteration also closes its own ETW session.
        let started = Instant::now();
        for _ in 0..10 {
            drop(QueryOrigins::start().await.unwrap());
        }
        println!("Ten cold starts and cleanups completed in {:?}", started.elapsed());
        let origins = QueryOrigins::start().await.unwrap();
        let host = format!("codex-dns-{}.example.com", std::process::id());
        let script =
            format!("$t = [System.Net.Dns]::GetHostAddressesAsync('{host}'); Write-Output 'started'; [Console]::ReadLine() | Out-Null");
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut reader = std::io::BufReader::new(child.0.stdout.take().unwrap());
        let mut ready = String::new();
        reader.read_line(&mut ready).unwrap();
        assert_eq!(ready.trim(), "started");
        let question = Question::new(&host, 1);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                origins.0.synchronize().await.unwrap();
                if origins.0.state.pid(&question, Instant::now()) == Some(child.0.id()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let request = super::super::tests::request(&host);
        let processes = crate::ProcessBypass::new(["powershell.exe".into()]);
        let started = Instant::now();
        assert!(origins.bypass(&request, &processes).await.unwrap());
        println!("Observed original PID {}; classification {:?}", child.0.id(), started.elapsed());
        let started = Instant::now();
        let mut queries = tokio::task::JoinSet::new();
        for _ in 0..64 {
            let (origins, request, processes) = (origins.clone(), request.clone(), processes.clone());
            queries.spawn(async move { origins.bypass(&request, &processes).await });
        }
        while let Some(result) = queries.join_next().await {
            assert!(result.unwrap().unwrap());
        }
        println!("64 concurrent caller checks completed in {:?}", started.elapsed());
        super::super::tests::verify_real_process_dns_routing(&host, processes.clone(), origins.clone()).await;
        processes.set_names(["unrelated.exe".into()]);
        assert!(!origins.bypass(&request, &processes).await.unwrap());
        origins.0.state.record(question, std::process::id(), Instant::now());
        assert!(!origins.bypass(&request, &processes).await.unwrap());
        let executable = std::env::current_exe().unwrap();
        processes.set_names([executable.file_name().unwrap().to_string_lossy().into_owned()]);
        assert!(origins.bypass(&request, &processes).await.unwrap());
        // A busy consumer may miss one deadline without ending the ETW session.
        let slot = origins.0.flush_slot.lock().await;
        assert!(!origins.bypass(&request, &processes).await.unwrap());
        assert!(!origins.0.healthy.load(Ordering::Relaxed));
        processes.set_names([]);
        assert!(!origins.bypass(&[], &processes).await.unwrap());
        drop(slot);
        processes.set_names([executable.file_name().unwrap().to_string_lossy().into_owned()]);
        assert!(origins.bypass(&request, &processes).await.unwrap());
        assert!(origins.0.healthy.load(Ordering::Relaxed));
        child.0.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
        child.0.wait().unwrap();
    }
    #[test]
    fn dns_service_payload_uses_client_pid_and_origins_expire_or_are_replaced() {
        let mut bytes = "EXAMPLE.com\0".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend("10.0.0.1\0".encode_utf16().flat_map(u16::to_le_bytes));
        bytes.extend_from_slice(&42u32.to_le_bytes());
        let (key, pid) = origin(3010, 1, 999, &bytes).unwrap();
        assert_eq!(pid, 42);
        assert_eq!(key.name, "example.com");
        assert!(origin(3010, 0, 999, &bytes).is_none());
        for n in 0..bytes.len() {
            assert!(origin(3010, 1, 999, &bytes[..n]).is_none());
        }
        let state = State::default();
        let now = Instant::now();
        state.record(key.clone(), 42, now);
        assert_eq!(state.pid(&Question::new("example.com.", 1), now), Some(42));
        assert_eq!(state.pid(&Question::new("example.com.", 28), now), None);
        state.record(key.clone(), 77, now);
        assert_eq!(state.pid(&key, now), Some(77));
        assert_eq!(state.pid(&key, now + ORIGIN_TTL), None);
    }
}
