//! Wrapper around `netwatch_sdk::ebpf::EventSource`.
//!
//! Owns the eBPF event source and a background thread that drains decoded
//! `EbpfEvent`s from the SDK's mpsc receiver into an attribution cache.
//! `ConnectionCollector` consults the cache when overlaying kernel-derived
//! `(pid, comm)` onto lsof/ss-discovered connections — the same shape as
//! the macOS PKTAP integration, just with a different kernel data source.
//!
//! Phase 1 of the SDK's eBPF roadmap covers `tcp_v4_connect` only:
//! - IPv4 TCP only (no IPv6, no UDP)
//! - Source port is 0 in events (kernel field requires CO-RE — later
//!   roadmap phase). We key the cache by (saddr, daddr, dport) and accept
//!   that two concurrent connections from the same source to the same
//!   `daddr:dport` would alias. Rare in practice.
//!
//! Compiles on non-Linux targets when `--features ebpf` is set so
//! cross-platform builds keep working; `EventSource::new` returns
//! `EbpfError::UnsupportedPlatform` at runtime there.

use netwatch_sdk::ebpf::{ConnectEvent, EbpfError, EbpfEvent, EventSource};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Lifetime of a cache entry after the matching kprobe last fired. Matches
/// the PKTAP TTL — long enough to span a few lsof poll cycles, short
/// enough that closed connections age out.
const ATTRIBUTION_TTL: Duration = Duration::from_secs(60);

/// Cached attribution from a `tcp_v4_connect` kprobe firing.
#[derive(Debug, Clone)]
pub struct EbpfAttribution {
    pub pid: u32,
    pub comm: String,
    pub seen_at: Instant,
}

/// `(saddr, daddr, dport)` — see module docstring on why sport is omitted.
type AttrKey = (Ipv4Addr, Ipv4Addr, u16);

/// Shared cache of `AttrKey → EbpfAttribution`. Populated by the background
/// drain thread, consulted by the connection collector.
#[derive(Default)]
pub struct EbpfAttributor {
    cache: Mutex<HashMap<AttrKey, EbpfAttribution>>,
}

impl EbpfAttributor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn lookup(&self, saddr: Ipv4Addr, daddr: Ipv4Addr, dport: u16) -> Option<EbpfAttribution> {
        self.cache.lock().ok()?.get(&(saddr, daddr, dport)).cloned()
    }

    fn record(&self, key: AttrKey, attr: EbpfAttribution) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(key, attr);
        }
    }

    fn evict_stale(&self, ttl: Duration) {
        if let Ok(mut cache) = self.cache.lock() {
            let now = Instant::now();
            cache.retain(|_, a| now.duration_since(a.seen_at) < ttl);
        }
    }
}

/// Owns the SDK's `EventSource` plus a background thread draining its
/// receiver into the attributor cache. Drop to stop the thread.
pub struct ConnTracker {
    pub attributor: Arc<EbpfAttributor>,
    /// `EventSource` is held to keep the BPF programs attached for the
    /// lifetime of the tracker. Dropping it detaches the kprobe.
    _source: EventSource,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ConnTracker {
    /// Load and attach the BPF programs, spawn the drain thread, and
    /// return a tracker. On non-Linux or when the BPF object is missing
    /// returns the `EbpfError` from the SDK so the caller can surface it
    /// to the UI.
    pub fn new() -> Result<Self, EbpfError> {
        let (source, rx) = EventSource::new()?;
        let attributor = EbpfAttributor::new();
        let stop = Arc::new(AtomicBool::new(false));

        let thread_attr = Arc::clone(&attributor);
        let thread_stop = Arc::clone(&stop);
        let join = thread::Builder::new()
            .name("ebpf-attributor".into())
            .spawn(move || {
                let mut last_evict = Instant::now();
                while !thread_stop.load(Ordering::Relaxed) {
                    // recv_timeout so the loop checks the stop flag even
                    // when the kprobe is silent for long stretches.
                    match rx.recv_timeout(Duration::from_millis(500)) {
                        Ok(EbpfEvent::Connect(evt)) => record_connect(&thread_attr, evt),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        // Sender hung up (EventSource dropped) — exit loop.
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    if last_evict.elapsed() >= Duration::from_secs(10) {
                        thread_attr.evict_stale(ATTRIBUTION_TTL);
                        last_evict = Instant::now();
                    }
                }
            })
            .ok();

        Ok(Self {
            attributor,
            _source: source,
            stop,
            join,
        })
    }
}

impl Drop for ConnTracker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

fn record_connect(attributor: &Arc<EbpfAttributor>, evt: ConnectEvent) {
    // Skip kernel-internal sockets and unreachable saddr=0.0.0.0 events
    // that some kernels emit for sockets not yet bound. They can't be
    // matched against any /proc connection.
    if evt.saddr.is_unspecified() || evt.daddr.is_unspecified() || evt.dport == 0 {
        return;
    }
    attributor.record(
        (evt.saddr, evt.daddr, evt.dport),
        EbpfAttribution {
            pid: evt.pid,
            comm: evt.comm,
            seen_at: Instant::now(),
        },
    );
}
