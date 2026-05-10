//! eBPF subsystem for enhanced kernel-level network monitoring.
//!
//! This module is optional and only active on Linux with the `ebpf` feature flag:
//! `cargo build --features ebpf`
//!
//! When not compiled, stubs are provided so the rest of the app works unchanged.

#[cfg(feature = "ebpf")]
pub mod conn_tracker;
pub mod rtt_monitor;

/// Status of the eBPF subsystem, used by the UI status indicator.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum EbpfStatus {
    /// eBPF is loaded and the kprobe is firing into the attribution cache.
    Active,
    /// eBPF compiled in, but `EventSource::new()` failed at runtime
    /// (UnsupportedPlatform on non-Linux, missing CAP_BPF/CAP_PERFMON,
    /// kernel rejected the program, BPF object not embedded, …).
    Unavailable(String),
    /// `--features ebpf` wasn't enabled at build time.
    NotCompiled,
}
