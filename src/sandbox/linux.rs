//! Linux sandbox backend — capability drop + Landlock filesystem
//! restrictions.
//!
//! Phase 1 does *not* enable Landlock's network-block (ABI V4) rule. The
//! TUI makes legitimate outbound HTTPS calls for ip-api.com GeoIP
//! fallback, `--remote` metric streaming, and inline WHOIS lookups; a
//! blanket TCP-block would silently break working features. A later
//! phase can add port-allow-listing once those endpoints are known at
//! startup.

use super::paths::SandboxPaths;
use super::{Mode, Report};

use caps::{CapSet, Capability};
use landlock::{
    path_beneath_rules, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::path::{Path, PathBuf};

/// Highest Landlock ABI we know how to target. ABI V4 (Linux 6.4+)
/// brings TCP bind/connect restrictions; the crate degrades cleanly to
/// V3 / V2 / V1 on older kernels.
const TARGET_ABI: ABI = ABI::V4;

/// Capabilities we want gone after pcap and the eBPF kprobe are up.
const CAPS_TO_DROP: &[Capability] = &[
    Capability::CAP_NET_RAW,
    Capability::CAP_BPF,
    Capability::CAP_PERFMON,
    // CAP_SYS_ADMIN is the legacy fallback for BPF on pre-5.8 kernels.
    // Drop it too — modern userspaces don't need it post-attach.
    Capability::CAP_SYS_ADMIN,
];

pub fn apply(mode: Mode, paths: &SandboxPaths, report: &mut Report) {
    report.mode.effective = Some(mode.label());

    drop_caps(report);

    let read_only = collect_read_only(paths);
    let read_write = collect_read_write(paths);

    if let Err(e) = apply_landlock(&read_only, &read_write, report) {
        let msg = format!("Landlock not applied: {e}");
        tracing::warn!(target: "netwatch::sandbox", error = %e, "Landlock not applied");
        report.mode.warnings.push(msg);
    }

    if matches!(mode, Mode::Strict) && report.platform.landlock_abi == 0 {
        report
            .mode
            .warnings
            .push("strict sandbox requested but Landlock did not enforce".into());
    }
}

fn drop_caps(report: &mut Report) {
    for cap in CAPS_TO_DROP {
        // Try to drop from every set we have access to. `caps::drop`
        // returns Ok(()) even if the cap wasn't present, so the no-cap
        // (unprivileged) path is silently fine.
        let permitted_before = caps::has_cap(None, CapSet::Permitted, *cap).unwrap_or(false);

        // Effective + Permitted + Inheritable — full hand-back. Skip
        // Bounding because dropping from there requires CAP_SETPCAP and
        // failing silently is better than aborting startup.
        let _ = caps::drop(None, CapSet::Effective, *cap);
        let _ = caps::drop(None, CapSet::Inheritable, *cap);
        let _ = caps::drop(None, CapSet::Permitted, *cap);

        if permitted_before {
            report
                .platform
                .caps_dropped
                .push(cap_name(*cap).to_string());
        }
    }
}

fn cap_name(cap: Capability) -> &'static str {
    match cap {
        Capability::CAP_NET_RAW => "CAP_NET_RAW",
        Capability::CAP_BPF => "CAP_BPF",
        Capability::CAP_PERFMON => "CAP_PERFMON",
        Capability::CAP_SYS_ADMIN => "CAP_SYS_ADMIN",
        _ => "CAP_OTHER",
    }
}

/// Paths we need to be able to read once restricted. Order doesn't
/// matter; missing paths are silently skipped.
///
/// The allow-list is intentionally broad on system dirs (`/proc`, `/sys`,
/// `/usr`, `/etc`, `/bin`, `/sbin`, `/lib`) — those contain no per-user
/// secrets and are needed by every subprocess (`ss`, `lsof`, `ip`,
/// `traceroute`, `whois`) that inherits the Landlock policy. The
/// confidentiality benefit comes from omitting `/home`, `/root`,
/// `/var/lib/*`, mail spools, browser profiles, etc.
fn collect_read_only(paths: &SandboxPaths) -> Vec<PathBuf> {
    let mut out = Vec::new();

    for path in [
        // procfs — interface counters, /proc/net/dev, process attribution.
        "/proc",
        // sysfs — interface info, statistics, wireless detection
        // (`/sys/class/net/*/{statistics,operstate,carrier,mtu,address,wireless}`).
        "/sys",
        // Executables the connection / topology / WHOIS collectors spawn
        // (ss, lsof, ip, traceroute, whois, host). Landlock applies its
        // policy to children, so the children also need Execute on
        // their own binaries. Allow these broadly.
        "/bin",
        "/sbin",
        "/usr",
        // Dynamic linker / shared library load paths.
        "/lib",
        "/lib64",
        // System resolver + service-name files. getaddrinfo() walks NSS
        // modules from /usr/lib/x86_64-linux-gnu/libnss_*.so plus
        // /etc/{passwd,group,nsswitch.conf}. Narrow list (instead of
        // allow-all /etc) is deliberate so a sudo'd netwatch can't read
        // /etc/shadow or /etc/sudoers through the sandbox.
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/services",
        "/etc/nsswitch.conf",
        "/etc/host.conf",
        "/etc/gai.conf",
        "/etc/protocols",
        "/etc/passwd",
        "/etc/group",
        "/etc/os-release",
        "/etc/localtime",
        "/etc/timezone",
        "/etc/ssl",
        "/etc/pki",
        "/etc/ca-certificates",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        // systemd-resolved socket dir (NSS via systemd-resolved variant).
        "/run/systemd/resolve",
        // DBus runtime dir for tools that talk to system services.
        "/run/dbus",
    ] {
        out.push(PathBuf::from(path));
    }

    if let Some(p) = &paths.config_dir {
        out.push(p.clone());
    }
    if let Some(p) = &paths.geoip_db_dir {
        out.push(p.clone());
    }
    if let Some(p) = &paths.geoip_asn_db_dir {
        out.push(p.clone());
    }

    out
}

/// Paths we need to be able to write to. Read access is implied by
/// `AccessFs::from_all` so these don't also need to appear in the
/// read-only list.
fn collect_read_write(paths: &SandboxPaths) -> Vec<PathBuf> {
    let mut out = Vec::new();

    if let Some(p) = &paths.cache_dir {
        out.push(p.clone());
    }
    if let Some(p) = &paths.cwd {
        // PCAP exports and Flight Recorder bundles land in CWD by
        // default. Locked at startup — see SandboxPaths::from_config.
        out.push(p.clone());
    }
    // `/tmp` and per-user `/run/user/<uid>` — common scratch dirs for
    // temp files, shared-memory backing, and the like.
    out.push(PathBuf::from("/tmp"));
    if let Some(uid_dir) = runtime_user_dir() {
        out.push(uid_dir);
    }
    // `/dev/null` is needed for various stdlib paths (e.g., NSS
    // canary opens).
    out.push(PathBuf::from("/dev/null"));

    out
}

fn runtime_user_dir() -> Option<PathBuf> {
    let uid = unsafe { nix::libc::getuid() };
    let candidate = PathBuf::from(format!("/run/user/{uid}"));
    candidate.exists().then_some(candidate)
}

fn apply_landlock(
    read_only: &[PathBuf],
    read_write: &[PathBuf],
    report: &mut Report,
) -> Result<(), landlock::RulesetError> {
    // BestEffort lets the crate downgrade ABI features (e.g., V4
    // network access types) on older kernels without erroring.
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(TARGET_ABI))?;

    let read_rules =
        path_beneath_rules(filter_existing(read_only), AccessFs::from_read(TARGET_ABI));
    let write_rules =
        path_beneath_rules(filter_existing(read_write), AccessFs::from_all(TARGET_ABI));

    let status = ruleset
        .create()?
        .add_rules(read_rules)?
        .add_rules(write_rules)?
        .restrict_self()?;

    // Record the effective ABI for the Settings overlay. `landlock`
    // exposes the effective ABI inside `LandlockStatus::Available`.
    match status.landlock {
        landlock::LandlockStatus::Available { effective_abi, .. } => {
            report.platform.landlock_abi = effective_abi as u32;
        }
        landlock::LandlockStatus::NotEnabled | landlock::LandlockStatus::NotImplemented => {
            // Ruleset wasn't enforced — keep landlock_abi at 0.
        }
    }

    if status.ruleset == RulesetStatus::NotEnforced {
        report
            .mode
            .warnings
            .push("Landlock present but ruleset was not enforced".into());
    } else if status.ruleset == RulesetStatus::PartiallyEnforced {
        report
            .mode
            .warnings
            .push("Landlock ruleset partially enforced (older kernel)".into());
    }

    Ok(())
}

/// Yield only paths that actually exist. PathFd::new opens the path
/// via O_PATH and fails on ENOENT; pre-filtering is cheaper than
/// catching that inside path_beneath_rules.
fn filter_existing<'a>(paths: &'a [PathBuf]) -> impl Iterator<Item = &'a Path> + 'a {
    paths
        .iter()
        .filter_map(|p| if p.exists() { Some(p.as_path()) } else { None })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_read_only_includes_proc_and_etc() {
        let paths = SandboxPaths::default();
        let ro = collect_read_only(&paths);
        assert!(ro.iter().any(|p| p == Path::new("/proc")));
        assert!(ro.iter().any(|p| p == Path::new("/etc/resolv.conf")));
    }

    #[test]
    fn collect_read_write_includes_tmp() {
        let paths = SandboxPaths::default();
        let rw = collect_read_write(&paths);
        assert!(rw.iter().any(|p| p == Path::new("/tmp")));
    }
}
