//! Collect the allow-list paths the sandbox needs to permit.
//!
//! Built once at startup from `NetwatchConfig` + the platform-derived
//! cache/config dirs. Captured eagerly so the sandbox knows exactly what
//! to permit before `apply()` runs — changing PCAP-export paths or
//! GeoIP-db paths mid-session is intentionally not supported under the
//! sandbox (would require lifting and re-applying Landlock, which is
//! one-shot per thread).

use crate::config::NetwatchConfig;
use std::path::PathBuf;

/// Paths the sandbox needs to know about. All optional — empty entries
/// are skipped at apply time rather than treated as `/` allow-all.
#[derive(Debug, Clone, Default)]
pub struct SandboxPaths {
    /// `~/.cache/netwatch/` — log files + Flight Recorder bundles + any
    /// other transient output the TUI writes.
    pub cache_dir: Option<PathBuf>,
    /// `~/.config/netwatch/` — config.toml read at startup and on
    /// settings-overlay edits.
    pub config_dir: Option<PathBuf>,
    /// Parent dir of `config.geoip_db` (MaxMind City mmdb). Read-only.
    pub geoip_db_dir: Option<PathBuf>,
    /// Parent dir of `config.geoip_asn_db` (MaxMind ASN mmdb). Read-only.
    pub geoip_asn_db_dir: Option<PathBuf>,
    /// Current working directory at startup — PCAP exports and ad-hoc
    /// file dumps land here. Captured eagerly so post-startup `cd`
    /// inside a shell doesn't expand the allow-list.
    pub cwd: Option<PathBuf>,
}

impl SandboxPaths {
    /// Derive the sandbox path set from runtime config and dirs.
    ///
    /// All filesystem ops here are read-only (existence checks via
    /// `dirs::*` + `parent()`). No directories are created — the
    /// sandbox just needs to *permit* the directory if the app later
    /// chooses to write there. Missing dirs are silently skipped.
    pub fn from_config(cfg: &NetwatchConfig) -> Self {
        let cache_dir = dirs::cache_dir().map(|c| c.join("netwatch"));
        let config_dir = dirs::config_dir().map(|c| c.join("netwatch"));

        let geoip_db_dir = parent_dir_if_set(&cfg.geoip_db);
        let geoip_asn_db_dir = parent_dir_if_set(&cfg.geoip_asn_db);

        let cwd = std::env::current_dir().ok();

        Self {
            cache_dir,
            config_dir,
            geoip_db_dir,
            geoip_asn_db_dir,
            cwd,
        }
    }
}

fn parent_dir_if_set(path: &str) -> Option<PathBuf> {
    if path.is_empty() {
        return None;
    }
    let p = PathBuf::from(path);
    // `parent()` on a bare filename returns `Some("")`, which Landlock
    // rejects. Promote to `.` so the rule applies to CWD in that case.
    match p.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Some(parent.to_path_buf()),
        Some(_) => Some(PathBuf::from(".")),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_geoip_paths_resolve_to_none() {
        let mut cfg = NetwatchConfig::default();
        cfg.geoip_db = String::new();
        cfg.geoip_asn_db = String::new();
        let paths = SandboxPaths::from_config(&cfg);
        assert!(paths.geoip_db_dir.is_none());
        assert!(paths.geoip_asn_db_dir.is_none());
    }

    #[test]
    fn absolute_geoip_path_extracts_parent() {
        let mut cfg = NetwatchConfig::default();
        cfg.geoip_db = "/usr/share/GeoIP/GeoLite2-City.mmdb".to_string();
        let paths = SandboxPaths::from_config(&cfg);
        assert_eq!(
            paths.geoip_db_dir.as_deref(),
            Some(std::path::Path::new("/usr/share/GeoIP"))
        );
    }

    #[test]
    fn bare_filename_geoip_falls_back_to_cwd() {
        let mut cfg = NetwatchConfig::default();
        cfg.geoip_db = "city.mmdb".to_string();
        let paths = SandboxPaths::from_config(&cfg);
        assert_eq!(
            paths.geoip_db_dir.as_deref(),
            Some(std::path::Path::new("."))
        );
    }
}
