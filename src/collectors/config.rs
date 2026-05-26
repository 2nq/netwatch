use std::process::Command;

pub struct NetworkConfig {
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    #[allow(dead_code)]
    pub hostname: String,
}

impl NetworkConfig {
    /// DNS server to use for the Health widget probe.
    ///
    /// Skips IPv6 link-local addresses (`fe80::/10`) because they require a
    /// zone identifier (`%en0`) that `IpAddr::parse` rejects, so the ICMP
    /// probe can't actually reach them — leaving the widget stuck at 100%
    /// loss even when the host's *other* DNS server is healthy. macOS in
    /// particular surfaces an IPv6 RA-discovered link-local nameserver
    /// ahead of the routable IPv4 one in `/etc/resolv.conf`.
    pub fn primary_dns(&self) -> Option<String> {
        self.dns_servers
            .iter()
            .find(|s| !is_link_local(s))
            .or_else(|| self.dns_servers.first())
            .cloned()
    }
}

fn is_link_local(addr: &str) -> bool {
    let lower = addr.trim().to_ascii_lowercase();
    lower.starts_with("fe80:") || lower.starts_with("fe80::")
}

pub struct ConfigCollector {
    pub config: NetworkConfig,
}

impl Default for ConfigCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigCollector {
    pub fn new() -> Self {
        #[cfg(unix)]
        let hostname = nix::unistd::gethostname()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        #[cfg(windows)]
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        Self {
            config: NetworkConfig {
                gateway: None,
                dns_servers: Vec::new(),
                hostname,
            },
        }
    }

    pub fn update(&mut self) {
        self.config.gateway = collect_gateway();
        self.config.dns_servers = collect_dns();
    }
}

#[cfg(target_os = "macos")]
fn collect_gateway() -> Option<String> {
    let output = Command::new("netstat").args(["-rn"]).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 2 && cols[0] == "default" {
            return Some(cols[1].to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn collect_gateway() -> Option<String> {
    let output = Command::new("ip").args(["route"]).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.starts_with("default via ") {
            return line.split_whitespace().nth(2).map(|s| s.to_string());
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn collect_gateway() -> Option<String> {
    let output = Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Look for: 0.0.0.0  0.0.0.0  <gateway>  ...
        if cols.len() >= 3 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            return Some(cols[2].to_string());
        }
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn collect_gateway() -> Option<String> {
    None
}

fn collect_dns() -> Vec<String> {
    let mut servers = Vec::new();

    #[cfg(unix)]
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver ") {
                if let Some(addr) = trimmed.split_whitespace().nth(1) {
                    servers.push(addr.to_string());
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    if servers.is_empty() {
        if let Ok(output) = Command::new("scutil").args(["--dns"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver[") {
                    // Format: `nameserver[0] : 192.168.1.1` or
                    // `nameserver[0] : fe80::1%en0`. Splitting on every `:`
                    // shreds IPv6 — split once on the first `:` after the
                    // closing bracket instead.
                    if let Some(rest) = trimmed.split_once(':').map(|(_, v)| v) {
                        let addr = rest.trim().to_string();
                        if !addr.is_empty() && !servers.contains(&addr) {
                            servers.push(addr);
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    if servers.is_empty() {
        if let Ok(output) = Command::new("ipconfig").args(["/all"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("DNS Servers")
                    || (trimmed.starts_with("DNS") && trimmed.contains("Server"))
                {
                    if let Some(addr) = trimmed.split(':').last() {
                        let addr = addr.trim().to_string();
                        if !addr.is_empty() && !servers.contains(&addr) {
                            servers.push(addr);
                        }
                    }
                } else if !trimmed.is_empty()
                    && servers.len() > 0
                    && !trimmed.contains(':')
                    && trimmed
                        .chars()
                        .next()
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                {
                    // Continuation lines for additional DNS servers (indented IPs)
                    let addr = trimmed.to_string();
                    if !servers.contains(&addr) {
                        servers.push(addr);
                    }
                }
            }
        }
    }

    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dns: &[&str]) -> NetworkConfig {
        NetworkConfig {
            gateway: None,
            dns_servers: dns.iter().map(|s| s.to_string()).collect(),
            hostname: "test".into(),
        }
    }

    #[test]
    fn primary_dns_prefers_routable_over_ipv6_link_local() {
        // Issue #31: macOS lists the IPv6 RA-discovered link-local
        // nameserver first, but ICMP can't reach it without a zone ID,
        // so the Health widget sat at 100% loss. We must pick the
        // routable IPv4 fallback.
        let c = cfg(&["fe80::96ea:eaff:fe05:f074", "192.168.15.1"]);
        assert_eq!(c.primary_dns().as_deref(), Some("192.168.15.1"));
    }

    #[test]
    fn primary_dns_skips_link_local_with_zone_id() {
        let c = cfg(&["fe80::1%en0", "1.1.1.1"]);
        assert_eq!(c.primary_dns().as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn primary_dns_keeps_first_when_no_routable_option() {
        let c = cfg(&["fe80::1", "fe80::2"]);
        assert_eq!(c.primary_dns().as_deref(), Some("fe80::1"));
    }

    #[test]
    fn primary_dns_keeps_global_ipv6() {
        // 2001:: is global, not link-local — keep it.
        let c = cfg(&["2001:4860:4860::8888", "192.168.1.1"]);
        assert_eq!(c.primary_dns().as_deref(), Some("2001:4860:4860::8888"));
    }

    #[test]
    fn primary_dns_empty_returns_none() {
        let c = cfg(&[]);
        assert!(c.primary_dns().is_none());
    }

    #[test]
    fn primary_dns_single_routable() {
        let c = cfg(&["192.168.1.1"]);
        assert_eq!(c.primary_dns().as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn is_link_local_matches_fe80_prefix() {
        assert!(is_link_local("fe80::1"));
        assert!(is_link_local("fe80::96ea:eaff:fe05:f074"));
        assert!(is_link_local("fe80::1%en0"));
        assert!(is_link_local("FE80::1")); // case-insensitive
        assert!(!is_link_local("192.168.1.1"));
        assert!(!is_link_local("2001:4860:4860::8888"));
        assert!(!is_link_local("fec0::1")); // deprecated site-local, not link-local
    }
}
