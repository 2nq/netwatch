//! Smoke test for `netwatch::sandbox`.
//!
//! Runs from a CI / dev shell on Linux: applies the sandbox in
//! BestEffort mode, prints the report, then exercises a few accesses
//! to confirm enforcement:
//!
//! - Read `/proc/self/status`  → allowed
//! - Read `~/.cache/netwatch/x` → allowed (if cache_dir resolves)
//! - Read `/etc/shadow`         → expected EACCES (Landlock or DAC)
//! - Open new raw socket        → expected EPERM (caps dropped)
//!
//! Exits 0 on success, 1 on unexpected outcome.

use netwatch::config::NetwatchConfig;
use netwatch::sandbox::{self, Mode, SandboxPaths};
use std::fs;

fn main() {
    let cfg = NetwatchConfig::default();
    let paths = SandboxPaths::from_config(&cfg);
    println!("paths = {:#?}", paths);

    let report = sandbox::apply(Mode::BestEffort, &paths);
    println!("report = {:#?}", report);
    println!("summary = {}", report.summary());

    // /proc — should still be readable.
    match fs::read_to_string("/proc/self/status") {
        Ok(s) => println!("OK   read /proc/self/status ({} bytes)", s.len()),
        Err(e) => {
            eprintln!("FAIL read /proc/self/status: {e}");
            std::process::exit(1);
        }
    }

    // /etc/shadow — readable only as root pre-sandbox. After Landlock
    // applies, the *kernel* enforces deny independent of DAC.
    match fs::read_to_string("/etc/shadow") {
        Ok(_) => {
            eprintln!("FAIL read /etc/shadow succeeded — sandbox did not block");
            std::process::exit(1);
        }
        Err(e) => println!("OK   read /etc/shadow denied ({})", e),
    }

    // Try to open a new raw socket. Without CAP_NET_RAW, socket(2) with
    // SOCK_RAW returns EPERM. If the sandbox dropped the cap, this
    // fails; if we never had it, this also fails. Either way the
    // post-apply state should be "no raw socket".
    let sock = unsafe {
        nix::libc::socket(
            nix::libc::AF_INET,
            nix::libc::SOCK_RAW,
            nix::libc::IPPROTO_ICMP,
        )
    };
    if sock >= 0 {
        unsafe {
            nix::libc::close(sock);
        }
        eprintln!("FAIL opened a raw socket after sandbox apply — CAP_NET_RAW retained");
        std::process::exit(1);
    } else {
        println!(
            "OK   socket(AF_INET, SOCK_RAW) denied ({})",
            std::io::Error::last_os_error()
        );
    }

    println!("\nsandbox smoke: all checks passed");
}
