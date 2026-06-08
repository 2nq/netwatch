pub mod app;
pub mod clipboard;
pub mod collectors;
pub mod config;
pub mod dpi;
pub mod ebpf;
pub mod event;
pub mod graph;
pub mod logging;
pub mod metrics;
pub mod platform;
pub mod remote;
pub mod sandbox;
pub mod sort;
pub mod state;
pub mod theme;
pub mod ui;

/// A simple hello world function that returns a greeting message.
pub fn hello_world() -> String {
    "Hello, World!".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world() {
        assert_eq!(hello_world(), "Hello, World!");
    }
}
