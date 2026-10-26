//! Unprivileged terminal client for the vpnui daemon. Holds no credentials and never touches the
//! network stack; every protection-relevant change is a request to the daemon.

#![forbid(unsafe_code)]

pub mod app;
pub mod browser;
pub mod errors;
pub mod format;
pub mod layout;
pub mod link;
pub mod runtime;
pub mod terminal;
pub mod theme;
pub mod view;
