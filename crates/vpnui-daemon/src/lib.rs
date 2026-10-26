//! `vpnuid`: the privileged daemon that owns the WireGuard tunnel, routes, DNS, and the pf kill
//! switch. Everything privileged goes through [`platform::Platform`]; the engine and all policy
//! logic are plain code testable against [`fake::FakePlatform`].

#![forbid(unsafe_code)]

pub mod country;
pub mod daemon;
pub mod doctor;
pub mod engine;
pub mod exec;
pub mod fake;
pub mod install;
pub mod macos;
pub mod net;
pub mod platform;
pub mod policy;
pub mod profile;
pub mod rescue;
pub mod secret;
pub mod server;
pub mod shared;
pub mod state;
pub mod store;
pub mod testkeys;
pub mod trust;
pub mod uapi;
