//! Restores a clean network without the daemon: best effort, idempotent, and every step is
//! reported. Works with no network.

use vpnui_proto::Settings;

use crate::platform::{Anchor, Platform};
use crate::state::{PersistedState, Undo};

/// Runs every rescue step and returns one line per action taken.
pub fn rescue<P: Platform>(p: &P) -> Vec<String> {
    let mut log = Vec::new();
    let mut step = |text: String| {
        log.push(text);
    };

    match p.service_bootout() {
        Ok(true) => step("stopped the launchd service".into()),
        Ok(false) => step("launchd service not running".into()),
        Err(e) => step(format!("could not stop the launchd service: {e}")),
    }

    let state: Option<PersistedState> = p
        .load_state()
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str(&json).ok());
    let journal = state
        .as_ref()
        .map(|s| s.journal.clone())
        .unwrap_or_default();

    let mut ifnames: Vec<_> = journal
        .iter()
        .filter_map(|e| match &e.undo {
            Undo::WireGuard { ifname } => ifname.clone(),
            Undo::EndpointException { .. }
            | Undo::TunnelException { .. }
            | Undo::HostRoute { .. }
            | Undo::NetRoute { .. }
            | Undo::Dns => None,
        })
        .collect();
    ifnames.dedup();
    let stopped = if ifnames.is_empty() {
        p.wg_stop(None)
    } else {
        ifnames.iter().try_for_each(|i| p.wg_stop(Some(i)))
    };
    match stopped {
        Ok(()) => step("stopped wireguard-go (if it was ours and running)".into()),
        Err(e) => step(format!("could not stop wireguard-go: {e}")),
    }

    for entry in journal.iter().rev() {
        let result = match &entry.undo {
            Undo::NetRoute { net, ifname } => Some((
                format!("removed route {net} via {ifname}"),
                p.route_delete_net(*net, ifname),
            )),
            Undo::HostRoute { dest } => Some((
                format!("removed host route to {dest}"),
                p.route_delete_host(*dest),
            )),
            Undo::EndpointException { .. }
            | Undo::TunnelException { .. }
            | Undo::WireGuard { .. }
            | Undo::Dns => None,
        };
        if let Some((text, outcome)) = result {
            match outcome {
                Ok(()) => step(text),
                Err(e) => step(format!("{text} failed: {e}")),
            }
        }
    }

    match p.dns_clear() {
        Ok(()) => step("removed the DNS override".into()),
        Err(e) => step(format!("could not remove the DNS override: {e}")),
    }
    for anchor in [Anchor::KillSwitch, Anchor::SelfTest] {
        match p.pf_flush(anchor) {
            Ok(()) => step(format!("flushed pf anchor {}", anchor.name())),
            Err(e) => step(format!("could not flush pf anchor {}: {e}", anchor.name())),
        }
    }

    let token = state.as_ref().and_then(|s| s.pf_token.clone());
    let enabled_by_us = state.as_ref().is_some_and(|s| s.pf_enabled_by_us);
    match token {
        Some(token) => match p.pf_release(&token) {
            Ok(()) => step("released the pf enable token".into()),
            Err(e) => step(format!("could not release the pf token: {e}")),
        },
        None if enabled_by_us => match p.pf_disable() {
            Ok(()) => step("disabled pf (vpnuid had enabled it)".into()),
            Err(e) => step(format!("could not disable pf: {e}")),
        },
        None => step("no pf token held".into()),
    }

    let settings: Settings = state
        .as_ref()
        .map_or_else(crate::state::default_settings, |s| s.settings);
    let cleaned = PersistedState {
        armed: false,
        settings,
        recents: state
            .as_ref()
            .map(|s| s.recents.clone())
            .unwrap_or_default(),
        last_profile: state.as_ref().and_then(|s| s.last_profile.clone()),
        ..PersistedState::default()
    };
    let saved = serde_json::to_string_pretty(&cleaned)
        .map_err(|e| e.to_string())
        .and_then(|json| p.save_state(&json).map_err(|e| e.to_string()));
    match saved {
        Ok(()) => step("set the kill switch to disarmed and cleared the journal".into()),
        Err(e) => step(format!("could not update the state file: {e}")),
    }
    match p.remove_socket() {
        Ok(()) => step("removed the control socket".into()),
        Err(e) => step(format!("could not remove the control socket: {e}")),
    }
    log
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::engine::{Action, Engine, EngineOptions, Input};
    use crate::fake::fake::FakePlatform;
    use crate::shared::Shared;

    #[test]
    fn rescue_on_a_clean_machine_is_a_harmless_no_op() {
        let fake = FakePlatform::new();
        let log = rescue(&fake);
        assert!(log.iter().any(|l| l.contains("not running")));
        {
            let st = fake.state();
            assert!(st.tunnel_is_clean() && st.anchors.is_empty() && !st.pf_enabled());
        }
        let again = rescue(&fake);
        assert_eq!(log.len(), again.len(), "idempotent");
    }

    #[test]
    fn rescue_cleans_up_after_a_crash_while_armed_and_connected() {
        let profiles = vec![crate::testkeys::profile(1, "CO#4", "203.0.113.40:51820", 1)];
        let fake = FakePlatform::new().with_profiles(profiles.clone());
        let mut engine = Engine::start(fake.clone(), Shared::new(), EngineOptions::default());
        engine.command(Action::SetKillSwitch(true)).unwrap();
        engine
            .command(Action::Connect(profiles[0].id.clone()))
            .unwrap();
        fake.advance(250);
        engine.handle(Input::Tick);
        assert!(!fake.state().net_routes.is_empty());
        drop(engine);
        fake.state().service_loaded = true;

        let log = rescue(&fake);
        let st = fake.state();
        assert!(st.tunnel_is_clean(), "{log:#?}");
        assert!(st.anchors.is_empty());
        assert!(st.tokens.is_empty() && !st.pf_enabled());
        assert!(!st.service_loaded);
        let saved: PersistedState =
            serde_json::from_str(st.state_file.as_deref().unwrap_or("{}")).unwrap();
        assert!(!saved.armed && saved.journal.is_empty());
        drop(st);

        let restarted = Engine::start(fake.clone(), Shared::new(), EngineOptions::default());
        assert_eq!(restarted.kill_switch(), &vpnui_proto::KillSwitchState::Off);
    }
}
