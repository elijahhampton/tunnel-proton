use vpnui_proto::KillSwitchState;

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};
use vpnui_proto::{
    ConnectPhase, ErrorBody, ErrorCode, Event, IpInfo, Server, ServerId, Settings,
    SettingsPatch, Stats, TunnelState, UnixMillis,
};

use crate::country;
use crate::engine::engine::{Action, DEFAULT_TUNNEL_MTU, Engine, EngineError, EngineOptions, Input, Phase, Retry, SOFT_ATTEMPTS, Session, TUNNEL_OVERHEAD, backoff, millis, same_ignoring_handshake, server_of, tunnel_routes};
use crate::net::net::{DefaultRoute, IpNet, split_default_routes};
use crate::platform::{Anchor, Mono, Now, Platform, PlatformError, WgInstance};
use crate::policy::policy::{self, Policy};
use crate::profile::profile::Profile;
use crate::shared::Shared;
use crate::state::{JournalEntry, PersistedState, Undo};
use crate::uapi::uapi::DeviceConfig;

impl<P: Platform> fmt::Debug for Engine<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("state", &self.st)
            .field("kill_switch", &self.kill_switch)
            .field("session", &self.session)
            .field("catalog", &self.catalog)
            .field("last_error", &self.last_error)
            .finish_non_exhaustive()
    }
}

impl<P: Platform> Engine<P> {
    pub(crate) fn platform(&self) -> &P {
        &self.p
    }

    pub(crate) fn persisted(&self) -> &PersistedState {
        &self.st
    }

    pub(crate) fn kill_switch(&self) -> &KillSwitchState {
        &self.kill_switch
    }

        pub(crate) fn has_leftovers(&self) -> bool {
        !self.st.journal.is_empty()
    }

       pub(crate) fn tunnel_of(s: &Session) -> TunnelState {
        let server_id = ServerId::new(s.profile.id.clone());
        match &s.phase {
            Phase::Handshaking { retry: None, .. } => TunnelState::Connecting {
                server_id,
                phase: ConnectPhase::Handshaking,
                started_at_ms: s.started_at,
            },
            Phase::Handshaking {
                retry: Some(retry), ..
            }
            | Phase::Soft { retry, .. }
            | Phase::Offline { retry } => TunnelState::Reconnecting {
                server_id,
                attempt: retry.attempt,
                retry_at_ms: None,
                reason: retry.reason.clone(),
            },
            Phase::Waiting { retry, at_wall, .. } => TunnelState::Reconnecting {
                server_id,
                attempt: retry.attempt,
                retry_at_ms: Some(*at_wall),
                reason: retry.reason.clone(),
            },
            Phase::Connected => TunnelState::Connected {
                server_id,
                since_ms: s.since.unwrap_or(s.started_at),
                endpoint: s.profile.endpoint().to_string(),
                last_handshake_ms: s.last_handshake,
            },
        }
    }


        pub(crate) fn reported_tunnel(&self) -> TunnelState {
        match &self.session {
            Some(s) => Self::tunnel_of(s),
            None if self.has_leftovers() => TunnelState::Disconnecting,
            None => TunnelState::Disconnected {
                last_error: self.last_error.clone(),
            },
        }
    }

    pub(crate) fn tunnel(&self) -> TunnelState {
        self.reported_tunnel()
    }

    /// The profile of the current session, if any.
    pub(crate) fn session_profile(&self) -> Option<&str> {
        self.session.as_ref().map(|s| s.profile.id.as_str())
    }

    pub(crate) fn tick_interval(&self) -> Duration {
        match self.session.as_ref().map(|s| &s.phase) {
            Some(Phase::Handshaking { .. } | Phase::Soft { .. }) => Duration::from_millis(250),
            Some(Phase::Connected | Phase::Waiting { .. } | Phase::Offline { .. }) => {
                Duration::from_secs(1)
            }
            None if !self.st.journal.is_empty() => Duration::from_secs(1),
            None => Duration::from_secs(5),
        }
    }

    pub(crate) fn bind_socket(&self) -> crate::platform::PResult<std::os::unix::net::UnixListener> {
        self.p.bind_socket()
    }

        pub(crate) fn set_public_ip(&mut self, ip: Option<IpAddr>) {
        let connected = self
            .session
            .as_ref()
            .is_some_and(|s| matches!(s.phase, Phase::Connected));
        let info = ip.filter(|_| connected).map(|ip| IpInfo {
            ip,
            city: String::new(),
            country: String::new(),
            lat: None,
            lon: None,
        });
        if self.public_ip != info {
            self.public_ip = info.clone();
            self.shared
                .publish(Event::PublicIpChanged { public_ip: info });
        }
    }

        pub(crate) fn publish_tunnel_state(&mut self, state: TunnelState) {
        if !matches!(state, TunnelState::Connected { .. }) {
            self.set_public_ip(None);
        }
        self.published_tunnel = Some(state.clone());
        self.shared.publish(Event::TunnelChanged { tunnel: state });
    }

    pub(crate) fn republish_tunnel(&mut self) {
        let state = self.reported_tunnel();
        self.publish_tunnel_state(state);
    }

        /// Publishes the tunnel state if it changed. Handshake times alone do not count; they travel
    /// in `stats`.
    pub(crate) fn sync_tunnel(&mut self) {
        let state = self.reported_tunnel();
        let same = self
            .published_tunnel
            .as_ref()
            .is_some_and(|old| same_ignoring_handshake(old, &state));
        if !same {
            self.publish_tunnel_state(state);
        }
    }

    /// Runs one command to completion and returns its result.
    pub(crate) fn command(&mut self, action: Action) -> Result<(), EngineError> {
        let result = match action {
            Action::Connect(id) => self.connect(&id),
            Action::QuickConnect => self.quick_connect(),
            Action::Disconnect => self.disconnect(),
            Action::SetKillSwitch(armed) => self.set_kill_switch(armed),
            Action::SetSettings(patch) => self.set_settings(patch),
            Action::ReloadProfiles => self.reload_profiles(),
        };
        self.sync_tunnel();
        if let Err(e) = &result {
            info!(code = e.code.as_str(), "command failed: {}", e.message);
        }
        result
    }

    pub(crate) fn handle(&mut self, input: Input) {
        match input {
            Input::Command { action, reply } => {
                let result = self.command(action).map_err(|e| e.body());
                if let Some(reply) = reply {
                    let _ = reply.send(result);
                }
            }
            Input::Tick => self.tick(),
            Input::PublicIp(ip) => self.set_public_ip(ip),
            Input::Stop { graceful, done } => {
                if graceful {
                    self.shutdown();
                }
                if let Some(done) = done {
                    let _ = done.send(());
                }
            }
        }
    }

        /// Undoes a session's entries newest first, stopping at the first failure so the remaining
    /// teardown order is preserved for the retry.
    pub(crate) fn undo_where(&mut self, session: u64, keep: impl Fn(&Undo) -> bool) -> Result<(), EngineError> {
        let mut entries: Vec<JournalEntry> = self
            .st
            .journal
            .iter()
            .filter(|e| e.session == session && !keep(&e.undo))
            .cloned()
            .collect();
        entries.sort_by_key(|e| e.seq);
        for entry in entries.into_iter().rev() {
            self.run_undo(&entry)?;
            self.forget(entry.seq);
        }
        Ok(())
    }


    pub(crate) fn undo_session(&mut self, session: u64) -> Result<(), EngineError> {
        self.undo_where(session, |_| false)
    }


    /// Disconnects completely but leaves an armed policy in place.
    pub(crate) fn shutdown(&mut self) {
        if let Some(session) = self.session.take() {
            info!("shutting down: tearing the tunnel down");
            self.publish_tunnel_state(TunnelState::Disconnecting);
            if let Err(e) = self.undo_session(session.id) {
                error!(%e, "teardown incomplete; recovery will finish it");
            }
        }
        self.sync_tunnel();
    }

    pub(crate) fn arm_at_startup(&mut self) {
        let baseline = self.policy();
        let result = (|| -> Result<(), EngineError> {
            self.p
                .pf_load(Anchor::KillSwitch, &policy::render(&baseline))?;
            self.last_loaded = Some(baseline.clone());
            let previous = self.st.pf_token.take();
            let was_enabled = self.p.pf_is_enabled().unwrap_or(true);
            let token = self.p.pf_enable()?;
            if let Some(old) = previous {
                let _ = self.p.pf_release(&old);
            } else {
                self.st.pf_enabled_by_us = !was_enabled;
            }
            self.st.pf_token = Some(token);
            self.persist_best_effort();
            self.p.pf_flush_states()?;
            Ok(())
        })();
        self.kill_switch = match result {
            Ok(()) => KillSwitchState::Armed,
            Err(e) => {
                error!(%e, "could not restore the kill switch at startup");
                KillSwitchState::Error { message: e.message }
            }
        };
    }

    /// Undoes every journal entry, newest first. Best effort: failures stay journaled.
    pub(crate) fn recover(&mut self) {
        if self.st.journal.is_empty() {
            return;
        }
        warn!(
            entries = self.st.journal.len(),
            "recovering from an unclean shutdown"
        );
        let mut entries = self.st.journal.clone();
        entries.sort_by_key(|e| e.seq);
        for entry in entries.into_iter().rev() {
            match self.run_undo(&entry) {
                Ok(()) => self.forget(entry.seq),
                Err(e) => error!(%e, kind = ?entry.undo, "recovery step failed"),
            }
        }
    }

    /// The policy the journal currently implies. During recovery exceptions are ignored, so
    /// every reload during recovery is the baseline.
    pub(crate) fn policy(&self) -> Policy {
        self.policy_excluding(None)
    }

    pub(crate) fn policy_excluding(&self, seq: Option<u64>) -> Policy {
        let mut endpoints = BTreeSet::new();
        let mut tunnel_if = None;
        if !self.recovering {
            for entry in self.st.journal.iter().filter(|e| Some(e.seq) != seq) {
                match &entry.undo {
                    Undo::EndpointException { endpoint } => {
                        endpoints.insert(*endpoint);
                    }
                    Undo::TunnelException { ifname } => tunnel_if = Some(ifname.clone()),
                    Undo::WireGuard { .. }
                    | Undo::HostRoute { .. }
                    | Undo::NetRoute { .. }
                    | Undo::Dns => {}
                }
            }
        }
        Policy {
            armed: self.st.armed,
            allow_lan: self.st.settings.allow_lan,
            block_ipv6: self.st.settings.block_ipv6,
            endpoints,
            tunnel_if,
        }
    }

    pub(crate) fn load(&mut self, policy: Policy) -> Result<(), EngineError> {
        if !policy.armed {
            return Ok(());
        }
        let tighter = policy::tightens(
            self.last_loaded.as_ref().unwrap_or(&Policy::default()),
            &policy,
        );
        let result = self
            .p
            .pf_load(Anchor::KillSwitch, &policy::render(&policy))
            .map_err(EngineError::from)
            .and_then(|()| {
                self.last_loaded = Some(policy);
                self.ensure_pf_enabled()
            });
        match result {
            Ok(()) => {
                if tighter {
                    self.p.pf_flush_states()?;
                }
                if self.kill_switch != KillSwitchState::Armed {
                    self.set_ks_state(KillSwitchState::Armed);
                }
                Ok(())
            }
            Err(e) => {
                self.set_ks_state(KillSwitchState::Error {
                    message: e.message.clone(),
                });
                Err(e)
            }
        }
    }

    pub(crate) fn reload(&mut self) -> Result<(), EngineError> {
        let policy = self.policy();
        self.load(policy)
    }

    /// Set the Kill Switch state.
    pub(crate) fn set_ks_state(&mut self, state: KillSwitchState) {
        if self.kill_switch != state {
            self.kill_switch = state.clone();
            self.shared
                .publish(Event::KillSwitchChanged { kill_switch: state });
        }
    }

    /// Ensure PFCtl is enabled.
    pub(crate) fn ensure_pf_enabled(&mut self) -> Result<(), EngineError> {
        if self.st.pf_token.is_some() {
            return Ok(());
        }
        let was_enabled = self.p.pf_is_enabled()?;
        let token = self.p.pf_enable()?;
        self.st.pf_token = Some(token);
        self.st.pf_enabled_by_us = !was_enabled;
        self.persist()
    }

    pub(crate) fn release_token(&mut self) {
        if let Some(token) = self.st.pf_token.take() {
            if let Err(e) = self.p.pf_release(&token) {
                warn!(%e, "could not release the pf token");
            }
            self.st.pf_enabled_by_us = false;
            self.persist_best_effort();
        }
    }

    pub(crate) fn persist(&mut self) -> Result<(), EngineError> {
        let json = serde_json::to_string_pretty(&self.st)
            .map_err(|e| EngineError::new(ErrorCode::Internal, e.to_string()))?;
        self.p.save_state(&json).map_err(EngineError::from)
    }

    pub(crate) fn persist_best_effort(&mut self) {
        if let Err(e) = self.persist() {
            error!(%e, "could not save state");
        }
    }

    /// Appends an undo entry and makes it durable before the mutation it describes.
    pub(crate) fn journal(&mut self, session: u64, undo: Undo) -> Result<u64, EngineError> {
        let seq = self.st.next_seq;
        self.st.next_seq += 1;
        self.st.journal.push(JournalEntry { seq, session, undo });
        if let Err(e) = self.persist() {
            self.st.journal.retain(|e| e.seq != seq);
            return Err(e);
        }
        Ok(seq)
    }

    pub(crate) fn forget(&mut self, seq: u64) {
        self.st.journal.retain(|e| e.seq != seq);
        self.persist_best_effort();
    }

    pub(crate) fn run_undo(&mut self, entry: &JournalEntry) -> Result<(), EngineError> {
        debug!(kind = ?entry.undo, "undo");
        match &entry.undo {
            Undo::Dns => self.p.dns_clear()?,
            Undo::NetRoute { net, ifname } => self.p.route_delete_net(*net, ifname)?,
            Undo::HostRoute { dest } => self.p.route_delete_host(*dest)?,
            Undo::TunnelException { .. } | Undo::EndpointException { .. } => {
                let policy = self.policy_excluding(Some(entry.seq));
                self.load(policy)?;
            }
            Undo::WireGuard { ifname } => self.p.wg_stop(ifname.as_ref())?,
        }
        Ok(())
    }

    /// Tears down everything except the endpoint exception, for a hard reconnect.
    pub(crate) fn undo_keep_endpoint(&mut self, session: u64) -> Result<(), EngineError> {
        self.undo_where(session, |u| matches!(u, Undo::EndpointException { .. }))
    }

    pub(crate) fn retry_leftovers(&mut self) {
        let current = self.session.as_ref().map(|s| s.id);
        let mut sessions: Vec<u64> = self
            .st
            .journal
            .iter()
            .map(|e| e.session)
            .filter(|s| Some(*s) != current)
            .collect();
        sessions.sort_unstable();
        sessions.dedup();
        for session in sessions {
            if let Err(e) = self.undo_session(session) {
                warn!(%e, "teardown still incomplete");
                return;
            }
        }
    }

    pub(crate) fn tick(&mut self) {
        let now = self.p.now();
        // The monotonic clock stops during sleep, so wall time beyond it is time spent asleep.
        let woke = self.last_tick.is_some_and(|t| {
            let wall = now.wall.since(t.wall);
            let awake = Duration::from_millis(now.mono.0.saturating_sub(t.mono.0));
            wall.saturating_sub(awake) > self.opts.wake_gap
        });
        if woke {
            info!("wall clock jumped; treating it as a wake-up");
        }
        self.last_tick = Some(now);

        if let Some(mut session) = self.session.take() {
            if self.tick_session(&mut session, now, woke) {
                self.session = Some(session);
            } else {
                self.set_public_ip(None);
            }
        }
        if !self.st.journal.is_empty() {
            self.retry_leftovers();
        }
        self.sync_tunnel();
    }

    /// Returns false when the session ended.
    pub(crate) fn tick_session(&mut self, s: &mut Session, now: Now, woke: bool) -> bool {
        match s.phase.clone() {
            Phase::Handshaking { deadline, retry } => {
                let Some(instance) = s.instance.clone() else {
                    return self.attempt_failed(
                        s,
                        retry,
                        EngineError::new(ErrorCode::WgFailed, "no tunnel instance"),
                    );
                };
                if !self.p.wg_alive(&instance).unwrap_or(false) {
                    return self.attempt_failed(
                        s,
                        retry,
                        EngineError::new(ErrorCode::WgFailed, "wireguard-go exited"),
                    );
                }
                let handshake = self
                    .p
                    .uapi_status(&instance.ifname)
                    .ok()
                    .and_then(|st| st.last_handshake);
                if let Some(at) = handshake {
                    s.last_handshake = Some(at);
                    return match self.finish_up(s) {
                        Ok(()) => true,
                        Err(e) => self.attempt_failed(s, retry, e),
                    };
                }
                if now.mono >= deadline {
                    let secs = self.opts.handshake_timeout.as_secs();
                    return self.attempt_failed(
                        s,
                        retry,
                        EngineError::new(
                            ErrorCode::HandshakeTimeout,
                            format!("no handshake from the server within {secs}s"),
                        ),
                    );
                }
                true
            }
            Phase::Connected => self.tick_connected(s, now, woke),
            Phase::Waiting { retry, at, .. } => {
                if matches!(self.p.default_route(), Ok(None)) {
                    self.go_offline(s);
                } else if now.mono >= at {
                    self.attempt(s, retry, now);
                }
                true
            }
            Phase::Soft {
                retry,
                deadline,
                forced_at,
            } => {
                if matches!(self.p.default_route(), Ok(None)) {
                    self.go_offline(s);
                    return true;
                }
                let status = s
                    .instance
                    .as_ref()
                    .and_then(|i| self.p.uapi_status(&i.ifname).ok());
                if let Some(at) = status.and_then(|st| st.last_handshake)
                    && at >= forced_at
                {
                    s.last_handshake = Some(at);
                    s.phase = Phase::Connected;
                    info!(attempt = retry.attempt, "reconnected");
                    self.publish_tunnel_state(Self::tunnel_of(s));
                } else if now.mono >= deadline {
                    self.schedule_next(s, retry, now);
                }
                true
            }
            Phase::Offline { retry } => {
                if let Ok(Some(_)) = self.p.default_route() {
                    info!("network is back");
                    let retry = Retry {
                        attempt: 1,
                        reason: retry.reason,
                    };
                    self.attempt(s, retry, now);
                }
                true
            }
        }
    }

    pub(crate) fn tick_connected(&mut self, s: &mut Session, now: Now, woke: bool) -> bool {
        match self.p.default_route() {
            Ok(None) => {
                self.go_offline(s);
                return true;
            }
            Ok(Some(route)) => {
                if route != s.route || woke {
                    info!(gateway = %route.gateway, interface = %route.interface, "network changed; re-pinning the endpoint route");
                    if let Err(e) = self.repin(s, route).and_then(|()| self.refresh(s)) {
                        warn!(%e, "re-pinning failed; will retry");
                    }
                }
            }
            Err(e) => debug!(%e, "default route lookup failed"),
        }
        let Some(instance) = s.instance.clone() else {
            return self.lost(s, now, ErrorCode::WgFailed, "no tunnel instance", true);
        };
        if !self.p.wg_alive(&instance).unwrap_or(false) {
            return self.lost(s, now, ErrorCode::WgFailed, "wireguard-go exited", true);
        }
        if !self.p.interface_exists(&instance.ifname).unwrap_or(true) {
            return self.lost(
                s,
                now,
                ErrorCode::WgFailed,
                "tunnel interface disappeared",
                true,
            );
        }
        if let Ok(status) = self.p.uapi_status(&instance.ifname) {
            if status.last_handshake.is_some() {
                s.last_handshake = status.last_handshake;
            }
            self.shared.publish(Event::Stats(Stats {
                rx_bytes: status.rx_bytes,
                tx_bytes: status.tx_bytes,
                last_handshake_ms: s.last_handshake,
            }));
        }
        let stale = s
            .last_handshake
            .is_none_or(|at| now.wall.since(at) >= self.opts.reject_after);
        if stale {
            let secs = self.opts.reject_after.as_secs();
            let reason = format!("no handshake for {secs}s");
            return self.lost(s, now, ErrorCode::HandshakeTimeout, &reason, false);
        }
        true
    }

    /// Leaves Connected. Returns false if the session ended.
    pub(crate) fn lost(
        &mut self,
        s: &mut Session,
        now: Now,
        code: ErrorCode,
        reason: &str,
        hard: bool,
    ) -> bool {
        warn!(code = code.as_str(), reason, "tunnel lost");
        self.set_public_ip(None);
        if !self.st.settings.auto_reconnect {
            self.publish_tunnel_state(TunnelState::Disconnecting);
            if let Err(e) = self.undo_session(s.id) {
                error!(%e, "teardown incomplete; will retry");
            }
            self.last_error = Some(EngineError::new(code, reason).to_string());
            return false;
        }
        if hard {
            if let Err(e) = self.undo_keep_endpoint(s.id) {
                error!(%e, "teardown incomplete; will retry");
            }
            s.instance = None;
        }
        let retry = Retry {
            attempt: 0,
            reason: reason.to_owned(),
        };
        self.schedule_next(s, retry, now);
        true
    }

    pub(crate) fn schedule_next(&mut self, s: &mut Session, mut retry: Retry, now: Now) {
        retry.attempt = retry.attempt.saturating_add(1);
        let delay = backoff(retry.attempt);
        s.phase = Phase::Waiting {
            at: now.mono.plus_ms(millis(delay)),
            at_wall: now.wall.plus(delay),
            retry,
        };
        self.publish_tunnel_state(Self::tunnel_of(s));
    }

    pub(crate) fn go_offline(&mut self, s: &mut Session) {
        if matches!(s.phase, Phase::Offline { .. }) {
            return;
        }
        warn!("no default route; waiting for the network");
        s.phase = Phase::Offline {
            retry: Retry {
                attempt: 1,
                reason: "network offline".to_owned(),
            },
        };
        self.set_public_ip(None);
        self.publish_tunnel_state(Self::tunnel_of(s));
    }

    /// Runs reconnect attempt `retry.attempt`: soft for the first few while wireguard-go is
    /// healthy, otherwise a full teardown and bring-up.
    pub(crate) fn attempt(&mut self, s: &mut Session, retry: Retry, now: Now) {
        let route = match self.p.default_route() {
            Ok(Some(route)) => route,
            Ok(None) => {
                self.go_offline(s);
                return;
            }
            Err(e) => {
                warn!(%e, "default route lookup failed");
                self.schedule_next(s, retry, now);
                return;
            }
        };
        let healthy = s.instance.as_ref().is_some_and(|i| {
            self.p.wg_alive(i).unwrap_or(false)
                && self.p.interface_exists(&i.ifname).unwrap_or(false)
        });
        if retry.attempt <= SOFT_ATTEMPTS && healthy {
            info!(attempt = retry.attempt, "soft reconnect");
            let forced_at = self.p.now().wall;
            if let Err(e) = self.repin(s, route).and_then(|()| self.refresh(s)) {
                warn!(%e, "soft reconnect failed");
                self.schedule_next(s, retry, now);
                return;
            }
            s.phase = Phase::Soft {
                deadline: now.mono.plus_ms(millis(self.opts.soft_window)),
                forced_at,
                retry,
            };
            self.publish_tunnel_state(Self::tunnel_of(s));
            return;
        }
        info!(attempt = retry.attempt, "hard reconnect");
        if let Err(e) = self.undo_keep_endpoint(s.id) {
            warn!(%e, "teardown before reconnect failed");
            self.schedule_next(s, retry, now);
            return;
        }
        s.instance = None;
        s.route = route;
        if let Err(e) = self.bring_up(s, Some(retry.clone())) {
            warn!(
                code = e.code.as_str(),
                "hard reconnect failed: {}", e.message
            );
            if let Err(e) = self.undo_keep_endpoint(s.id) {
                error!(%e, "compensation incomplete; will retry");
            }
            s.instance = None;
            self.schedule_next(s, retry, now);
        }
    }

    /// Returns false if the session ended.
    pub(crate) fn attempt_failed(
        &mut self,
        s: &mut Session,
        retry: Option<Retry>,
        error: EngineError,
    ) -> bool {
        match retry {
            None => {
                self.connect_failed(s.id, error);
                false
            }
            Some(retry) => {
                warn!(
                    code = error.code.as_str(),
                    "reconnect attempt failed: {}", error.message
                );
                if let Err(e) = self.undo_keep_endpoint(s.id) {
                    error!(%e, "compensation incomplete; will retry");
                }
                s.instance = None;
                let now = self.p.now();
                self.schedule_next(s, retry, now);
                true
            }
        }
    }

    /// Points the endpoint host route at `route`'s gateway.
    pub(crate) fn repin(&mut self, s: &mut Session, route: DefaultRoute) -> Result<(), EngineError> {
        let dest = s.profile.endpoint().ip();
        let journaled = self
            .st
            .journal
            .iter()
            .any(|e| e.session == s.id && e.undo == Undo::HostRoute { dest });
        if !journaled {
            self.journal(s.id, Undo::HostRoute { dest })?;
        }
        self.p.route_delete_host(dest)?;
        self.p.route_add_host(dest, route.gateway)?;
        s.route = route;
        Ok(())
    }

    pub(crate) fn refresh(&mut self, s: &Session) -> Result<(), EngineError> {
        let Some(instance) = &s.instance else {
            return Ok(());
        };
        let keepalive = match s.profile.peer.persistent_keepalive {
            Some(k) if k > 0 => k,
            Some(_) | None => self.opts.keepalive,
        };
        self.p.uapi_refresh(
            &instance.ifname,
            &s.profile.peer.public_key,
            s.profile.endpoint(),
            keepalive,
        )?;
        Ok(())
    }

 






    pub(crate) fn republish_kill_switch(&mut self) {
        self.shared.publish(Event::KillSwitchChanged {
            kill_switch: self.kill_switch.clone(),
        });
    }



    pub(crate) fn publish_servers(&mut self) {
        let servers: Vec<Server> = self.catalog.iter().map(server_of).collect();
        self.shared.publish(Event::ServersUpdated { servers });
    }

    pub(crate) fn publish_snapshot(&mut self) {
        let tunnel = self.reported_tunnel();
        self.published_tunnel = Some(tunnel.clone());
        let snapshot = vpnui_proto::Snapshot {
            protocol_version: vpnui_proto::PROTOCOL_VERSION,
            tunnel,
            kill_switch: self.kill_switch.clone(),
            settings: self.st.settings,
            servers: self.catalog.iter().map(server_of).collect(),
            recents: self.st.recents.iter().cloned().map(ServerId::new).collect(),
            public_ip: None,
            profiles_count: u32::try_from(self.catalog.len()).unwrap_or(u32::MAX),
        };
        self.shared.publish(Event::Snapshot(Box::new(snapshot)));
    }

    pub(crate) fn settings(&self) -> Settings {
        self.st.settings
    }
}