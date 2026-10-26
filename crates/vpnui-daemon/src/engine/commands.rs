use vpnui_proto::KillSwitchState;

use tracing::{debug, error, info, warn};
use vpnui_proto::{
    ConnectPhase, ErrorCode, Event, ServerId, SettingsPatch,
   TunnelState, 
};

use crate::engine::engine::{Engine, EngineError, Phase, Session};
use crate::platform::{Anchor, Mono, Now, Platform};
use crate::policy::{self};
use crate::state::{Undo};

impl<P: Platform> Engine<P> {
    pub(crate) fn connect(&mut self, id: &str) -> Result<(), EngineError> {
        if self.catalog.is_empty() {
            return Err(EngineError::new(
                ErrorCode::NoProfiles,
                "no profiles imported; run: sudo vpnuid import <files>",
            ));
        }
        let profile = self
            .catalog
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| {
                EngineError::new(ErrorCode::UnknownServer, format!("no profile {id}"))
            })?;
        if let Some(session) = &self.session
            && session.profile.id == id
            && matches!(
                session.phase,
                Phase::Connected | Phase::Handshaking { retry: None, .. }
            )
        {
            self.republish_tunnel();
            return Ok(());
        }
        self.p.wg_verify().map_err(|e| {
            EngineError::new(
                ErrorCode::BinaryUntrusted,
                format!("{}; install it with: sudo vpnuid install", e.detail),
            )
        })?;
        let route = self
            .p
            .default_route()?
            .ok_or_else(|| EngineError::new(ErrorCode::NoNetwork, "no default route"))?;
        self.retry_leftovers();
        let current = self.session.as_ref().map(|s| s.id);
        if self.st.journal.iter().any(|e| Some(e.session) != current) {
            return Err(EngineError::new(
                ErrorCode::Busy,
                "a previous tunnel is still being torn down; try again shortly",
            ));
        }

        let now = self.p.now();
        let id = self.next_session;
        self.next_session += 1;
        self.last_error = None;
        self.publish_tunnel_state(TunnelState::Connecting {
            server_id: ServerId::new(profile.id.clone()),
            phase: ConnectPhase::Resolving,
            started_at_ms: now.wall,
        });

        let endpoint = profile.endpoint();
        let first = self
            .journal(id, Undo::EndpointException { endpoint })
            .and_then(|_| self.reload());
        if let Err(e) = first {
            return Err(self.connect_failed(id, e));
        }
        if let Some(old) = self.session.take() {
            info!(from = %old.profile.id, to = %profile.id, "switching servers");
            if let Err(e) = self.undo_session(old.id) {
                return Err(self.connect_failed(id, e));
            }
        }
        let mut session = Session {
            id,
            profile,
            route,
            instance: None,
            phase: Phase::Connected,
            started_at: now.wall,
            since: None,
            last_handshake: None,
        };
        match self.bring_up(&mut session, None) {
            Ok(()) => {
                self.session = Some(session);
                Ok(())
            }
            Err(e) => Err(self.connect_failed(id, e)),
        }
    }

    pub(crate) fn connect_failed(&mut self, session: u64, error: EngineError) -> EngineError {
        warn!(
            code = error.code.as_str(),
            "connect failed: {}", error.message
        );
        if let Err(e) = self.undo_session(session) {
            error!(%e, "compensation incomplete; will retry");
        }
        self.last_error = Some(error.to_string());
        error
    }

    pub(crate) fn quick_connect(&mut self) -> Result<(), EngineError> {
        let target = self
            .st
            .recents
            .iter()
            .find(|id| self.catalog.iter().any(|p| &p.id == *id))
            .cloned()
            .or_else(|| {
                self.catalog
                    .iter()
                    .max_by_key(|p| (p.imported_at, p.id.clone()))
                    .map(|p| p.id.clone())
            })
            .ok_or_else(|| {
                EngineError::new(
                    ErrorCode::NoProfiles,
                    "no profiles imported; run: sudo vpnuid import <files>",
                )
            })?;
        self.connect(&target)
    }

    pub(crate) fn disconnect(&mut self) -> Result<(), EngineError> {
        let Some(session) = self.session.take() else {
            self.republish_tunnel();
            return Ok(());
        };
        self.publish_tunnel_state(TunnelState::Disconnecting);
        self.last_error = None;
        self.set_public_ip(None);
        self.undo_session(session.id)
    }

    pub(crate) fn set_kill_switch(&mut self, armed: bool) -> Result<(), EngineError> {
        if armed {
            if self.st.armed && self.kill_switch == KillSwitchState::Armed {
                self.republish_kill_switch();
                return Ok(());
            }
            self.st.armed = true;
            if let Err(e) = self.persist() {
                self.st.armed = false;
                return Err(e);
            }
            let result = self.reload();
            if let Err(e) = &result {
                self.set_ks_state(KillSwitchState::Error {
                    message: e.message.clone(),
                });
            }
            result
        } else {
            if !self.st.armed {
                self.republish_kill_switch();
                return Ok(());
            }
            self.st.armed = false;
            if let Err(e) = self.persist() {
                self.st.armed = true;
                return Err(e);
            }
            if let Err(e) = self.p.pf_flush(Anchor::KillSwitch) {
                self.st.armed = true;
                self.persist_best_effort();
                return Err(e.into());
            }
            self.last_loaded = None;
            self.release_token();
            self.set_ks_state(KillSwitchState::Off);
            Ok(())
        }
    }

    pub(crate) fn set_settings(&mut self, patch: SettingsPatch) -> Result<(), EngineError> {
        if patch.is_empty() {
            return Err(EngineError::new(
                ErrorCode::BadRequest,
                "set_settings needs at least one field",
            ));
        }
        let before = self.st.settings;
        let old_policy = self.policy();
        patch.apply(&mut self.st.settings);
        let new_policy = self.policy();
        // Tightening loads then persists; relaxing persists then loads. A partial failure leaves
        // the stricter setting in force.
        let result = if policy::policy::tightens(&old_policy, &new_policy) {
            match self.load(new_policy) {
                Ok(()) => match self.persist() {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        self.st.settings = before;
                        let _ = self.load(old_policy);
                        Err(e)
                    }
                },
                Err(e) => {
                    self.st.settings = before;
                    Err(e)
                }
            }
        } else {
            match self.persist() {
                Ok(()) if new_policy != old_policy => self.load(new_policy),
                Ok(()) => Ok(()),
                Err(e) => {
                    self.st.settings = before;
                    Err(e)
                }
            }
        };
        self.shared.publish(Event::SettingsChanged {
            settings: self.st.settings,
        });
        result
    }

    pub(crate) fn reload_profiles(&mut self) -> Result<(), EngineError> {
        self.catalog = self.p.load_profiles()?;
        self.publish_servers();
        Ok(())
    }
}
