use vpnui_proto::KillSwitchState;

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};
use vpnui_proto::{
    ConnectPhase, ErrorBody, ErrorCode, Event, IpInfo, Server, ServerId, Settings, SettingsPatch,
    Stats, TunnelState, UnixMillis,
};

use crate::country;
use crate::engine::engine::{
    Action, DEFAULT_TUNNEL_MTU, Engine, EngineError, EngineOptions, Input, Phase, Retry,
    SOFT_ATTEMPTS, Session, TUNNEL_OVERHEAD, backoff, millis, same_ignoring_handshake, server_of,
    tunnel_routes,
};
use crate::net::net::{DefaultRoute, IpNet, split_default_routes};
use crate::platform::{Anchor, Mono, Now, Platform, PlatformError, WgInstance};
use crate::policy::policy::{self, Policy};
use crate::profile::profile::Profile;
use crate::shared::Shared;
use crate::state::{JournalEntry, PersistedState, Undo};
use crate::uapi::uapi::DeviceConfig;

impl<P: Platform> Engine<P> {
    /// start() carries out startup steps 1-3:
    /// 1. Load state
    /// 2. Fail closed if armed
    /// 3. Recover from the journal
    /// The caller binds the socket only after this returns
    pub(crate) fn start(p: P, shared: Arc<Shared>, opts: EngineOptions) -> Self {
        let st = match p.load_state() {
            Ok(Some(json)) => match serde_json::from_str::<PersistedState>(&json) {
                Ok(st) => st,
                Err(e) => {
                    error!(%e, "state file is unreadable; assuming the kill switch was armed");
                    PersistedState::fail_closed()
                }
            },
            Ok(None) => PersistedState::default(),
            Err(e) => {
                error!(%e, "cannot read state; assuming the kill switch was armed");
                PersistedState::fail_closed()
            }
        };

        let mut engine = Self {
            p,
            shared,
            opts,
            next_session: st.journal.iter().map(|e| e.session).max().unwrap_or(0) + 1,
            st,
            catalog: Vec::new(),
            kill_switch: KillSwitchState::Off,
            session: None,
            last_error: None,
            last_tick: None,
            last_loaded: None,
            recovering: true,
            published_tunnel: None,
            public_ip: None,
        };

        if engine.st.armed {
            engine.arm_at_startup();
        } else {
            if let Err(e) = engine.p.pf_flush(Anchor::KillSwitch) {
                warn!(%e, "could not clear the kill-switch anchor");
            }
            engine.release_token();
        }

        engine.recover();
        engine.recovering = false;
        engine.catalog = match engine.p.load_profiles() {
            Ok(profiles) => profiles,
            Err(e) => {
                error!(%e, "could not load profiles");
                Vec::new()
            }
        };

        engine.publish_snapshot();
        engine
    }

    /// Steps 2-4 of a connect: 
    /// 1. Spawn and configure wireguard-go
    /// 2. Allow its interface
    /// 3. pin the endpoint route
    /// 4. Wait for a handshake.
    pub(crate) fn bring_up(
        &mut self,
        s: &mut Session,
        retry: Option<Retry>,
    ) -> Result<(), EngineError> {
        self.journal(s.id, Undo::WireGuard { ifname: None })?;
        let instance = self.p.wg_spawn()?;
        if let Some(entry) = self
            .st
            .journal
            .iter_mut()
            .rev()
            .find(|e| e.session == s.id && matches!(e.undo, Undo::WireGuard { ifname: None }))
        {
            entry.undo = Undo::WireGuard {
                ifname: Some(instance.ifname.clone()),
            };
        }
        self.persist()?;
        let ifname = instance.ifname.clone();
        s.instance = Some(instance);

        let profile = &s.profile;
        let keepalive = match profile.peer.persistent_keepalive {
            Some(k) if k > 0 => k,
            Some(_) | None => self.opts.keepalive,
        };
        self.p.uapi_configure(
            &ifname,
            &DeviceConfig {
                private_key: &profile.interface.private_key,
                peer: &profile.peer.public_key,
                preshared_key: profile.peer.preshared_key.as_ref(),
                endpoint: profile.endpoint(),
                keepalive,
                allowed_ips: &profile.peer.allowed_ips,
            },
        )?;
        let mtu = match profile.interface.mtu {
            Some(mtu) => mtu,
            None => self
                .p
                .interface_mtu(&s.route.interface)?
                .map_or(DEFAULT_TUNNEL_MTU, |m| m.saturating_sub(TUNNEL_OVERHEAD)),
        };
        let addresses = profile.interface.addresses.clone();
        self.p.interface_configure(&ifname, &addresses, mtu)?;

        self.journal(
            s.id,
            Undo::TunnelException {
                ifname: ifname.clone(),
            },
        )?;
        self.reload()?;

        let dest = s.profile.endpoint().ip();
        self.journal(s.id, Undo::HostRoute { dest })?;
        self.p.route_add_host(dest, s.route.gateway)?;

        let now = self.p.now();
        s.phase = Phase::Handshaking {
            deadline: now.mono.plus_ms(millis(self.opts.handshake_timeout)),
            retry: retry.clone(),
        };
        match retry {
            None => self.publish_tunnel_state(TunnelState::Connecting {
                server_id: ServerId::new(s.profile.id.clone()),
                phase: ConnectPhase::Handshaking,
                started_at_ms: s.started_at,
            }),
            Some(_) => self.publish_tunnel_state(Self::tunnel_of(s)),
        }
        Ok(())
    }

    /// Steps 6-8, once a handshake has been seen.
    pub(crate) fn finish_up(&mut self, s: &mut Session) -> Result<(), EngineError> {
        if matches!(s.phase, Phase::Handshaking { retry: None, .. }) {
            self.publish_tunnel_state(TunnelState::Connecting {
                server_id: ServerId::new(s.profile.id.clone()),
                phase: ConnectPhase::ConfiguringRoutes,
                started_at_ms: s.started_at,
            });
        }
        let ifname = s
            .instance
            .as_ref()
            .map(|i| i.ifname.clone())
            .ok_or_else(|| EngineError::new(ErrorCode::WgFailed, "no tunnel instance"))?;
        for net in tunnel_routes(&s.profile) {
            self.journal(
                s.id,
                Undo::NetRoute {
                    net,
                    ifname: ifname.clone(),
                },
            )?;
            self.p.route_add_net(net, &ifname)?;
        }
        if !s.profile.interface.dns.is_empty() {
            self.journal(s.id, Undo::Dns)?;
            let servers = s.profile.interface.dns.clone();
            self.p.dns_set(&servers)?;
        }
        let now = self.p.now();
        s.phase = Phase::Connected;
        s.since = s.since.or(Some(now.wall));
        self.st.push_recent(&s.profile.id);
        self.persist_best_effort();
        let recents: Vec<ServerId> = self.st.recents.iter().cloned().map(ServerId::new).collect();
        self.shared.update(|snap| snap.recents = recents);
        info!(profile = %s.profile.id, "connected");
        self.publish_tunnel_state(Self::tunnel_of(s));
        Ok(())
    }
}
