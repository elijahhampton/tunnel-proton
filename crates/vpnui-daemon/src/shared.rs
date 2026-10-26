//! The snapshot every client sees, updated in lockstep with the broadcast of each event so a
//! subscriber never misses or double-counts one.

use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::broadcast;
use vpnui_proto::{Event, KillSwitchState, PROTOCOL_VERSION, Snapshot, TunnelState};

use crate::state::default_settings;

const EVENT_BUFFER: usize = 512;

pub struct Shared {
    snapshot: Mutex<Snapshot>,
    events: broadcast::Sender<Event>,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        Arc::new(Self {
            snapshot: Mutex::new(Snapshot {
                protocol_version: PROTOCOL_VERSION,
                tunnel: TunnelState::Disconnected { last_error: None },
                kill_switch: KillSwitchState::Off,
                settings: default_settings(),
                servers: Vec::new(),
                recents: Vec::new(),
                public_ip: None,
                profiles_count: 0,
            }),
            events,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Snapshot> {
        self.snapshot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn publish(&self, event: Event) {
        let mut snapshot = self.lock();
        apply(&mut snapshot, &event);
        let _ = self.events.send(event);
    }

    /// Changes the snapshot without an event (for fields with no event of their own).
    pub fn update(&self, f: impl FnOnce(&mut Snapshot)) {
        f(&mut self.lock());
    }

    /// The current snapshot and a receiver for every event after it.
    pub fn subscribe(&self) -> (Snapshot, broadcast::Receiver<Event>) {
        let snapshot = self.lock();
        (snapshot.clone(), self.events.subscribe())
    }

    pub fn snapshot(&self) -> Snapshot {
        self.lock().clone()
    }
}

fn apply(snapshot: &mut Snapshot, event: &Event) {
    match event {
        Event::Snapshot(new) => *snapshot = (**new).clone(),
        Event::TunnelChanged { tunnel } => snapshot.tunnel = tunnel.clone(),
        Event::KillSwitchChanged { kill_switch } => snapshot.kill_switch = kill_switch.clone(),
        Event::SettingsChanged { settings } => snapshot.settings = *settings,
        Event::ServersUpdated { servers } => {
            snapshot.servers = servers.clone();
            snapshot.profiles_count = u32::try_from(servers.len()).unwrap_or(u32::MAX);
        }
        Event::PublicIpChanged { public_ip } => snapshot.public_ip = public_ip.clone(),
        Event::Stats(stats) => {
            if let TunnelState::Connected {
                last_handshake_ms, ..
            } = &mut snapshot.tunnel
            {
                *last_handshake_ms = stats.last_handshake_ms;
            }
        }
        Event::Log { .. } | Event::Unknown => {}
    }
}
