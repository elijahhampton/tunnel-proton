//! Builders shared by reducer and rendering tests.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use vpnui_proto::{
    ConnectPhase, DaemonMessage, Event as DaemonEvent, Feature, IpInfo, KillSwitchState,
    PROTOCOL_VERSION, Request, Response, Server, ServerId, Settings, Snapshot, TunnelState,
    UnixMillis,
};

use super::{AppState, Effect, Event, LinkEvent, update};
use crate::theme::{ColorMode, Theme};

pub const T0: UnixMillis = UnixMillis(1_760_000_000_000);

pub fn at(secs: u64) -> UnixMillis {
    UnixMillis(T0.0 + secs * 1000)
}

struct Place {
    cc: &'static str,
    country: &'static str,
    city: &'static str,
    lat: f64,
    lon: f64,
}

const ZURICH: Place = Place {
    cc: "CH",
    country: "Switzerland",
    city: "Zürich",
    lat: 47.3769,
    lon: 8.5417,
};
const GENEVA: Place = Place {
    cc: "CH",
    country: "Switzerland",
    city: "Geneva",
    lat: 46.2044,
    lon: 6.1432,
};
const STOCKHOLM: Place = Place {
    cc: "SE",
    country: "Sweden",
    city: "Stockholm",
    lat: 59.3293,
    lon: 18.0686,
};
const TOKYO: Place = Place {
    cc: "JP",
    country: "Japan",
    city: "Tokyo",
    lat: 35.6762,
    lon: 139.6503,
};
const SAO_PAULO: Place = Place {
    cc: "BR",
    country: "Brazil",
    city: "São Paulo",
    lat: -23.5505,
    lon: -46.6333,
};

fn server(
    id: &str,
    name: &str,
    place: &Place,
    load: u8,
    latency: u32,
    features: &[Feature],
) -> Server {
    Server {
        id: ServerId::new(id),
        name: name.into(),
        country_code: place.cc.into(),
        country: place.country.into(),
        city: place.city.into(),
        lat: Some(place.lat),
        lon: Some(place.lon),
        load_pct: Some(load),
        latency_ms: Some(latency),
        features: features.to_vec(),
        profile_id: None,
        entry_ip: None,
        imported_at_ms: None,
    }
}

/// An imported profile as vpnuid reports it: no load, latency, features, or city.
fn profile(id: &str, name: &str, entry: [u8; 4], imported_days_ago: u64) -> Server {
    Server {
        id: ServerId::new(id),
        name: name.into(),
        country_code: "CO".into(),
        country: "Colombia".into(),
        city: String::new(),
        lat: Some(4.5709),
        lon: Some(-74.2973),
        load_pct: None,
        latency_ms: None,
        features: Vec::new(),
        profile_id: Some(ServerId::new(id)),
        entry_ip: Some(std::net::IpAddr::from(entry)),
        imported_at_ms: Some(UnixMillis(T0.0 - imported_days_ago * 86_400_000)),
    }
}

pub fn colombia_profiles() -> Vec<Server> {
    vec![
        profile("co-4-1a2b3c", "CO#4", [203, 0, 113, 40], 3),
        profile("co-7-4d5e6f", "CO#7", [203, 0, 113, 41], 1),
    ]
}

pub fn co4() -> ServerId {
    ServerId::new("co-4-1a2b3c")
}

/// What vpnuid sends: imported profiles only, no IP check.
pub fn profiles_snapshot(
    tunnel: TunnelState,
    kill_switch: KillSwitchState,
    servers: Vec<Server>,
    recents: Vec<ServerId>,
) -> Snapshot {
    Snapshot {
        protocol_version: PROTOCOL_VERSION,
        tunnel,
        kill_switch,
        settings: settings(),
        profiles_count: u32::try_from(servers.len()).unwrap_or(u32::MAX),
        servers,
        recents,
        public_ip: None,
    }
}

pub fn servers() -> Vec<Server> {
    use Feature::{Multihop, P2p, Streaming, Unknown};
    vec![
        server(
            "ch-zrh-012",
            "Zürich #12",
            &ZURICH,
            41,
            92,
            &[P2p, Streaming],
        ),
        server("ch-zrh-003", "Zürich #3", &ZURICH, 83, 95, &[Multihop]),
        server("ch-gva-001", "Geneva #1", &GENEVA, 22, 99, &[]),
        server("se-sto-002", "Stockholm #2", &STOCKHOLM, 12, 110, &[P2p]),
        server(
            "jp-tyo-007",
            "Tokyo #7",
            &TOKYO,
            64,
            180,
            &[Streaming, Unknown],
        ),
        server(
            "br-sao-004",
            "São Paulo #4",
            &SAO_PAULO,
            55,
            130,
            &[P2p, Streaming, Multihop],
        ),
    ]
}

pub fn zurich() -> ServerId {
    ServerId::new("ch-zrh-012")
}

pub fn home_ip() -> IpInfo {
    IpInfo {
        ip: std::net::IpAddr::from([203, 0, 113, 7]),
        city: "New York".into(),
        country: "United States".into(),
        lat: Some(40.7128),
        lon: Some(-74.0060),
    }
}

pub fn exit_ip() -> IpInfo {
    IpInfo {
        ip: std::net::IpAddr::from([198, 51, 100, 12]),
        city: "Zürich".into(),
        country: "Switzerland".into(),
        lat: Some(47.3769),
        lon: Some(8.5417),
    }
}

pub fn disconnected() -> TunnelState {
    TunnelState::Disconnected { last_error: None }
}

pub fn connecting() -> TunnelState {
    TunnelState::Connecting {
        server_id: zurich(),
        phase: ConnectPhase::Handshaking,
        started_at_ms: at(0),
    }
}

pub fn connected() -> TunnelState {
    TunnelState::Connected {
        server_id: zurich(),
        since_ms: at(0),
        endpoint: "198.51.100.12:51820".into(),
        last_handshake_ms: Some(at(0)),
    }
}

pub fn reconnecting() -> TunnelState {
    TunnelState::Reconnecting {
        server_id: zurich(),
        attempt: 3,
        retry_at_ms: Some(at(4)),
        reason: "peer stopped responding".into(),
    }
}

pub fn settings() -> Settings {
    Settings {
        allow_lan: false,
        block_ipv6: true,
        auto_reconnect: true,
    }
}

pub fn snapshot(tunnel: TunnelState, kill_switch: KillSwitchState) -> Snapshot {
    let public_ip = if tunnel.is_connected() {
        exit_ip()
    } else {
        home_ip()
    };
    Snapshot {
        protocol_version: PROTOCOL_VERSION,
        tunnel,
        kill_switch,
        settings: settings(),
        servers: servers(),
        recents: vec![
            zurich(),
            ServerId::new("se-sto-002"),
            ServerId::new("jp-tyo-007"),
        ],
        public_ip: Some(public_ip),
        profiles_count: 6,
    }
}

pub fn theme() -> Theme {
    Theme::new(ColorMode::None, false)
}

pub fn daemon(event: DaemonEvent) -> Event {
    Event::Daemon(Box::new(DaemonMessage::Event { event }))
}

pub fn reply(response: Response) -> Event {
    Event::Daemon(Box::new(DaemonMessage::Response(response)))
}

pub fn key(c: char) -> Event {
    Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
}

pub fn code(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

pub fn sent(effects: &[Effect]) -> Vec<Request> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::Send(request) => Some(request.clone()),
            Effect::Log(..) | Effect::Quit => None,
        })
        .collect()
}

/// Drives the real handshake (socket up, hello, subscribe, snapshot) to a live state.
pub fn live_with(snapshot: Snapshot, width: u16, height: u16) -> AppState {
    let mut state = AppState::new(theme(), T0, width, height);
    let hello = sent(&update(&mut state, Event::Link(LinkEvent::Connected)));
    let subscribe = sent(&update(
        &mut state,
        reply(Response::ok(hello[0].id).with_protocol_version(PROTOCOL_VERSION)),
    ));
    update(&mut state, reply(Response::ok(subscribe[0].id)));
    update(
        &mut state,
        daemon(DaemonEvent::Snapshot(Box::new(snapshot))),
    );
    state
}

pub fn live(tunnel: TunnelState, kill_switch: KillSwitchState) -> AppState {
    live_with(snapshot(tunnel, kill_switch), 120, 40)
}
