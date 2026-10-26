#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Debug;

use serde::Serialize;
use serde::de::DeserializeOwned;
use vpnui_proto::*;

fn roundtrip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let line = encode(value).unwrap();
    assert!(
        !line.contains('\n'),
        "encoded message must be a single line"
    );
    let back: T = decode(&line).unwrap();
    assert_eq!(
        &back, value,
        "roundtrip changed the value; wire form: {line}"
    );
}

/// Decodes `fixture` into `expected`, and checks that encoding `expected` reproduces the fixture.
fn golden<T>(fixture: &str, expected: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let decoded: T = decode(fixture.trim()).unwrap();
    assert_eq!(&decoded, expected);
    let encoded: serde_json::Value = serde_json::from_str(&encode(expected).unwrap()).unwrap();
    let fixture: serde_json::Value = serde_json::from_str(fixture).unwrap();
    assert_eq!(encoded, fixture);
}

fn zurich() -> Server {
    Server {
        id: ServerId::new("ch-zrh-012"),
        name: "Zürich #12".into(),
        country_code: "CH".into(),
        country: "Switzerland".into(),
        city: "Zürich".into(),
        lat: Some(47.3769),
        lon: Some(8.5417),
        load_pct: Some(41),
        latency_ms: Some(92),
        features: vec![Feature::P2p, Feature::Streaming],
        profile_id: None,
        entry_ip: None,
        imported_at_ms: None,
    }
}

fn colombia() -> Server {
    Server {
        id: ServerId::new("co-4-1a2b3c"),
        name: "CO#4".into(),
        country_code: "CO".into(),
        country: "Colombia".into(),
        city: String::new(),
        lat: Some(4.6),
        lon: Some(-74.1),
        load_pct: None,
        latency_ms: None,
        features: Vec::new(),
        profile_id: Some(ServerId::new("co-4-1a2b3c")),
        entry_ip: Some("203.0.113.40".parse().unwrap()),
        imported_at_ms: Some(UnixMillis(1_759_990_000_000)),
    }
}

#[test]
fn golden_hello_request() {
    golden(
        include_str!("fixtures/hello_request.json"),
        &Request {
            id: RequestId(1),
            cmd: Command::Hello {
                client_version: "0.2.0".into(),
                protocol_version: ProtocolVersion(2),
            },
        },
    );
}

#[test]
fn golden_partial_settings_request() {
    golden(
        include_str!("fixtures/set_settings_request.json"),
        &Request {
            id: RequestId(7),
            cmd: Command::SetSettings(SettingsPatch {
                allow_lan: Some(true),
                ..SettingsPatch::default()
            }),
        },
    );
}

#[test]
fn golden_reload_profiles_request() {
    golden(
        include_str!("fixtures/reload_profiles_request.json"),
        &Request {
            id: RequestId(12),
            cmd: Command::ReloadProfiles,
        },
    );
}

#[test]
fn golden_responses() {
    golden(
        include_str!("fixtures/handshake_timeout_response.json"),
        &DaemonMessage::Response(Response::err(
            RequestId(5),
            ErrorCode::HandshakeTimeout,
            "no handshake from the server within 15s",
        )),
    );
    golden(
        include_str!("fixtures/hello_response.json"),
        &DaemonMessage::Response(
            Response::ok(RequestId(1)).with_protocol_version(PROTOCOL_VERSION),
        ),
    );
    golden(
        include_str!("fixtures/error_response.json"),
        &DaemonMessage::Response(Response::err(
            RequestId(9),
            ErrorCode::UnknownServer,
            "no server with id xx-yyy-000",
        )),
    );
}

#[test]
fn golden_tunnel_changed() {
    golden(
        include_str!("fixtures/tunnel_connecting_event.json"),
        &DaemonMessage::Event {
            event: Event::TunnelChanged {
                tunnel: TunnelState::Connecting {
                    server_id: ServerId::new("ch-zrh-012"),
                    phase: ConnectPhase::ConfiguringRoutes,
                    started_at_ms: UnixMillis(1_760_000_000_000),
                },
            },
        },
    );
}

#[test]
fn golden_snapshot() {
    golden(
        include_str!("fixtures/snapshot_event.json"),
        &DaemonMessage::Event {
            event: Event::Snapshot(Box::new(Snapshot {
                protocol_version: ProtocolVersion(2),
                tunnel: TunnelState::Connected {
                    server_id: ServerId::new("co-4-1a2b3c"),
                    since_ms: UnixMillis(1_760_000_000_000),
                    endpoint: "203.0.113.40:51820".into(),
                    last_handshake_ms: Some(UnixMillis(1_760_000_090_000)),
                },
                kill_switch: KillSwitchState::Armed,
                settings: Settings {
                    allow_lan: false,
                    block_ipv6: true,
                    auto_reconnect: true,
                },
                servers: vec![colombia()],
                recents: vec![ServerId::new("co-4-1a2b3c")],
                public_ip: None,
                profiles_count: 1,
            })),
        },
    );
}

/// A v1 daemon's snapshot still decodes, so the client can reject it on `protocol_version`
/// with a clear message instead of a parse error.
#[test]
fn v1_snapshot_is_tolerated_and_identifiable() {
    let msg: DaemonMessage =
        decode(include_str!("fixtures/snapshot_v1_event.json").trim()).unwrap();
    let DaemonMessage::Event {
        event: Event::Snapshot(snapshot),
    } = msg
    else {
        panic!("expected a snapshot");
    };
    assert_eq!(snapshot.protocol_version, ProtocolVersion(1));
    assert_ne!(snapshot.protocol_version, PROTOCOL_VERSION);
    assert_eq!(snapshot.profiles_count, 0, "absent in v1, defaulted");
    let server = &snapshot.servers[0];
    assert_eq!(server.load_pct, Some(41));
    assert_eq!(server.latency_ms, Some(92));
    assert_eq!(server.lat, Some(47.3769));
    assert_eq!(server.profile_id, None);
    assert_eq!(server.entry_ip, None);
}

#[test]
fn error_codes_have_stable_spellings() {
    for code in ErrorCode::ALL {
        let encoded = encode(&code).unwrap();
        assert_eq!(encoded, format!("\"{}\"", code.as_str()));
        assert_eq!(ErrorCode::parse(code.as_str()), code);
        let back: ErrorCode = decode(&encoded).unwrap();
        assert_eq!(back, code);
    }
    assert_eq!(ErrorCode::parse("teapot"), ErrorCode::Unknown);
}

#[test]
fn future_event_type_decodes_as_unknown() {
    let msg: DaemonMessage = decode(include_str!("fixtures/future_event.json").trim()).unwrap();
    assert_eq!(
        msg,
        DaemonMessage::Event {
            event: Event::Unknown
        }
    );
}

#[test]
fn unknown_variants_inside_known_messages_decode_as_unknown() {
    let tunnel: TunnelState = decode(r#"{"type":"paused","until_ms":5}"#).unwrap();
    assert_eq!(tunnel, TunnelState::Unknown);

    let ks: KillSwitchState = decode(r#"{"type":"partial","rules":3}"#).unwrap();
    assert_eq!(ks, KillSwitchState::Unknown);

    let phase: ConnectPhase = decode(r#""negotiating_mtu""#).unwrap();
    assert_eq!(phase, ConnectPhase::Unknown);

    let features: Vec<Feature> = decode(r#"["p2p","tor","multihop"]"#).unwrap();
    assert_eq!(
        features,
        vec![Feature::P2p, Feature::Unknown, Feature::Multihop]
    );

    let code: ErrorCode = decode(r#""rate_limited""#).unwrap();
    assert_eq!(code, ErrorCode::Unknown);

    let cmd: Request = decode(r#"{"id":3,"cmd":{"type":"rotate_keys"}}"#).unwrap();
    assert_eq!(cmd.cmd, Command::Unknown);
}

#[test]
fn unknown_fields_are_ignored() {
    let msg: DaemonMessage =
        decode(r#"{"id":4,"ok":true,"elapsed_us":12,"server":{"build":"x"}}"#).unwrap();
    assert_eq!(msg, DaemonMessage::Response(Response::ok(RequestId(4))));

    let stats: Event =
        decode(r#"{"type":"stats","rx_bytes":10,"tx_bytes":20,"rx_packets":1}"#).unwrap();
    assert_eq!(
        stats,
        Event::Stats(Stats {
            rx_bytes: 10,
            tx_bytes: 20,
            last_handshake_ms: None
        })
    );
}

#[test]
fn malformed_daemon_message_reports_the_field() {
    let err = decode::<DaemonMessage>(r#"{"event":{"type":"stats","rx_bytes":"lots"}}"#)
        .unwrap_err()
        .to_string();
    assert!(err.contains("invalid type"), "unexpected error: {err}");
}

#[test]
fn every_command_roundtrips() {
    let commands = [
        Command::Hello {
            client_version: "1.2.3".into(),
            protocol_version: PROTOCOL_VERSION,
        },
        Command::Subscribe,
        Command::Connect {
            server_id: ServerId::new("se-sto-003"),
        },
        Command::QuickConnect,
        Command::Disconnect,
        Command::SetKillSwitch { armed: true },
        Command::SetSettings(SettingsPatch {
            allow_lan: None,
            block_ipv6: Some(false),
            auto_reconnect: Some(true),
        }),
        Command::SetSettings(SettingsPatch::default()),
        Command::ReloadProfiles,
    ];
    for (i, cmd) in commands.into_iter().enumerate() {
        roundtrip(&Request {
            id: RequestId(i as u64),
            cmd,
        });
    }
}

#[test]
fn every_event_roundtrips() {
    let tunnels = [
        TunnelState::Disconnected { last_error: None },
        TunnelState::Disconnected {
            last_error: Some("handshake timed out".into()),
        },
        TunnelState::Connecting {
            server_id: ServerId::new("jp-tyo-001"),
            phase: ConnectPhase::Resolving,
            started_at_ms: UnixMillis(5),
        },
        TunnelState::Connected {
            server_id: ServerId::new("jp-tyo-001"),
            since_ms: UnixMillis(6),
            endpoint: "198.51.100.1:51820".into(),
            last_handshake_ms: None,
        },
        TunnelState::Reconnecting {
            server_id: ServerId::new("jp-tyo-001"),
            attempt: 3,
            retry_at_ms: Some(UnixMillis(9)),
            reason: "peer stopped responding".into(),
        },
        TunnelState::Disconnecting,
    ];
    for tunnel in tunnels {
        roundtrip(&DaemonMessage::Event {
            event: Event::TunnelChanged { tunnel },
        });
    }

    for kill_switch in [
        KillSwitchState::Off,
        KillSwitchState::Armed,
        KillSwitchState::Error {
            message: "pf: rule load failed".into(),
        },
    ] {
        roundtrip(&Event::KillSwitchChanged { kill_switch });
    }

    roundtrip(&Event::SettingsChanged {
        settings: Settings {
            allow_lan: true,
            block_ipv6: false,
            auto_reconnect: true,
        },
    });
    roundtrip(&Event::Stats(Stats {
        rx_bytes: u64::MAX,
        tx_bytes: 0,
        last_handshake_ms: Some(UnixMillis(1)),
    }));
    roundtrip(&Event::ServersUpdated {
        servers: vec![zurich(), colombia()],
    });
    roundtrip(&Event::PublicIpChanged { public_ip: None });
    let bare: IpInfo = decode(r#"{"ip":"203.0.113.9"}"#).unwrap();
    assert_eq!((bare.lat, bare.city.as_str()), (None, ""));
    roundtrip(&Event::PublicIpChanged {
        public_ip: Some(bare),
    });
    roundtrip(&Event::Log {
        level: LogLevel::Warn,
        message: "line one \"quoted\"\nline two".into(),
    });
}

#[test]
fn oversized_messages_are_rejected() {
    let huge = Event::Log {
        level: LogLevel::Info,
        message: "x".repeat(MAX_LINE_BYTES),
    };
    assert!(matches!(encode(&huge), Err(ProtoError::TooLarge { .. })));
}

#[test]
fn socket_path_limit() {
    let ok = std::path::PathBuf::from(format!("/tmp/{}", "a".repeat(MAX_SOCKET_PATH_BYTES - 5)));
    assert_eq!(ok.as_os_str().len(), MAX_SOCKET_PATH_BYTES);
    assert!(validate_socket_path(&ok).is_ok());

    let too_long = ok.join("b");
    assert!(matches!(
        validate_socket_path(&too_long),
        Err(ProtoError::SocketPathTooLong { len: 105, .. })
    ));
}
