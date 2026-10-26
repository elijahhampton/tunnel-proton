use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;

use super::*;
use crate::testkeys::{TempDir, key_bytes, private_bytes, public_bytes, secret_forms};

type SetLog = Arc<Mutex<Vec<Vec<(String, String)>>>>;

/// A minimal UAPI server: accepts set/get, records the parsed set lines, and reports a fixed
/// handshake.
struct FakeUapi {
    _dir: TempDir,
    path: std::path::PathBuf,
    sets: SetLog,
}

impl FakeUapi {
    fn start(errno_on_set: i64) -> Self {
        let dir = TempDir::new("uapi").unwrap();
        let path = dir.path().join("utun9.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let sets = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&sets);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut lines = Vec::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\n" {
                        break;
                    }
                    lines.push(line.trim_end().to_owned());
                }
                let reply = match lines.first().map(String::as_str) {
                    Some("get=1") => format!(
                        "private_key={}\nlisten_port=51820\npublic_key={}\nendpoint=203.0.113.40:51820\n\
                         last_handshake_time_sec=1760000123\nlast_handshake_time_nsec=456000000\n\
                         rx_bytes=1000\ntx_bytes=2000\npersistent_keepalive_interval=25\n\
                         allowed_ip=0.0.0.0/0\nprotocol_version=1\nerrno=0\n\n",
                        crate::secret::hex(&private_bytes(1)),
                        crate::secret::hex(&public_bytes(1))
                    ),
                    Some("set=1") => {
                        let pairs = lines[1..]
                            .iter()
                            .filter_map(|l| l.split_once('='))
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect();
                        recorded.lock().unwrap().push(pairs);
                        format!("errno={errno_on_set}\n\n")
                    }
                    _ => "errno=22\n\n".to_owned(),
                };
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        Self {
            _dir: dir,
            path,
            sets,
        }
    }
}

fn allowed() -> Vec<IpNet> {
    vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]
}

#[test]
fn configure_encodes_hex_keys_and_peer_section() {
    let private = SecretKey::from_bytes(private_bytes(1));
    let psk = SecretKey::from_bytes(key_bytes(1));
    let peer = PublicKey::from_bytes(public_bytes(1));
    let nets = allowed();
    let text = encode_configure(&DeviceConfig {
        private_key: &private,
        peer: &peer,
        preshared_key: Some(&psk),
        endpoint: "203.0.113.40:51820".parse().unwrap(),
        keepalive: 25,
        allowed_ips: &nets,
    });
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "set=1");
    assert_eq!(
        lines[1],
        format!("private_key={}", crate::secret::hex(&private_bytes(1)))
    );
    assert_eq!(lines[2], "replace_peers=true");
    assert_eq!(lines[3], format!("public_key={}", peer.to_hex()));
    assert!(lines.contains(&"endpoint=203.0.113.40:51820"));
    assert!(lines.contains(&"persistent_keepalive_interval=25"));
    let replace = lines
        .iter()
        .position(|l| *l == "replace_allowed_ips=true")
        .unwrap();
    assert_eq!(
        &lines[replace + 1..],
        ["allowed_ip=0.0.0.0/0", "allowed_ip=::/0", ""]
    );
    assert!(text.ends_with("\n\n"));
    assert!(
        !text.contains(&private.to_base64().to_string()),
        "keys travel as hex, not base64"
    );
}

#[test]
fn refresh_carries_no_secrets() {
    let peer = PublicKey::from_bytes(public_bytes(1));
    let text = encode_refresh(&peer, "203.0.113.40:51820".parse().unwrap(), 25);
    assert!(text.starts_with("set=1\npublic_key="));
    assert!(text.contains("update_only=true\n"));
    assert!(
        text.ends_with("persistent_keepalive_interval=0\npersistent_keepalive_interval=25\n\n")
    );
    for form in secret_forms(1) {
        assert!(!text.contains(&form));
    }
}

#[test]
fn parses_status_and_errors() {
    let status = parse_get_response(
        "public_key=ab\nlast_handshake_time_sec=10\nlast_handshake_time_nsec=500000000\n\
         rx_bytes=5\ntx_bytes=7\nerrno=0\n",
    )
    .unwrap();
    assert_eq!(status.last_handshake, Some(UnixMillis(10_500)));
    assert_eq!((status.rx_bytes, status.tx_bytes), (5, 7));

    let fresh = parse_get_response("last_handshake_time_sec=0\nrx_bytes=0\nerrno=0\n").unwrap();
    assert_eq!(fresh.last_handshake, None);

    assert_eq!(parse_set_response("errno=0\n"), Ok(()));
    assert_eq!(parse_set_response("errno=22\n"), Err(UapiError::Errno(22)));
    assert_eq!(
        parse_set_response("errno=-22\n"),
        Err(UapiError::Errno(-22)),
        "wireguard-go negates errno"
    );
    assert!(matches!(
        parse_set_response("nothing\n"),
        Err(UapiError::Malformed(_))
    ));
    assert!(matches!(
        parse_get_response("rx_bytes=x\nerrno=0\n"),
        Err(UapiError::Malformed(_))
    ));
}

#[test]
fn talks_to_a_uapi_server() {
    let server = FakeUapi::start(0);
    let private = SecretKey::from_bytes(private_bytes(1));
    let peer = PublicKey::from_bytes(public_bytes(1));
    let nets = allowed();
    let request = encode_configure(&DeviceConfig {
        private_key: &private,
        peer: &peer,
        preshared_key: None,
        endpoint: "203.0.113.40:51820".parse().unwrap(),
        keepalive: 25,
        allowed_ips: &nets,
    });
    let response = transact(&server.path, &request, Duration::from_secs(2)).unwrap();
    parse_set_response(&response).unwrap();

    let sets = server.sets.lock().unwrap().clone();
    let first: BTreeMap<_, _> = sets[0].iter().cloned().collect();
    assert_eq!(
        first.get("private_key"),
        Some(&private.to_hex().to_string())
    );
    assert_eq!(
        first.get("endpoint").map(String::as_str),
        Some("203.0.113.40:51820")
    );

    let response = transact(&server.path, GET_REQUEST, Duration::from_secs(2)).unwrap();
    let status = parse_get_response(&response).unwrap();
    assert_eq!(status.last_handshake, Some(UnixMillis(1_760_000_123_456)));
    assert_eq!((status.rx_bytes, status.tx_bytes), (1000, 2000));
    let shown = format!("{status:?}");
    for form in secret_forms(1) {
        assert!(
            !shown.contains(&form),
            "status must not retain the private key"
        );
    }
}

#[test]
fn nonzero_errno_from_server_is_an_error() {
    let server = FakeUapi::start(-13);
    let peer = PublicKey::from_bytes(public_bytes(1));
    let response = transact(
        &server.path,
        &encode_refresh(&peer, "203.0.113.40:51820".parse().unwrap(), 25),
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(parse_set_response(&response), Err(UapiError::Errno(-13)));
}

#[test]
fn missing_socket_is_an_io_error() {
    let dir = TempDir::new("uapi-missing").unwrap();
    let result = transact(
        &dir.path().join("none.sock"),
        GET_REQUEST,
        Duration::from_millis(200),
    );
    assert!(matches!(result, Err(UapiError::Io(_))));
}
