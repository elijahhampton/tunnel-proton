use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::*;
use crate::testkeys::{key_b64, private_b64, public_b64};

fn config(peer_comment: &str, extra_interface: &str, extra_peer: &str) -> String {
    format!(
        "[Interface]\n\
         # Key for test\n\
         PrivateKey = {}\n\
         Address = 10.2.0.2/32, fd00::2/128\n\
         DNS = 10.2.0.1\n\
         {extra_interface}\n\
         [Peer]\n\
         {peer_comment}\n\
         PublicKey = {}\n\
         AllowedIPs = 0.0.0.0/0, ::/0\n\
         Endpoint = 203.0.113.40:51820\n\
         {extra_peer}\n",
        private_b64(1),
        public_b64(1),
    )
}

#[test]
fn parses_a_typical_provider_config() {
    let parsed = parse(&config("# CO#4", "", "")).unwrap();
    assert_eq!(parsed.peer_comment.as_deref(), Some("CO#4"));
    assert_eq!(parsed.interface.addresses.len(), 2);
    assert_eq!(
        parsed.interface.dns,
        vec!["10.2.0.1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(parsed.interface.mtu, None);
    assert_eq!(parsed.peer.endpoint, "203.0.113.40:51820".parse().unwrap());
    assert_eq!(parsed.peer.allowed_ips.len(), 2);
    assert_eq!(parsed.peer.persistent_keepalive, None);
    assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
    assert_eq!(parsed.peer.public_key.to_base64(), public_b64(1));
}

#[test]
fn optional_fields() {
    let parsed = parse(&config(
        "",
        "MTU = 1380",
        &format!("PresharedKey = {}\nPersistentKeepalive = 15", key_b64(9)),
    ))
    .unwrap();
    assert_eq!(parsed.interface.mtu, Some(1380));
    assert!(parsed.peer.preshared_key.is_some());
    assert_eq!(parsed.peer.persistent_keepalive, Some(15));
    assert_eq!(parsed.peer_comment, None);

    let off = parse(&config("", "", "PersistentKeepalive = off")).unwrap();
    assert_eq!(off.peer.persistent_keepalive, Some(0));
}

#[test]
fn every_hard_reject_key_is_refused() {
    for key in [
        "PreUp",
        "PostUp",
        "PreDown",
        "PostDown",
        "SaveConfig",
        "Table",
        "FwMark",
    ] {
        for spelling in [key.to_owned(), key.to_lowercase(), key.to_uppercase()] {
            for (interface, peer) in [
                (format!("{spelling} = true"), String::new()),
                (String::new(), format!("{spelling} = 51820")),
            ] {
                let error = parse(&config("", &interface, &peer)).unwrap_err();
                assert_eq!(error.kind, ParseErrorKind::HardRejected(key), "{spelling}");
                let message = error.to_string();
                assert!(
                    message.contains(key) && message.contains("not allowed"),
                    "{message}"
                );
            }
        }
    }
    let commented = parse(&config("", "# PostUp = curl evil", "")).unwrap();
    assert!(commented.warnings.is_empty(), "comments are not keys");
}

#[test]
fn hostname_endpoints_are_rejected() {
    let text = config("", "", "").replace("203.0.113.40:51820", "co-4.vpn.example:51820");
    let error = parse(&text).unwrap_err();
    assert_eq!(error.kind, ParseErrorKind::HostnameEndpoint);
    assert!(error.to_string().contains("hostnames are rejected"));

    let v6 = config("", "", "").replace("203.0.113.40:51820", "[2001:db8::40]:51820");
    assert_eq!(parse(&v6).unwrap_err().kind, ParseErrorKind::Ipv6Endpoint);

    let no_port = config("", "", "").replace("203.0.113.40:51820", "203.0.113.40");
    assert!(matches!(
        parse(&no_port).unwrap_err().kind,
        ParseErrorKind::InvalidValue("Endpoint", _)
    ));

    let zero = config("", "", "").replace(":51820", ":0");
    assert!(matches!(
        parse(&zero).unwrap_err().kind,
        ParseErrorKind::InvalidValue("Endpoint", _)
    ));
}

#[test]
fn bad_key_lengths_are_rejected_without_echoing_values() {
    let short = STANDARD.encode([5u8; 31]);
    let long = STANDARD.encode([5u8; 33]);
    for (bad, fragment) in [
        (&short, "31 bytes"),
        (&long, "33 bytes"),
        (&"%%%".to_owned(), "base64"),
    ] {
        let text = config("", "", "").replace(&private_b64(1), bad);
        let error = parse(&text).unwrap_err();
        assert!(matches!(
            error.kind,
            ParseErrorKind::InvalidKey("PrivateKey", _)
        ));
        let message = error.to_string();
        assert!(message.contains(fragment), "{message}");
        assert!(!message.contains(bad.as_str()), "value echoed: {message}");

        let text = config("", "", "").replace(&public_b64(1), bad);
        assert!(matches!(
            parse(&text).unwrap_err().kind,
            ParseErrorKind::InvalidKey("PublicKey", _)
        ));
    }
    let text = config("", "", &format!("PresharedKey = {short}"));
    assert!(matches!(
        parse(&text).unwrap_err().kind,
        ParseErrorKind::InvalidKey("PresharedKey", _)
    ));
}

#[test]
fn crlf_bom_and_comments_are_tolerated() {
    let text = format!("\u{feff}{}", config("; CO#4", "", "").replace('\n', "\r\n"));
    let parsed = parse(&text).unwrap();
    assert_eq!(parsed.peer_comment.as_deref(), Some("CO#4"));

    let inline = config("", "", "").replace(
        "Endpoint = 203.0.113.40:51820",
        "Endpoint = 203.0.113.40:51820 # Bogotá",
    );
    assert_eq!(parse(&inline).unwrap().peer.endpoint.port(), 51820);
}

#[test]
fn structural_errors() {
    let two_peers = format!(
        "{}\n[Peer]\nPublicKey = {}\n",
        config("", "", ""),
        public_b64(2)
    );
    assert_eq!(
        parse(&two_peers).unwrap_err().kind,
        ParseErrorKind::MultiplePeers
    );

    let no_peer = config("", "", "")
        .split("[Peer]")
        .next()
        .unwrap_or_default()
        .to_owned();
    assert_eq!(
        parse(&no_peer).unwrap_err().kind,
        ParseErrorKind::MissingSection("Peer")
    );

    let outside = format!("MTU = 1400\n{}", config("", "", ""));
    assert_eq!(
        parse(&outside).unwrap_err().kind,
        ParseErrorKind::OutsideSection
    );

    let dup = config("", &format!("PrivateKey = {}", private_b64(2)), "");
    assert_eq!(
        parse(&dup).unwrap_err().kind,
        ParseErrorKind::DuplicateKey("PrivateKey")
    );

    let dns_domain = config("", "", "").replace("DNS = 10.2.0.1", "DNS = 10.2.0.1, corp.example");
    assert!(matches!(
        parse(&dns_domain).unwrap_err().kind,
        ParseErrorKind::InvalidValue("DNS", _)
    ));

    let bad_mtu = config("", "MTU = 100", "");
    assert!(matches!(
        parse(&bad_mtu).unwrap_err().kind,
        ParseErrorKind::InvalidValue("MTU", _)
    ));

    assert_eq!(
        parse_bytes(&[0xff, 0xfe, 0x00]).unwrap_err().kind,
        ParseErrorKind::NotUtf8
    );
}

#[test]
fn unknown_keys_warn_and_split_tunnels_warn() {
    let text = config("", "ListenPort = 51820", "")
        .replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.0.0.0/8");
    let parsed = parse(&text).unwrap();
    assert!(parsed.warnings.iter().any(|w| w.contains("ListenPort")));
    assert!(parsed.warnings.iter().any(|w| w.contains("0.0.0.0/0")));
}

#[test]
fn name_and_country_derivation() {
    let none = Overrides::default();
    let id = identity(Some("CO#4"), Some("wg-co-4"), &none).unwrap();
    assert_eq!(
        (id.name.as_str(), id.country_code.as_deref()),
        ("CO#4", Some("CO"))
    );

    let id = identity(Some("US-NY#123"), None, &none).unwrap();
    assert_eq!(id.country_code.as_deref(), Some("US"));

    let id = identity(Some("UK#5"), None, &none).unwrap();
    assert_eq!(
        id.country_code.as_deref(),
        Some("GB"),
        "exceptional reservation alias"
    );

    for no_country in ["my-vpn", "Home", "CORP-1", "ZZ#1", "C#1", "#1"] {
        assert_eq!(country_from_name(no_country), None, "{no_country}");
    }

    let id = identity(None, Some("CH-12"), &none).unwrap();
    assert_eq!(
        (id.name.as_str(), id.country_code.as_deref()),
        ("CH-12", Some("CH"))
    );

    let id = identity(None, None, &none).unwrap();
    assert_eq!((id.name.as_str(), id.country_code), ("profile", None));
}

#[test]
fn overrides_win_and_are_validated() {
    let overrides = Overrides {
        name: Some("Bogotá home".into()),
        country: Some("co".into()),
        city: Some("Bogotá".into()),
    };
    let id = identity(Some("US#1"), Some("x"), &overrides).unwrap();
    assert_eq!(id.name, "Bogotá home");
    assert_eq!(id.country_code.as_deref(), Some("CO"));
    assert_eq!(id.city.as_deref(), Some("Bogotá"));

    let unknown_but_valid = Overrides {
        country: Some("xk".into()),
        ..Overrides::default()
    };
    assert_eq!(
        identity(None, None, &unknown_but_valid)
            .unwrap()
            .country_code
            .as_deref(),
        Some("XK")
    );

    for bad in ["C", "COL", "1A", ""] {
        let overrides = Overrides {
            country: Some(bad.into()),
            ..Overrides::default()
        };
        assert_eq!(
            identity(None, None, &overrides),
            Err(OverrideError::Country),
            "{bad}"
        );
    }
    let blank = Overrides {
        name: Some("  \u{7}".into()),
        ..Overrides::default()
    };
    assert_eq!(identity(None, None, &blank), Err(OverrideError::Name));
}

#[test]
fn ids_are_stable_slugs_with_key_fingerprints() {
    let key = PublicKey::from_base64(&public_b64(1)).unwrap();
    let id = profile_id("CO#4", &key);
    assert_eq!(id, profile_id("CO#4", &key), "stable");
    let (slug_part, fingerprint) = id.rsplit_once('-').unwrap();
    assert_eq!(slug_part, "co-4");
    assert_eq!(fingerprint.len(), 6);
    assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
    let other = PublicKey::from_base64(&public_b64(2)).unwrap();
    assert_ne!(profile_id("CO#4", &other), id);

    assert_eq!(slug("US-NY#123"), "us-ny-123");
    assert_eq!(slug("  Bogotá  home!! "), "bogot-home");
    assert_eq!(slug("###"), "profile");
    assert!(slug(&"a".repeat(100)).len() <= 32);
}

#[test]
fn names_are_cleaned() {
    let parsed = parse(&config("#   \u{1b}[31mCO#4\u{7}   ", "", "")).unwrap();
    assert_eq!(parsed.peer_comment.as_deref(), Some("[31mCO#4"));
    let long = format!("# {}", "x".repeat(200));
    assert_eq!(
        parse(&config(&long, "", ""))
            .unwrap()
            .peer_comment
            .map(|n| n.chars().count()),
        Some(64)
    );
}
