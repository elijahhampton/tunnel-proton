use std::path::Path;
use std::process::Command;

use crate::policy::policy::{BLOCK_ALL_RULE, BLOCK_V6_RULE, LOOPBACK_RULE, Policy, render, tightens};
use crate::policy::policy::SELFTEST_RULE;
use super::*;

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/policy.txt");

fn combinations() -> Vec<(String, Policy)> {
    let endpoint_sets: [&[&str]; 3] = [
        &[],
        &["203.0.113.40:51820"],
        &["203.0.113.40:51820", "198.51.100.7:1194"],
    ];
    let mut out = Vec::new();
    for armed in [false, true] {
        for allow_lan in [false, true] {
            for block_ipv6 in [false, true] {
                for endpoints in endpoint_sets {
                    for tunnel in [None, Some("utun4")] {
                        let label = format!(
                            "armed={armed} allow_lan={allow_lan} block_ipv6={block_ipv6} endpoints={} tunnel_if={}",
                            endpoints.len(),
                            tunnel.unwrap_or("none")
                        );
                        let policy = Policy {
                            armed,
                            allow_lan,
                            block_ipv6,
                            endpoints: endpoints.iter().map(|e| e.parse().unwrap()).collect(),
                            tunnel_if: tunnel.map(|t| t.parse().unwrap()),
                        };
                        out.push((label, policy));
                    }
                }
            }
        }
    }
    out
}

fn render_all() -> String {
    let mut out = String::new();
    for (label, policy) in combinations() {
        out.push_str(&format!("=== {label}\n{}", render(&policy)));
    }
    out
}

/// Set UPDATE_GOLDEN=1 to rewrite the file after an intentional change, then review the diff.
#[test]
fn golden_renderings_for_every_combination() {
    assert_eq!(combinations().len(), 48);
    let rendered = render_all();
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(GOLDEN, &rendered).unwrap();
    }
    let golden = std::fs::read_to_string(GOLDEN).unwrap();
    assert_eq!(
        rendered, golden,
        "rendering changed; rerun with UPDATE_GOLDEN=1 and review"
    );
}

#[test]
fn structure_holds_for_every_combination() {
    for (label, policy) in combinations() {
        let text = render(&policy);
        if !policy.armed {
            assert!(text.is_empty(), "{label}");
            continue;
        }
        let rules: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert!(
            rules.iter().all(|r| r.contains(" quick ")),
            "{label}: every rule is quick"
        );
        assert_eq!(rules.first(), Some(&LOOPBACK_RULE), "{label}");
        assert_eq!(rules.last(), Some(&BLOCK_ALL_RULE), "{label}");
        assert!(
            !text.contains("en0") && !text.contains("en1"),
            "{label}: no physical interface"
        );
        let position = |needle: &str| rules.iter().position(|r| r.contains(needle));
        let dns = position("port 53").unwrap();
        if policy.allow_lan {
            assert!(
                position("10.0.0.0/8").unwrap() > dns,
                "{label}: LAN DNS stays blocked"
            );
        } else {
            assert!(position("10.0.0.0/8").is_none(), "{label}");
        }
        if let Some(tunnel) = position("on utun4") {
            assert!(tunnel < dns, "{label}: tunnel DNS is allowed");
        }
        assert_eq!(
            position(BLOCK_V6_RULE).is_some(),
            policy.block_ipv6,
            "{label}"
        );
        assert_eq!(
            text.matches("port 51820").count() + text.matches("port 1194").count(),
            policy.endpoints.len()
        );
        assert!(
            rules
                .iter()
                .filter(|r| r.contains("from {"))
                .all(|r| r.starts_with("pass in ")),
            "{label}: LAN-sourced rules are inbound only, or every outbound packet would match"
        );
    }
}

#[test]
fn tightening_is_settings_level() {
    let base = Policy {
        armed: true,
        block_ipv6: true,
        ..Policy::default()
    };
    assert!(tightens(&Policy::default(), &base));
    let lan = Policy {
        allow_lan: true,
        ..base.clone()
    };
    assert!(tightens(&lan, &base));
    assert!(!tightens(&base, &lan));
    let with_tunnel = Policy {
        tunnel_if: Some("utun4".parse().unwrap()),
        endpoints: ["203.0.113.40:51820".parse().unwrap()].into(),
        ..base.clone()
    };
    assert!(
        !tightens(&with_tunnel, &base),
        "dropping exceptions is not a flush trigger"
    );
}

/// `pfctl -n` parses without loading and needs no privileges. Skipped where pfctl is absent.
#[test]
fn every_rendering_parses_with_the_real_pf_parser() {
    let pfctl = Path::new("/sbin/pfctl");
    if !pfctl.exists() {
        eprintln!("skipping: /sbin/pfctl not available");
        return;
    }
    let dir = crate::testkeys::TempDir::new("pfparse").unwrap();
    for (index, (label, policy)) in combinations().into_iter().enumerate() {
        if !policy.armed {
            continue;
        }
        let file = dir.path().join(format!("{index}.pf"));
        std::fs::write(&file, render(&policy)).unwrap();
        let output = Command::new(pfctl)
            .arg("-n")
            .arg("-f")
            .arg(&file)
            .env_clear()
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{label}: pfctl rejected the ruleset: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let file = dir.path().join("selftest.pf");
    std::fs::write(&file, format!("{SELFTEST_RULE}\n")).unwrap();
    let output = Command::new(pfctl)
        .arg("-n")
        .arg("-f")
        .arg(&file)
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success(), "self-test rule must parse");
}
