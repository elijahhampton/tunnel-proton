//! The policy audit. [`check_op`] runs after every platform call; [`check_quiescent`] after
//! each engine step. Both read only the fake's kernel model, the persisted state file, and the
//! test's own record of what it asked for.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use vpnui_proto::KillSwitchState;

use crate::fake::fake::FakeState;
use crate::net::net::IfName;
use crate::platform::Anchor;
use crate::policy::policy::{
    self, BLOCK_ALL_RULE, BLOCK_DNS_RULE, BLOCK_V6_RULE, DHCP_IN_RULE, DHCP_OUT_RULE, LOOPBACK_RULE,
};
use crate::state::PersistedState;

pub(crate) fn persisted(st: &FakeState) -> Option<PersistedState> {
    st.state_file
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
}

/// Endpoints and tunnel interfaces the loaded kill-switch policy passes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Passes {
    pub endpoints: BTreeSet<SocketAddr>,
    pub tunnels: BTreeSet<IfName>,
    pub lan: bool,
}

/// Parses the loaded ruleset, reporting any rule outside the allowed forms.
pub fn parse_rules(rules: &str) -> (Passes, Vec<String>) {
    let mut passes = Passes::default();
    let mut problems = Vec::new();
    let lan = policy::lan_rules();
    let lines: Vec<&str> = rules
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .collect();
    for rule in &lines {
        if [
            LOOPBACK_RULE,
            DHCP_OUT_RULE,
            DHCP_IN_RULE,
            BLOCK_V6_RULE,
            BLOCK_DNS_RULE,
            BLOCK_ALL_RULE,
        ]
        .contains(rule)
        {
            continue;
        }
        if lan.iter().any(|l| l == rule) {
            passes.lan = true;
            continue;
        }
        if let Some(endpoint) = parse_endpoint_rule(rule) {
            passes.endpoints.insert(endpoint);
            continue;
        }
        if let Some(ifname) = parse_tunnel_rule(rule) {
            passes.tunnels.insert(ifname);
            continue;
        }
        problems.push(format!("I1: rule outside the allowed forms: {rule}"));
    }
    if !lines.is_empty() && lines.last() != Some(&BLOCK_ALL_RULE) {
        problems.push("I1: ruleset does not end with block drop quick all".to_owned());
    }
    if !lines.is_empty() && lines.first() != Some(&LOOPBACK_RULE) {
        problems.push("I1: ruleset does not start with the loopback pass".to_owned());
    }
    (passes, problems)
}

fn parse_endpoint_rule(rule: &str) -> Option<SocketAddr> {
    let rest = rule
        .strip_prefix("pass out quick inet proto udp from any to ")
        .or_else(|| rule.strip_prefix("pass out quick inet6 proto udp from any to "))?;
    let rest = rest.strip_suffix(" keep state")?;
    let (ip, port) = rest.split_once(" port ")?;
    let endpoint = SocketAddr::new(ip.parse().ok()?, port.parse().ok()?);
    (policy::endpoint_rule(endpoint) == rule).then_some(endpoint)
}

fn parse_tunnel_rule(rule: &str) -> Option<IfName> {
    let name = rule
        .strip_prefix("pass quick on ")?
        .strip_suffix(" all flags any keep state")?;
    let ifname: IfName = name.parse().ok()?;
    (ifname.is_tunnel() && policy::tunnel_rule(&ifname) == rule).then_some(ifname)
}

/// I1 and I2, valid at every instant.
pub fn check_op(st: &FakeState) -> Vec<String> {
    let mut problems = Vec::new();
    let saved = persisted(st);
    let rules = st.kill_switch_rules();
    let (passes, mut rule_problems) = parse_rules(rules);
    problems.append(&mut rule_problems);

    if !rules.is_empty() {
        for endpoint in &passes.endpoints {
            if !st.audit.allowed_endpoints.contains(endpoint) {
                problems.push(format!(
                    "I1: passes UDP to {endpoint}, which no requested profile uses"
                ));
            }
        }
        if passes.lan && !saved.as_ref().is_some_and(|s| s.settings.allow_lan) {
            problems.push("I1: LAN ranges pass while allow_lan is off".to_owned());
        }
        if passes.tunnels.len() > 1 {
            problems.push(format!(
                "I1: more than one tunnel interface passes: {:?}",
                passes.tunnels
            ));
        }
    }
    for ifname in &passes.tunnels {
        if !st.instances.contains_key(ifname) {
            problems.push(format!(
                "I2: pass rule for {ifname} without a tunnel instance"
            ));
        }
    }
    if !rules.is_empty() && !st.audit.recovering {
        for (net, ifname) in &st.net_routes {
            if !passes.tunnels.contains(ifname) {
                problems.push(format!(
                    "I2: route {net} points at {ifname}, which has no pass rule"
                ));
            }
        }
    }
    if st.instances.len() > 1 {
        problems.push(format!(
            "more than one wireguard-go instance: {:?}",
            st.instances.keys().collect::<Vec<_>>()
        ));
    }
    if let Some(selftest) = st.anchors.get(&Anchor::SelfTest)
        && !selftest.trim().is_empty()
        && selftest.trim() != policy::SELFTEST_RULE
    {
        problems.push("self-test anchor holds more than the probe rule".to_owned());
    }
    problems
}

/// Checks that hold between engine steps, given what the engine reports.
pub fn check_quiescent(
    st: &FakeState,
    reported: &KillSwitchState,
    session_endpoint: Option<SocketAddr>,
) -> Vec<String> {
    let mut problems = check_op(st);
    let Some(saved) = persisted(st) else {
        return problems;
    };
    let rules = st.kill_switch_rules();
    if !saved.armed && !rules.is_empty() {
        problems.push("I3: disarmed but the anchor is not empty".to_owned());
    }
    if saved.armed {
        let enforced = !rules.is_empty() && st.pf_enabled();
        let reported_error = matches!(reported, KillSwitchState::Error { .. });
        if !enforced && !reported_error {
            problems.push("armed, not enforced, and no error reported".to_owned());
        }
    }
    let (passes, _) = parse_rules(rules);
    let leftovers: BTreeSet<SocketAddr> = saved
        .journal
        .iter()
        .filter_map(|e| match &e.undo {
            crate::state::Undo::EndpointException { endpoint } => Some(*endpoint),
            crate::state::Undo::TunnelException { .. }
            | crate::state::Undo::WireGuard { .. }
            | crate::state::Undo::HostRoute { .. }
            | crate::state::Undo::NetRoute { .. }
            | crate::state::Undo::Dns => None,
        })
        .collect();
    for endpoint in &passes.endpoints {
        if Some(*endpoint) != session_endpoint && !leftovers.contains(endpoint) {
            problems.push(format!(
                "I1: {endpoint} passes but is neither current nor journaled"
            ));
        }
    }
    problems
}
