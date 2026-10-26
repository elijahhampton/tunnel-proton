//! `vpnuid doctor`: the pf self-test, which proves our anchor is actually evaluated on this OS.

use crate::platform::{Anchor, Platform};
use crate::policy::policy::SELFTEST_RULE;
use crate::state::PersistedState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfTest {
    Passed { before: u64, after: u64 },
    Failed(String),
    RefusedArmed,
    SkippedNoRoute,
}

/// Loads a temporary anchor that blocks only UDP to 192.0.2.1:9 (TEST-NET-1), sends one datagram
/// there, and checks that the rule's packet counter moved. Cleans up either way.
pub fn self_test<P: Platform>(p: &P) -> SelfTest {
    let armed = p
        .load_state()
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str::<PersistedState>(&json).ok())
        .is_some_and(|s| s.armed);
    if armed {
        return SelfTest::RefusedArmed;
    }
    match p.default_route() {
        Ok(Some(_)) => {}
        Ok(None) => return SelfTest::SkippedNoRoute,
        Err(e) => return SelfTest::Failed(e.to_string()),
    }

    let mut token = None;
    let result = (|| {
        if !p.pf_is_enabled().map_err(|e| e.to_string())? {
            token = Some(p.pf_enable().map_err(|e| e.to_string())?);
        }
        p.pf_load(Anchor::SelfTest, &format!("{SELFTEST_RULE}\n"))
            .map_err(|e| e.to_string())?;
        let before = p
            .pf_anchor_packets(Anchor::SelfTest)
            .map_err(|e| e.to_string())?;
        p.send_probe().map_err(|e| e.to_string())?;
        std::thread::sleep(std::time::Duration::from_millis(100));
        let after = p
            .pf_anchor_packets(Anchor::SelfTest)
            .map_err(|e| e.to_string())?;
        Ok::<_, String>((before, after))
    })();
    let _ = p.pf_flush(Anchor::SelfTest);
    if let Some(token) = token {
        let _ = p.pf_release(&token);
    }
    match result {
        Ok((before, after)) if after > before => SelfTest::Passed { before, after },
        Ok((before, after)) => SelfTest::Failed(format!(
            "the probe was not counted ({before} -> {after}); pf is not evaluating anchors under com.apple/"
        )),
        Err(e) => SelfTest::Failed(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::fake::FakePlatform;
    use crate::platform::Op;

    #[test]
    fn passes_when_the_anchor_is_evaluated_and_cleans_up() {
        let fake = FakePlatform::new();
        assert!(matches!(
            self_test(&fake),
            SelfTest::Passed {
                before: 0,
                after: 1
            }
        ));
        let st = fake.state();
        assert!(st.anchors.is_empty(), "temporary anchor removed");
        assert!(st.tokens.is_empty() && !st.pf_enabled(), "pf left as found");
    }

    #[test]
    fn refuses_when_armed_and_skips_without_a_route() {
        let fake = FakePlatform::new();
        fake.state().state_file = Some(r#"{"armed":true}"#.into());
        assert_eq!(self_test(&fake), SelfTest::RefusedArmed);
        assert!(!fake.state().ops.iter().any(|o| o.op == Op::PfLoad));

        let fake = FakePlatform::new();
        fake.set_default_route(None);
        assert_eq!(self_test(&fake), SelfTest::SkippedNoRoute);
    }

    #[test]
    fn fails_when_the_probe_is_not_counted() {
        let fake = FakePlatform::new();
        fake.state().failing.insert(Op::Probe);
        assert!(matches!(self_test(&fake), SelfTest::Failed(_)));
        assert!(fake.state().anchors.is_empty());
    }
}
