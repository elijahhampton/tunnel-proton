use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Stable server identifier, e.g. `ch-zrh-012`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerId(String);

impl ServerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Client-chosen correlation id echoed back in the matching [`crate::Response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub u64);

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolVersion(pub u32);

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Wall-clock time as milliseconds since the Unix epoch.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct UnixMillis(pub u64);

impl UnixMillis {
    pub fn now() -> Self {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Self(u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX))
    }

    /// Time elapsed from `earlier` to `self`, zero if `earlier` is in the future.
    pub fn since(self, earlier: Self) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }

    /// Time remaining from `self` until `later`, zero if `later` has passed.
    pub fn until(self, later: Self) -> Duration {
        later.since(self)
    }

    pub fn plus(self, duration: Duration) -> Self {
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(millis))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_and_until_saturate() {
        let a = UnixMillis(1_000);
        let b = UnixMillis(3_500);
        assert_eq!(b.since(a), Duration::from_millis(2_500));
        assert_eq!(a.since(b), Duration::ZERO);
        assert_eq!(a.until(b), Duration::from_millis(2_500));
        assert_eq!(a.plus(Duration::from_secs(2)), UnixMillis(3_000));
    }
}
