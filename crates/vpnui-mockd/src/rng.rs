use std::time::Duration;

/// SplitMix64. Deterministic for a given seed across platforms and releases.
#[derive(Debug, Clone)]
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `lo..=hi`. Modulo bias is irrelevant at these ranges.
    pub(crate) fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo + 1)
    }

    /// Uniform in `[0, 1)`.
    pub(crate) fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub(crate) fn chance(&mut self, probability: f64) -> bool {
        self.unit() < probability
    }

    /// Uniform in `-magnitude..=magnitude`.
    pub(crate) fn jitter(&mut self, magnitude: i64) -> i64 {
        let span = magnitude.unsigned_abs();
        self.range(0, span * 2) as i64 - magnitude.abs()
    }

    pub(crate) fn millis(&mut self, lo: u64, hi: u64) -> Duration {
        Duration::from_millis(self.range(lo, hi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn ranges_stay_in_bounds() {
        let mut rng = Rng::new(7);
        for _ in 0..10_000 {
            assert!((5..=95).contains(&rng.range(5, 95)));
            assert!((-3..=3).contains(&rng.jitter(3)));
            let u = rng.unit();
            assert!((0.0..1.0).contains(&u));
        }
    }
}
