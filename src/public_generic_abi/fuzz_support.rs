//! Shared deterministic bounded mutation engine for issue #173's bounded
//! property/fuzz coverage of the descriptor and carrier reference codecs
//! (implementation-sequence item 7: "Add property/fuzz generation within
//! hard byte/depth/node bounds and persist minimized reproductions for any
//! discovered distinct invariant").
//!
//! There is no `proptest`/`quickcheck` dependency in this workspace, and
//! adding one edits `Cargo.toml`, which is off a bounded worker's file
//! lease. This hand-rolled fixed-seed `xorshift64*` generator covers the
//! same requirement without one: every trial is a pure function of its
//! index, so a run is byte-for-byte reproducible on every machine and every
//! `cargo test` invocation -- there is nothing to "flake" and nothing to
//! seed from wall-clock entropy. Every bound below is a hard, named
//! constant, matching #173's explicit exclusion of "unbounded fuzzing" from
//! scope: a fixed trial count, a fixed maximum point-mutation count, and a
//! fixed maximum length delta.

/// A minimal `xorshift64*` PRNG. Not cryptographic; only used to pick
/// deterministic mutation offsets and length deltas.
pub(crate) struct Rng(u64);

impl Rng {
    /// `xorshift64*` requires a nonzero state.
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn next_below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

/// How many deterministic trials each bounded fuzz harness runs.
pub(crate) const TRIALS: usize = 500;
/// The most point mutations (single-byte flips) any one trial applies.
pub(crate) const MAX_POINT_MUTATIONS: usize = 4;
/// The largest truncation or extension any one trial applies, in bytes.
pub(crate) const MAX_LENGTH_DELTA: usize = 16;

/// Deterministically mutate `baseline` for trial `trial_index`
/// (`0..TRIALS`): one to [`MAX_POINT_MUTATIONS`] single-byte flips at
/// pseudo-random offsets, then with 1-in-4 odds either a bounded truncation
/// or a bounded extension with pseudo-random bytes -- never past
/// [`MAX_LENGTH_DELTA`] in either direction. The same `trial_index` always
/// produces the same bytes, on any host, forever: the seed is derived from
/// `trial_index` alone.
pub(crate) fn mutate(baseline: &[u8], trial_index: usize) -> Vec<u8> {
    let mut rng =
        Rng::new(0xC0FF_EE00_u64 ^ (trial_index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut bytes = baseline.to_vec();
    if !bytes.is_empty() {
        let mutations = 1 + rng.next_below(MAX_POINT_MUTATIONS);
        for _ in 0..mutations {
            let at = rng.next_below(bytes.len());
            bytes[at] = rng.next_byte();
        }
    }
    match rng.next_below(4) {
        0 if bytes.len() > 1 => {
            let cut = 1 + rng.next_below(MAX_LENGTH_DELTA.min(bytes.len() - 1));
            bytes.truncate(bytes.len() - cut);
        }
        1 => {
            let extra = 1 + rng.next_below(MAX_LENGTH_DELTA);
            for _ in 0..extra {
                bytes.push(rng.next_byte());
            }
        }
        _ => {}
    }
    bytes
}

/// Render `bytes` as a pasteable Rust byte-slice literal -- #173's
/// "persist minimized reproductions for any discovered distinct
/// invariant". A minimized reproduction here is a literal a human copies
/// directly into a new pinned `#[test]`, not a saved file: the mutation
/// engine above is already minimal (a handful of point edits over a small
/// fixture), so there is no larger counterexample to shrink first.
pub(crate) fn minimized_repro_literal(bytes: &[u8]) -> String {
    let mut out = String::from("&[");
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!("0x{byte:02x}"));
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutate_is_a_pure_function_of_the_trial_index() {
        let baseline = b"the quick brown fox jumps over the lazy dog".to_vec();
        for trial in 0..TRIALS {
            assert_eq!(
                mutate(&baseline, trial),
                mutate(&baseline, trial),
                "trial {trial} must be reproducible"
            );
        }
    }

    #[test]
    fn mutate_respects_the_hard_length_delta_bound() {
        let baseline = b"the quick brown fox jumps over the lazy dog".to_vec();
        for trial in 0..TRIALS {
            let mutated = mutate(&baseline, trial);
            let delta = (mutated.len() as isize - baseline.len() as isize).unsigned_abs();
            assert!(
                delta <= MAX_LENGTH_DELTA,
                "trial {trial} moved length by {delta}, over the {MAX_LENGTH_DELTA}-byte bound"
            );
        }
    }

    #[test]
    fn different_trials_are_not_all_identical() {
        let baseline = b"the quick brown fox jumps over the lazy dog".to_vec();
        let distinct: std::collections::BTreeSet<Vec<u8>> =
            (0..TRIALS).map(|trial| mutate(&baseline, trial)).collect();
        assert!(
            distinct.len() > TRIALS / 2,
            "the mutation engine is not exploring a varied space: only {} distinct outputs across {TRIALS} trials",
            distinct.len()
        );
    }

    #[test]
    fn minimized_repro_literal_renders_a_pasteable_byte_array() {
        assert_eq!(
            minimized_repro_literal(&[0x00, 0xff, 0x0a]),
            "&[0x00,0xff,0x0a]"
        );
        assert_eq!(minimized_repro_literal(&[]), "&[]");
    }
}
