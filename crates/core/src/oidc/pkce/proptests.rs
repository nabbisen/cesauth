//! **RFC 117 T5** — property tests for `pkce::verify` under S256.
//!
//! There were no PKCE property tests before this (RFC 117 §2b.2); `tests.rs` holds
//! example tests only.
//!
//! The property, stated exactly: for a verifier `v` and challenge `c`,
//!
//! ```text
//! verify(v, c, S256) is Ok   <=>   43 <= v.len() <= 128   AND   c == base64url_nopad(sha256(v))
//! ```
//!
//! The length window is RFC 7636 §4.1 and is part of the contract: a matching
//! pair with a verifier outside it is refused. Both halves of the "iff" need
//! inputs that exercise them, so mismatches are generated in eight distinct
//! ways, not left to random noise (which would essentially never come close to a
//! match). [`the_generator_produces_both_matching_and_each_kind_of_mismatching_case`]
//! measures that and fails if a kind goes missing.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use sha2::{Digest, Sha256};

use super::{verify, ChallengeMethod};

/// The independent oracle: base64url without padding of the SHA-256 digest.
fn expected(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn legal_length(v: &str) -> bool { (43..=128).contains(&v.len()) }

/// A verifier whose byte length is inside 43..=128: the RFC's unreserved
/// alphabet, and multi-byte characters (2 bytes each, so 44..=120 bytes).
fn legal_verifier() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => "[A-Za-z0-9._~-]{43,128}",
        1 => "[\u{a1}-\u{7ff}]{22,60}",
    ]
}

/// A verifier whose byte length is outside the window, on both sides of it.
fn illegal_verifier() -> impl Strategy<Value = String> {
    prop_oneof!["[A-Za-z0-9._~-]{0,42}", "[A-Za-z0-9._~-]{129,200}"]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Correct,        // c == oracle(v)
    OneCharChanged, // the oracle with one character replaced
    Truncated,      // the oracle minus its last character
    Extended,       // the oracle plus a character
    StandardPadded, // the *standard*-alphabet, padded encoding of the same digest
    OtherVerifier,  // the oracle for a different verifier
    Arbitrary,      // any string
    Empty,          // the empty string
}

const KINDS: [Kind; 8] = [
    Kind::Correct, Kind::OneCharChanged, Kind::Truncated, Kind::Extended,
    Kind::StandardPadded, Kind::OtherVerifier, Kind::Arbitrary, Kind::Empty,
];

/// A (verifier, challenge, how the challenge was made) case.
fn case() -> impl Strategy<Value = (String, String, Kind)> {
    (legal_verifier(), prop::sample::select(KINDS.to_vec()), any::<usize>(),
     "[A-Za-z0-9._~-]{43,128}", any::<String>())
        .prop_map(|(v, kind, idx, other, arbitrary)| {
            let good = expected(&v);
            let c = match kind {
                Kind::Correct => good,
                Kind::OneCharChanged => {
                    let mut cs: Vec<char> = good.chars().collect();
                    let i = idx % cs.len();
                    cs[i] = if cs[i] == 'A' { 'B' } else { 'A' };
                    cs.into_iter().collect()
                }
                Kind::Truncated => good[..good.len() - 1].to_owned(),
                Kind::Extended => format!("{good}A"),
                Kind::StandardPadded => STANDARD.encode(Sha256::digest(v.as_bytes())),
                Kind::OtherVerifier => {
                    let o = if other == v { format!("{other}x") } else { other };
                    expected(&o)
                }
                Kind::Arbitrary => arbitrary,
                Kind::Empty => String::new(),
            };
            (v, c, kind)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// For a verifier of legal length, `verify` succeeds exactly when the
    /// challenge is the S256 of it. The oracle is `c == expected(v)`, not the
    /// generator's label, so a coincidental match is still judged correctly.
    #[test]
    fn verify_succeeds_iff_the_challenge_is_the_s256_of_the_verifier((v, c, _kind) in case()) {
        prop_assert_eq!(verify(&v, &c, ChallengeMethod::S256).is_ok(), c == expected(&v));
    }

    /// The length window is part of the contract: a verifier outside 43..=128
    /// bytes is refused even when the challenge is exactly its S256.
    #[test]
    fn verify_refuses_an_illegal_length_verifier_even_with_the_right_challenge(v in illegal_verifier()) {
        prop_assert!(!legal_length(&v));
        prop_assert!(verify(&v, &expected(&v), ChallengeMethod::S256).is_err());
    }

    /// The whole statement at once, over any string as verifier.
    #[test]
    fn verify_is_ok_iff_legal_length_and_matching_challenge(v in any::<String>(), c in any::<String>(), use_right in any::<bool>()) {
        let c = if use_right { expected(&v) } else { c };
        prop_assert_eq!(
            verify(&v, &c, ChallengeMethod::S256).is_ok(),
            legal_length(&v) && c == expected(&v),
        );
    }
}

/// §7.6 — a property test whose generator only produces matching pairs, or only
/// hopeless mismatches, proves nothing. Draws a fixed, seeded sample from
/// [`case`] and fails if matches are rare or any mismatch kind is missing.
/// `-- --nocapture` prints the measured proportions.
#[test]
fn the_generator_produces_both_matching_and_each_kind_of_mismatching_case() {
    use std::collections::HashMap;
    let (mut runner, strat) = (TestRunner::deterministic(), case());
    let (mut by_kind, mut matched, mut n) = (HashMap::<Kind, u32>::new(), 0u32, 0u32);
    for _ in 0..4000 {
        let (v, c, kind) = strat.new_tree(&mut runner).expect("generate").current();
        *by_kind.entry(kind).or_default() += 1;
        if c == expected(&v) { matched += 1; }
        n += 1;
    }
    let mismatched = n - matched;
    let pct = |x: u32| 100.0 * x as f64 / n as f64;
    println!("RFC 117 T5 coverage over {n} generated (verifier, challenge) cases:");
    println!("  matching   (c == sha256-b64url(v))  {matched:>5}  {:5.1}%", pct(matched));
    println!("  mismatching                         {mismatched:>5}  {:5.1}%", pct(mismatched));
    for k in KINDS { println!("    {:<16} generated {:>5}  {:5.1}%", format!("{k:?}"), by_kind.get(&k).copied().unwrap_or(0), pct(by_kind.get(&k).copied().unwrap_or(0))); }

    assert!(pct(matched)    >= 8.0,  "matching pairs are rare: the success half of the iff is barely exercised");
    assert!(pct(mismatched) >= 60.0, "mismatching pairs are rare: the failure half of the iff is barely exercised");
    for k in KINDS {
        assert!(by_kind.get(&k).copied().unwrap_or(0) as f64 >= 0.04 * n as f64, "kind {k:?} is under-generated");
    }
}
