//! Originally part of `crates/core/src/totp/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;

// verify_with_replay_protection
// =====================================================================

#[test]
fn verify_accepts_current_step() {
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let code = compute_code(&s, step);

    let result = verify_with_replay_protection(&s, code, 0, now).unwrap();
    assert_eq!(result, step);
}

#[test]
fn verify_accepts_previous_step_within_skew() {
    // User typed the code right at a step boundary; by the time
    // the request reaches the Worker the step has advanced.
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let prev_code = compute_code(&s, step - 1);

    let result = verify_with_replay_protection(&s, prev_code, 0, now).unwrap();
    assert_eq!(result, step - 1);
}

#[test]
fn verify_accepts_next_step_within_skew() {
    // User's clock runs ahead of the Worker's clock by ~30s.
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let next_code = compute_code(&s, step + 1);

    let result = verify_with_replay_protection(&s, next_code, 0, now).unwrap();
    assert_eq!(result, step + 1);
}

#[test]
fn verify_rejects_step_outside_skew() {
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    // Two steps back — outside ±SKEW_STEPS.
    let stale_code = compute_code(&s, step - 2);

    let result = verify_with_replay_protection(&s, stale_code, 0, now);
    assert_eq!(result, Err(TotpError::InvalidCode));
}

#[test]
fn verify_rejects_replay_within_window() {
    // First verify succeeds → returns last_used_step.
    // Second verify with the same code and the persisted
    // last_used_step should fail (replay protection).
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let code = compute_code(&s, step);

    let last_used = verify_with_replay_protection(&s, code, 0, now).unwrap();
    assert_eq!(last_used, step);

    // Same code, same now, but last_used_step is now `step`.
    let replay = verify_with_replay_protection(&s, code, last_used, now);
    assert_eq!(replay, Err(TotpError::InvalidCode));
}

#[test]
fn verify_advances_to_latest_matching_step() {
    // Edge case: the verify flow walks -1..=+1 windows. If only
    // one matches, we land on that. Pin that the returned step
    // is the matched step, not e.g. the current step.
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let prev_code = compute_code(&s, step - 1);

    let result = verify_with_replay_protection(&s, prev_code, 0, now).unwrap();
    assert_eq!(result, step - 1, "should record the matched step, not the current one");
}

#[test]
fn verify_rejects_random_code() {
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;

    // 000000 is a valid code, but very unlikely to be the
    // current/adjacent code for a random secret. ~1/3*10^6
    // chance of false-success which we accept as an
    // astronomically rare flake.
    let result = verify_with_replay_protection(&s, 999_999, 0, now);
    let result2 = verify_with_replay_protection(&s, 0, 0, now);
    // At least one of these MUST be rejected (probability of
    // both matching: 1/10^12, negligible).
    assert!(result.is_err() || result2.is_err());
}

#[test]
fn verify_rejects_already_used_step_even_if_within_window() {
    // last_used_step is the current step. None of the three
    // skew-window candidates (step-1, step, step+1) should be
    // accepted: step-1 and step are ≤ last_used (rejected by
    // replay gate), and step+1 yields a different code than
    // the current step's code.
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let code_at_step = compute_code(&s, step);

    let result = verify_with_replay_protection(&s, code_at_step, step, now);
    assert_eq!(result, Err(TotpError::InvalidCode));
}

// =====================================================================
