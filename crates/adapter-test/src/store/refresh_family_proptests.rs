//! **RFC 118 T2/T3** — the refresh-family lifecycle, held to its reference model
//! by generated adversarial sequences.
//!
//! Each generated sequence is applied, operation by operation, to the pure
//! model (`cesauth_core::ports::store::family_model`, the normative description
//! of the lifecycle) and to [`InMemoryRefreshTokenFamilyStore`] in lockstep. After
//! **every** operation the test compares
//!
//! * the **outcome** — `Rotated`, `AlreadyRevoked`, `ReusedAndRevoked` (with its
//!   `was_retired` label) and `Expired(kind)`, plus `init`'s `Conflict` and
//!   `revoke`'s success; and
//! * the **whole post-state** read back with `peek`: current jti, the retired
//!   ring's contents and order, `created_at`, `last_rotated_at`, `revoked_at`,
//!   the reuse forensics, `expired`, and the immutable fields. Two stores can
//!   return the same outcome and leave different state; comparing outcomes alone
//!   would not see it.
//!
//! The generator is adversarial by construction: replaying a retired jti, a jti
//! that has been **evicted past the 16-entry ring**, an invented jti, rotating
//! after an explicit revoke, `init` on an existing id, clock jumps across both
//! deadlines, and a **different lifetime policy on every rotation** (lowering it
//! must shorten a live family, RFC 139 §9.2). To reach the cap it produces a
//! prefix of up to 40 quiet rotations before the adversarial tail: any reuse ends
//! a family, so random operations alone almost never make 17 rotations.
//!
//! **The coverage test** draws a fixed seeded sample from the same strategy and
//! fails if any category goes rare, so a regression in the generator is loud
//! rather than silently vacuous. `-- --nocapture` prints the proportions.
//!
//! **Sequences, not threads.** "Any interleaving" is any *order* of operations on
//! one family, single-threaded. The in-memory store is what runs here; the
//! Durable Object is not host-testable, so **nothing in this file verifies the
//! Durable Object**, and it proves nothing about concurrency.
//!
//! **Not generated:** `rotate`/`revoke` on an id that was never initialised. The
//! port states it (`NotFound`; `peek` is `None`) and the model's
//! `apply_to_absent` is the rule, pinned by an example test and a store contract
//! test (`store/tests.rs`). Representing an absent family in the op sequence would
//! restructure every sequence for a case those two tests cover completely.

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

use cesauth_core::ports::PortError;
use cesauth_core::ports::store::family_model::{FamilyModel, ModelOutcome, Op as ModelOp, RETIRED_RING_CAP};
use cesauth_core::ports::store::{
    FamilyInit, FamilyState, LifetimeExpiry, RefreshLifetime, RefreshTokenFamilyStore, RotateOutcome,
};
use cesauth_core::types::{ClientId, FamilyId, Jti, UserId};

use super::InMemoryRefreshTokenFamilyStore;

const START: i64 = 1_000;

/// Which jti a `Rotate` presents.
#[derive(Debug, Clone)]
enum Presented {
    /// The family's current jti (the legitimate refresh).
    Current,
    /// The `back`-th most recent rotated-out jti, counting from the newest and
    /// wrapping. `back >= 16` reaches jtis the ring has evicted.
    Replay { back: usize },
    /// A jti this family never issued.
    Unknown,
}

#[derive(Debug, Clone)]
enum Op {
    /// The policy is per call, and `idle <= absolute` by construction.
    Rotate { presented: Presented, absolute: i64, idle: i64 },
    Revoke,
    /// `init` on the existing id, with different contents.
    Init,
    Advance { by: i64 },
}

/// A policy far from any deadline, so quiet rotations do not expire.
const WIDE: (i64, i64) = (100_000, 50_000);

/// Half the time a wide policy; otherwise a narrow one that the tail's clock
/// jumps can cross, with the idle window usually shorter than the absolute cap.
fn policy() -> impl Strategy<Value = (i64, i64)> {
    prop_oneof![
        5 => Just(WIDE),
        5 => (30i64..=250).prop_flat_map(|a| (
            Just(a),
            prop_oneof![1 => Just(0i64), 3 => 5i64..=a / 2, 1 => a / 2..=a],
        )),
    ]
}

fn presented() -> impl Strategy<Value = Presented> {
    prop_oneof![
        6 => Just(Presented::Current),
        4 => (0usize..40).prop_map(|back| Presented::Replay { back }),
        2 => Just(Presented::Unknown),
    ]
}

fn advance() -> impl Strategy<Value = i64> {
    prop_oneof![6 => 0i64..=12, 3 => 13i64..=100, 1 => 101i64..=400]
}

fn tail_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => (presented(), policy()).prop_map(|(p, (a, i))| Op::Rotate { presented: p, absolute: a, idle: i }),
        1 => Just(Op::Revoke),
        1 => Just(Op::Init),
        6 => advance().prop_map(|by| Op::Advance { by }),
    ]
}

/// A prefix of quiet rotations (so the ring can fill and overflow), then the
/// adversarial tail.
fn scenario() -> impl Strategy<Value = Vec<Op>> {
    (0usize..=40, prop::collection::vec(tail_op(), 1..=25)).prop_map(|(prefix, tail)| {
        let mut ops = Vec::new();
        for _ in 0..prefix {
            ops.push(Op::Advance { by: 1 });
            ops.push(Op::Rotate { presented: Presented::Current, absolute: WIDE.0, idle: WIDE.1 });
        }
        ops.extend(tail);
        ops
    })
}

fn family_id() -> FamilyId { FamilyId::from_storage("fam") }

fn family_init(first: &str, now: i64, auth_time: i64) -> FamilyInit {
    FamilyInit {
        family_id: family_id(),
        user_id:   UserId::from_storage("u"),
        client_id: ClientId::from_storage("c"),
        scopes:    vec!["openid".to_owned()],
        first_jti: Jti::from_storage(first),
        now_unix:  now,
        auth_time,
    }
}

/// What one run reached. Each category is a **flag per sequence** (1 if the
/// sequence produced it at least once), so summing runs gives "the number of
/// sequences that reached it". A share of *rotate operations* would be dominated
/// by the quiet prefix, which exists only to fill the ring.
#[derive(Debug, Default, Clone, Copy)]
struct Stats {
    rotate_ops:            u64, // a count, kept for reference only
    rotated:               u64,
    replay_in_ring:        u64, // ReusedAndRevoked, was_retired = true
    replay_evicted:        u64, // a jti this family issued but the ring dropped: was_retired = false
    unknown_reuse:         u64, // a jti never issued: was_retired = false
    after_explicit_revoke: u64, // AlreadyRevoked, family revoked by `revoke`
    after_other_revoke:    u64, // AlreadyRevoked, family revoked by reuse or expiry
    expired_absolute:      u64,
    expired_idle:          u64,
    idle_after_rotations:  u64, // Expired(Idle) on a family that had been kept alive by rotating
    init_conflicts:        u64,
    sequences:             u64,
    crossed_the_cap:       u64, // the ring reached its cap
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.rotate_ops += o.rotate_ops; self.rotated += o.rotated;
        self.replay_in_ring += o.replay_in_ring; self.replay_evicted += o.replay_evicted;
        self.unknown_reuse += o.unknown_reuse; self.after_explicit_revoke += o.after_explicit_revoke;
        self.after_other_revoke += o.after_other_revoke; self.expired_absolute += o.expired_absolute;
        self.expired_idle += o.expired_idle; self.idle_after_rotations += o.idle_after_rotations;
        self.init_conflicts += o.init_conflicts; self.sequences += o.sequences;
        self.crossed_the_cap += o.crossed_the_cap;
    }
}

macro_rules! ensure {
    ($c:expr, $($arg:tt)+) => { if !($c) { return Err(format!($($arg)+)); } };
}

fn as_model(o: RotateOutcome) -> ModelOutcome {
    match o {
        RotateOutcome::Rotated { new_current_jti }      => ModelOutcome::Rotated { new_current_jti },
        RotateOutcome::AlreadyRevoked                   => ModelOutcome::AlreadyRevoked,
        RotateOutcome::ReusedAndRevoked { reused_jti, was_retired } =>
            ModelOutcome::ReusedAndRevoked { reused_jti, was_retired },
        RotateOutcome::Expired(kind)                    => ModelOutcome::Expired(kind),
    }
}

/// The whole post-state, compared field by field so a failure names the field.
fn compare_state(got: &FamilyState, want: &FamilyState, when: &str) -> Result<(), String> {
    macro_rules! same { ($f:ident) => {
        ensure!(got.$f == want.$f, "{when}: `{}` differs: store {:?}, model {:?}", stringify!($f), got.$f, want.$f);
    } }
    same!(family_id); same!(user_id); same!(client_id); same!(scopes); same!(auth_time);
    same!(current_jti); same!(retired_jtis);
    same!(created_at); same!(last_rotated_at); same!(revoked_at);
    same!(reused_jti); same!(reused_at); same!(reuse_was_retired);
    same!(expired);
    Ok(())
}

fn run(ops: &[Op]) -> Result<Stats, String> {
    let rt = tokio::runtime::Builder::new_current_thread().build().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let store = InMemoryRefreshTokenFamilyStore::default();
        let first = family_init("j0", START, 1_234);
        store.init(&first).await.map_err(|e| format!("init: {e:?}"))?;
        let mut model = FamilyModel::new(&first);

        // Bookkeeping the model does not need: every jti that has been rotated
        // out, oldest first, so `Replay` can name jtis the ring has dropped.
        let mut history: Vec<Jti> = Vec::new();
        let (mut clock, mut n) = (START, 0u64);
        let (mut st, mut successes, mut explicit_revoke) = (Stats { sequences: 1, ..Stats::default() }, 0u32, false);

        macro_rules! check { ($when:expr) => {{
            let got = store.peek(&family_id()).await.map_err(|e| format!("peek: {e:?}"))?
                .ok_or_else(|| format!("{}: the family vanished", $when))?;
            compare_state(&got, model.state(), &$when)?;
        }} }
        check!("after init");

        for (i, op) in ops.iter().enumerate() {
            match op {
                Op::Advance { by } => clock += by,

                Op::Init => {
                    n += 1;
                    let again = family_init(&format!("re-init-{n}"), clock, 9_000 + n as i64);
                    let res  = store.init(&again).await;
                    let want = model.apply(&ModelOp::Init(again), clock);
                    ensure!(matches!(res, Err(PortError::Conflict)) && want == ModelOutcome::Conflict,
                        "op {i} init on an existing id: store {res:?}, model {want:?}");
                    st.init_conflicts = 1;
                    check!(format!("op {i} (init conflict)"));
                }

                Op::Revoke => {
                    let res  = store.revoke(&family_id(), clock).await;
                    let was_live = model.state().revoked_at.is_none();
                    let want = model.apply(&ModelOp::Revoke, clock);
                    ensure!(res.is_ok() && want == ModelOutcome::Revoked, "op {i} revoke: store {res:?}, model {want:?}");
                    if was_live { explicit_revoke = true; }
                    check!(format!("op {i} (revoke)"));
                }

                Op::Rotate { presented, absolute, idle } => {
                    let lifetime = RefreshLifetime::new(*absolute, *idle).map_err(|e| e.to_string())?;
                    n += 1;
                    let invented = || Jti::from_storage(format!("invented-{n}"));
                    let (presented_jti, was_issued) = match presented {
                        Presented::Current => (model.state().current_jti.clone(), true),
                        Presented::Unknown => (invented(), false),
                        Presented::Replay { back } if history.is_empty() => { let _ = back; (invented(), false) }
                        Presented::Replay { back } => (history[history.len() - 1 - back % history.len()].clone(), true),
                    };
                    let new = Jti::from_storage(format!("j{n}"));
                    let was_dead = model.state().revoked_at.is_some();

                    let got  = store.rotate(&family_id(), &presented_jti, &new, clock, &lifetime).await
                        .map_err(|e| format!("op {i} rotate: {e:?}"))?;
                    let want = model.apply(
                        &ModelOp::Rotate { presented: presented_jti.clone(), new: new.clone(), lifetime }, clock);
                    let got = as_model(got);
                    ensure!(got == want, "op {i} rotate at {clock} presenting {presented_jti:?} under ({absolute},{idle}): store {got:?}, model {want:?}");

                    st.rotate_ops += 1;
                    match &want {
                        ModelOutcome::Rotated { .. } => {
                            st.rotated = 1; successes += 1; history.push(presented_jti);
                        }
                        ModelOutcome::ReusedAndRevoked { was_retired: true, .. }  => st.replay_in_ring = 1,
                        ModelOutcome::ReusedAndRevoked { was_retired: false, .. } if was_issued => st.replay_evicted = 1,
                        ModelOutcome::ReusedAndRevoked { was_retired: false, .. } => st.unknown_reuse = 1,
                        ModelOutcome::AlreadyRevoked if was_dead && explicit_revoke => st.after_explicit_revoke = 1,
                        ModelOutcome::AlreadyRevoked => st.after_other_revoke = 1,
                        ModelOutcome::Expired(LifetimeExpiry::Absolute) => st.expired_absolute = 1,
                        ModelOutcome::Expired(LifetimeExpiry::Idle) => {
                            st.expired_idle = 1;
                            if successes > 0 { st.idle_after_rotations = 1; }
                        }
                        other => return Err(format!("op {i}: model returned {other:?} for a rotate")),
                    }
                    check!(format!("op {i} (rotate -> {want:?})"));
                }
            }
        }
        if model.state().retired_jtis.len() == RETIRED_RING_CAP { st.crossed_the_cap = 1; }
        Ok(st)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The in-memory store agrees with the reference model, in outcome and in
    /// post-state, after every operation of every generated sequence.
    #[test]
    fn refresh_family_store_matches_the_model(ops in scenario()) {
        run(&ops).map_err(TestCaseError::fail)?;
    }
}

/// Draws a fixed, seeded sample from [`scenario`] and fails if any category the
/// property is meant to exercise goes rare. `-- --nocapture` prints the
/// proportions.
#[test]
fn the_generator_reaches_every_category_including_the_ring_boundary() {
    let (mut runner, strat) = (TestRunner::deterministic(), scenario());
    let mut t = Stats::default();
    for _ in 0..1_000 {
        let ops = strat.new_tree(&mut runner).expect("generate").current();
        t.add(&run(&ops).expect("every generated sequence agrees with the model"));
    }
    let of = |n: u64| 100.0 * n as f64 / t.sequences as f64;
    println!("RFC 118 T3 coverage over {} generated sequences ({} rotate operations in all):", t.sequences, t.rotate_ops);
    println!("  share of SEQUENCES that reached each event at least once:");
    let row = |label: &str, n: u64| println!("    {label:<48} {n:>5}  {:5.1}%", of(n));
    row("a successful rotation", t.rotated);
    row("replay of a retired jti still in the ring", t.replay_in_ring);
    row("replay of a jti EVICTED past the cap", t.replay_evicted);
    row("a jti never issued", t.unknown_reuse);
    row("rotate after an explicit revoke", t.after_explicit_revoke);
    row("rotate after a reuse/expiry revocation", t.after_other_revoke);
    row("Expired(Absolute)", t.expired_absolute);
    row("Expired(Idle)", t.expired_idle);
    row("  ... of a family kept alive by rotating", t.idle_after_rotations);
    row("init on an existing id -> Conflict", t.init_conflicts);
    row(&format!("the ring reached its cap of {RETIRED_RING_CAP}"), t.crossed_the_cap);

    assert!(of(t.rotated)               >= THRESHOLDS.rotated,         "successful rotations are rare");
    assert!(of(t.replay_in_ring)        >= THRESHOLDS.in_ring,         "in-ring replays are rare");
    assert!(of(t.replay_evicted)        >= THRESHOLDS.evicted,         "evicted-jti replays are rare: the cap boundary is barely exercised (RFC 118 §16.2)");
    assert!(of(t.unknown_reuse)         >= THRESHOLDS.unknown,         "invented-jti rotations are rare");
    assert!(of(t.after_explicit_revoke) >= THRESHOLDS.after_explicit,  "rotations after an explicit revoke are rare");
    assert!(of(t.after_other_revoke)    >= THRESHOLDS.after_other,     "rotations after a reuse/expiry revocation are rare");
    assert!(of(t.expired_absolute)      >= THRESHOLDS.absolute,        "absolute expiries are rare");
    assert!(of(t.expired_idle)          >= THRESHOLDS.idle,            "idle expiries are rare");
    assert!(of(t.idle_after_rotations)  >= THRESHOLDS.idle_kept_alive, "idle expiries of a kept-alive family are rare");
    assert!(of(t.init_conflicts)        >= THRESHOLDS.init_conflict,   "init conflicts are rare");
    assert!(of(t.crossed_the_cap)       >= THRESHOLDS.cap_sequences,   "too few sequences reach the ring's cap");
}

/// Minimum share of sequences that reach each event, as a percentage.
///
/// **A threshold exists to catch a generator regression, not to ratify today's
/// numbers.** So it is set well below the measured share, and it is neither
/// tightened to match it (the test would then fail on ordinary seed drift, and
/// teach whoever meets it to lower the bar) nor lowered to make a run pass: if a
/// category has gone rare, fix the generator.
struct Thresholds {
    rotated: f64, in_ring: f64, evicted: f64, unknown: f64, after_explicit: f64, after_other: f64,
    absolute: f64, idle: f64, idle_kept_alive: f64, init_conflict: f64, cap_sequences: f64,
}
///
/// Measured over the seeded 1,000-sequence sample (RFC 118 T3): rotated 98.9,
/// in-ring 31.0, evicted 9.3, unknown 23.2, after-explicit 13.2, after-other
/// 70.2, absolute 8.7, idle 4.8, idle-kept-alive 4.7, init-conflict 53.2, cap 64.9.
const THRESHOLDS: Thresholds = Thresholds {
    rotated: 90.0, in_ring: 15.0, evicted: 4.0, unknown: 10.0, after_explicit: 6.0, after_other: 35.0,
    absolute: 4.0, idle: 2.0, idle_kept_alive: 2.0, init_conflict: 25.0, cap_sequences: 30.0,
};
