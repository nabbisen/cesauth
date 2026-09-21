//! **RFC 117 T4** — a state-machine property test for the `AuthChallengeStore`
//! contract, run against the in-memory store.
//!
//! Generated sequences of `Put`, `Peek`, `Take`, `Bump` and `Advance` (a
//! monotonic clock) are applied to the store and to a small reference model, and
//! every result is compared. The contract's clauses (`ports/store.rs`, as RFC 140
//! states them) are asserted on every step:
//!
//! 1. **No overwrite.** `put` on an occupied handle is `Conflict` and leaves the
//!    stored value unchanged.
//! 2. **At most one successful `take` per put**, across any interleaving of the
//!    generated operations.
//! 3. **Expiry is absence.** At `now >= expires_at`: `peek` is `None` and does not
//!    delete, `take` is `None` **and removes the entry**, `bump` is `NotFound`.
//! 4. **A successful `take` implies a prior `put` of that value.** Nothing is
//!    invented: the value returned is the one put.
//!
//! The store holds no clock (RFC 140), so `Advance` is a number the test passes
//! to the operations. Expiry times are generated both ahead of and *behind* it,
//! so expired handles occur by construction and not by luck; the coverage test
//! below fails if the generator stops producing them.
//!
//! **Occupied means physically present.** A `put` onto an entry that is expired
//! but was never taken is `Conflict`. The port contract states this (C1-117), and
//! the model mirrors it.
//!
//! **Sequences, not threads.** "Any interleaving" here is any order of operations
//! across the four handles. The in-memory store is `Mutex`-guarded and this test
//! is single-threaded; the Durable Object is not host-testable.

use std::collections::{HashMap, HashSet};

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

use cesauth_core::ports::PortError;
use cesauth_core::ports::store::{AuthChallengeStore, Challenge};
use cesauth_core::types::{ChallengeHandle, Scopes};

use super::InMemoryAuthChallengeStore;

const HANDLES:     usize = 4;
const START_CLOCK: i64   = 100;

#[derive(Debug, Clone)]
enum Op {
    /// `expires_at = clock + ttl`; a `ttl <= 0` is expired the moment it is put.
    Put { h: usize, magic: bool, ttl: i64 },
    Peek { h: usize },
    Take { h: usize },
    Bump { h: usize },
    Advance { by: i64 },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..HANDLES, any::<bool>(), -5i64..=25).prop_map(|(h, magic, ttl)| Op::Put { h, magic, ttl }),
        3 => (0..HANDLES).prop_map(|h| Op::Peek { h }),
        3 => (0..HANDLES).prop_map(|h| Op::Take { h }),
        2 => (0..HANDLES).prop_map(|h| Op::Bump { h }),
        4 => (0i64..=12).prop_map(|by| Op::Advance { by }),
    ]
}

fn ops_strategy() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(op_strategy(), 1..=60)
}

fn handle(h: usize) -> ChallengeHandle { ChallengeHandle::from_storage(format!("h{h}")) }

/// A challenge whose identity (`v<seq>`) is unique per put, so a `take` can be
/// matched to the put it came from (clause 4).
fn challenge(seq: u64, magic: bool, expires_at: i64) -> Challenge {
    let id = format!("v{seq}");
    if magic {
        Challenge::MagicLink { email_or_user: id, code_hash: "h".into(), attempts: 0, expires_at }
    } else {
        Challenge::AuthCode {
            client_id: "c".into(), redirect_uri: "https://app.test/cb".into(), user_id: id,
            scopes: Scopes(vec![]), nonce: None, code_challenge: "x".into(),
            code_challenge_method: "S256".into(), issued_at: 0, expires_at, auth_time: 0,
        }
    }
}

fn ident(c: &Challenge) -> &str {
    match c {
        Challenge::AuthCode { user_id, .. }            => user_id,
        Challenge::MagicLink { email_or_user, .. }     => email_or_user,
        _                                              => "?",
    }
}

/// What the model believes is stored at a handle.
struct Entry { seq: u64, magic: bool, expires_at: i64, attempts: u32, ident: String }

impl Entry {
    fn live(&self, clock: i64) -> bool { clock < self.expires_at }
}

/// How much of each kind of thing a run exercised (§7.6: a property that never
/// meets an expired entry proves nothing about expiry).
#[derive(Debug, Default, Clone, Copy)]
struct Stats {
    puts:          u64,
    conflicts:     u64,
    reads:         u64, // every Peek, Take and Bump
    absent_reads:  u64, // ... that found nothing stored
    live_reads:    u64, // ... that found a live entry
    expired_reads: u64, // ... that found an entry stored but expired
    takes:         u64,
    take_hits:     u64,
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.puts += o.puts; self.conflicts += o.conflicts; self.reads += o.reads;
        self.absent_reads += o.absent_reads; self.live_reads += o.live_reads;
        self.expired_reads += o.expired_reads; self.takes += o.takes; self.take_hits += o.take_hits;
    }
}

macro_rules! ensure {
    ($c:expr, $($arg:tt)+) => { if !($c) { return Err(format!($($arg)+)); } };
}

/// Apply `ops` to a fresh store and the model, asserting the clauses. `Err` is
/// the first violation, so proptest can shrink to a minimal failing sequence.
fn run(ops: &[Op]) -> Result<Stats, String> {
    let rt = tokio::runtime::Builder::new_current_thread().build().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let store = InMemoryAuthChallengeStore::default();
        let mut model: HashMap<usize, Entry> = HashMap::new();
        let mut taken: HashSet<u64> = HashSet::new();
        let (mut clock, mut next_seq) = (START_CLOCK, 0u64);
        let mut st = Stats::default();

        // Reads what is physically stored, whether or not it has expired:
        // `i64::MIN` is before every `expires_at`, so the store reports it live.
        macro_rules! raw { ($h:expr) => {
            store.peek(&handle($h), i64::MIN).await.map_err(|e| format!("raw peek: {e:?}"))?
        } }

        for op in ops {
            match *op {
                Op::Advance { by } => clock += by,

                Op::Put { h, magic, ttl } => {
                    let seq = next_seq; next_seq += 1;
                    let c = challenge(seq, magic, clock + ttl);
                    let res = store.put(&handle(h), &c).await;
                    match model.get(&h) {
                        Some(existing) => {
                            // Clause 1.
                            ensure!(matches!(res, Err(PortError::Conflict)),
                                "put on occupied h{h} must be Conflict, got {res:?}");
                            ensure!(raw!(h).as_ref().map(ident) == Some(existing.ident.as_str()),
                                "a conflicting put changed the value stored at h{h}");
                            st.conflicts += 1;
                        }
                        None => {
                            ensure!(res.is_ok(), "put on empty h{h} failed: {res:?}");
                            model.insert(h, Entry { seq, magic, expires_at: clock + ttl, attempts: 0, ident: format!("v{seq}") });
                            st.puts += 1;
                        }
                    }
                }

                Op::Peek { h } => {
                    st.reads += 1;
                    let got = store.peek(&handle(h), clock).await.map_err(|e| format!("peek: {e:?}"))?;
                    let want = model.get(&h).filter(|e| e.live(clock)).map(|e| e.ident.as_str());
                    ensure!(got.as_ref().map(ident) == want, "peek h{h} at {clock}: got {:?}, want {want:?}", got.as_ref().map(ident));
                    match model.get(&h) {
                        None => st.absent_reads += 1,
                        Some(e) if e.live(clock) => st.live_reads += 1,
                        Some(_) => {
                            st.expired_reads += 1;
                            // Clause 3: an expired peek does not delete.
                            ensure!(raw!(h).is_some(), "an expired peek of h{h} deleted the entry");
                        }
                    }
                }

                Op::Take { h } => {
                    st.reads += 1; st.takes += 1;
                    let got = store.take(&handle(h), clock).await.map_err(|e| format!("take: {e:?}"))?;
                    let entry = model.remove(&h);
                    let want = entry.as_ref().filter(|e| e.live(clock)).map(|e| e.ident.as_str());
                    // Clauses 3 and 4: only a live, previously-put value comes back.
                    ensure!(got.as_ref().map(ident) == want, "take h{h} at {clock}: got {:?}, want {want:?}", got.as_ref().map(ident));
                    match &entry {
                        None => st.absent_reads += 1,
                        Some(e) if e.live(clock) => {
                            st.live_reads += 1; st.take_hits += 1;
                            // Clause 2: each put is taken at most once.
                            ensure!(taken.insert(e.seq), "value v{} was taken twice", e.seq);
                        }
                        Some(_) => st.expired_reads += 1,
                    }
                    // Clauses 2 and 3: however it went, the entry is now gone.
                    ensure!(raw!(h).is_none(), "take of h{h} at {clock} left the entry stored");
                }

                Op::Bump { h } => {
                    st.reads += 1;
                    let res = store.bump_magic_link_attempts(&handle(h), clock).await;
                    match model.get_mut(&h) {
                        None => {
                            st.absent_reads += 1;
                            ensure!(matches!(res, Err(PortError::NotFound)), "bump of absent h{h}: {res:?}");
                        }
                        Some(e) if !e.live(clock) => {
                            st.expired_reads += 1;
                            // Clause 3.
                            ensure!(matches!(res, Err(PortError::NotFound)), "bump of expired h{h} must be NotFound, got {res:?}");
                        }
                        Some(e) if e.magic => {
                            st.live_reads += 1; e.attempts += 1;
                            ensure!(matches!(res, Ok(n) if n == e.attempts), "bump h{h}: got {res:?}, want Ok({})", e.attempts);
                        }
                        Some(_) => {
                            st.live_reads += 1;
                            ensure!(matches!(res, Err(PortError::PreconditionFailed(_))), "bump of a non-magic-link h{h}: {res:?}");
                        }
                    }
                }
            }
        }
        Ok(st)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The contract's four clauses hold for every generated sequence.
    #[test]
    fn auth_challenge_store_satisfies_the_contract(ops in ops_strategy()) {
        run(&ops).map_err(TestCaseError::fail)?;
    }
}

/// §7.6 — the property above is only worth something if its generator reaches
/// the interesting states. Draws a fixed, seeded sample from the same strategy
/// and fails if expired reads, conflicts or successful takes are rare, so a
/// regression in the generator is loud. `cargo test … -- --nocapture` prints
/// the measured proportions.
#[test]
fn the_generator_reaches_expired_conflicting_and_successful_operations() {
    let (mut runner, strat) = (TestRunner::deterministic(), ops_strategy());
    let (mut total, mut sequences) = (Stats::default(), 0u32);
    for _ in 0..500 {
        let ops = strat.new_tree(&mut runner).expect("generate").current();
        total.add(&run(&ops).expect("every generated sequence satisfies the contract"));
        sequences += 1;
    }
    let pct = |n: u64, d: u64| if d == 0 { 0.0 } else { 100.0 * n as f64 / d as f64 };
    println!("RFC 117 T4 coverage over {sequences} generated sequences:");
    println!("  reads (peek/take/bump)   {:>6}", total.reads);
    println!("    hit an expired entry   {:>6}  {:5.1}% of reads", total.expired_reads, pct(total.expired_reads, total.reads));
    println!("    hit a live entry       {:>6}  {:5.1}% of reads", total.live_reads,    pct(total.live_reads,    total.reads));
    println!("    found nothing stored   {:>6}  {:5.1}% of reads", total.absent_reads,  pct(total.absent_reads,  total.reads));
    println!("  puts accepted            {:>6}", total.puts);
    println!("  puts refused (Conflict)  {:>6}  {:5.1}% of put attempts", total.conflicts, pct(total.conflicts, total.puts + total.conflicts));
    println!("  takes                    {:>6}", total.takes);
    println!("    returned a value       {:>6}  {:5.1}% of takes", total.take_hits, pct(total.take_hits, total.takes));

    assert!(total.reads > 5_000, "too few reads generated: {}", total.reads);
    assert!(pct(total.expired_reads, total.reads) >= 8.0, "expired reads are rare: the expiry clause is barely exercised");
    assert!(pct(total.live_reads,    total.reads) >= 8.0, "live reads are rare: the success side is barely exercised");
    assert!(pct(total.conflicts, total.puts + total.conflicts) >= 5.0, "put conflicts are rare: clause 1 is barely exercised");
    assert!(pct(total.take_hits, total.takes) >= 5.0, "successful takes are rare: clauses 2 and 4 are barely exercised");
}
