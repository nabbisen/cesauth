//! Tests for the in-memory `AuditEventRepository`.
//!
//! These pin the chain semantics that the D1 adapter must
//! match, plus the search-filter behavior.

use super::*;
use cesauth_core::audit::chain::{
    compute_chain_hash, compute_payload_hash, GENESIS_HASH, verify_chain_link,
    verify_payload_hash,
};

fn ev<'a>(
    id:           &'a str,
    ts:           i64,
    kind:         &'a str,
    payload:      &'a str,
    payload_hash: &'a str,
) -> NewAuditEvent<'a> {
    NewAuditEvent {
        id, ts, kind,
        subject: None, client_id: None, ip: None, user_agent: None, reason: None,
        payload,
        payload_hash,
        created_at: ts,
    }
}

// =====================================================================
// Genesis / first-append semantics
// =====================================================================

#[tokio::test]
async fn empty_repo_first_append_chains_from_genesis() {
    let repo = InMemoryAuditEventRepository::new();
    let payload = r#"{"k":"login"}"#;
    let h = compute_payload_hash(payload.as_bytes());
    let row = repo.append(&ev("e1", 100, "login", payload, &h)).await.unwrap();
    assert_eq!(row.seq, 1);
    assert_eq!(row.previous_hash, GENESIS_HASH);
    // chain_hash recomputable from inputs.
    let expected = compute_chain_hash(GENESIS_HASH, &h, 1, 100, "login", "e1");
    assert_eq!(row.chain_hash, expected);
}

#[tokio::test]
async fn with_genesis_first_real_event_starts_at_seq_2() {
    let repo = InMemoryAuditEventRepository::with_genesis();
    let payload = r#"{"k":"x"}"#;
    let h = compute_payload_hash(payload.as_bytes());
    let row = repo.append(&ev("first", 50, "kind_a", payload, &h)).await.unwrap();
    assert_eq!(row.seq, 2,
        "with-genesis repo's first user append must be seq=2, got seq={}", row.seq);
    // previous_hash should be the genesis row's chain_hash, which by
    // convention equals GENESIS_HASH.
    assert_eq!(row.previous_hash, GENESIS_HASH);
}

// =====================================================================
// Chain integrity across multiple appends
// =====================================================================

#[tokio::test]
async fn three_appends_form_a_valid_chain() {
    let repo = InMemoryAuditEventRepository::new();
    let p1 = r#"{"k":"a"}"#;
    let p2 = r#"{"k":"b"}"#;
    let p3 = r#"{"k":"c"}"#;
    let h1 = compute_payload_hash(p1.as_bytes());
    let h2 = compute_payload_hash(p2.as_bytes());
    let h3 = compute_payload_hash(p3.as_bytes());

    let r1 = repo.append(&ev("a", 1, "k", p1, &h1)).await.unwrap();
    let r2 = repo.append(&ev("b", 2, "k", p2, &h2)).await.unwrap();
    let r3 = repo.append(&ev("c", 3, "k", p3, &h3)).await.unwrap();

    // seq monotonically increases by 1.
    assert_eq!((r1.seq, r2.seq, r3.seq), (1, 2, 3));

    // Each row's previous_hash links to the predecessor's chain_hash.
    assert_eq!(r1.previous_hash, GENESIS_HASH);
    assert_eq!(r2.previous_hash, r1.chain_hash);
    assert_eq!(r3.previous_hash, r2.chain_hash);

    // Each chain_hash is recomputable from the inputs.
    assert!(verify_chain_link(&r1.chain_hash, &r1.previous_hash, &r1.payload_hash, r1.seq, r1.ts, &r1.kind, &r1.id));
    assert!(verify_chain_link(&r2.chain_hash, &r2.previous_hash, &r2.payload_hash, r2.seq, r2.ts, &r2.kind, &r2.id));
    assert!(verify_chain_link(&r3.chain_hash, &r3.previous_hash, &r3.payload_hash, r3.seq, r3.ts, &r3.kind, &r3.id));

    // Each payload_hash matches the stored payload bytes.
    assert!(verify_payload_hash(&r1.payload_hash, r1.payload.as_bytes()));
    assert!(verify_payload_hash(&r2.payload_hash, r2.payload.as_bytes()));
    assert!(verify_payload_hash(&r3.payload_hash, r3.payload.as_bytes()));
}

#[tokio::test]
async fn rows_returns_chain_in_seq_order() {
    let repo = InMemoryAuditEventRepository::new();
    let h = compute_payload_hash(b"{}");
    repo.append(&ev("a", 1, "k", "{}", &h)).await.unwrap();
    repo.append(&ev("b", 2, "k", "{}", &h)).await.unwrap();
    repo.append(&ev("c", 3, "k", "{}", &h)).await.unwrap();

    let snap = repo.rows();
    assert_eq!(snap.len(), 3);
    assert_eq!(snap[0].seq, 1);
    assert_eq!(snap[1].seq, 2);
    assert_eq!(snap[2].seq, 3);
}

// =====================================================================
// tail()
// =====================================================================

#[tokio::test]
async fn tail_returns_none_for_empty_repo() {
    let repo = InMemoryAuditEventRepository::new();
    assert!(repo.tail().await.unwrap().is_none());
}

#[tokio::test]
async fn tail_returns_genesis_for_with_genesis_repo() {
    let repo = InMemoryAuditEventRepository::with_genesis();
    let t = repo.tail().await.unwrap().expect("genesis present");
    assert_eq!(t.seq, 1);
    assert_eq!(t.kind, "ChainGenesis");
}

#[tokio::test]
async fn tail_returns_latest_after_appends() {
    let repo = InMemoryAuditEventRepository::new();
    let h = compute_payload_hash(b"{}");
    repo.append(&ev("a", 1, "k", "{}", &h)).await.unwrap();
    repo.append(&ev("b", 2, "k", "{}", &h)).await.unwrap();
    let r3 = repo.append(&ev("c", 3, "k", "{}", &h)).await.unwrap();
    let t = repo.tail().await.unwrap().expect("non-empty");
    assert_eq!(t.seq, r3.seq);
    assert_eq!(t.id, r3.id);
}

// =====================================================================
// search()
// =====================================================================

async fn populate_for_search() -> InMemoryAuditEventRepository {
    let repo = InMemoryAuditEventRepository::new();
    let h = compute_payload_hash(b"{}");
    let mut e = ev("e1", 100, "login", "{}", &h);
    e.subject = Some("alice");
    repo.append(&e).await.unwrap();

    e = ev("e2", 200, "login", "{}", &h);
    e.subject = Some("bob");
    repo.append(&e).await.unwrap();

    e = ev("e3", 300, "logout", "{}", &h);
    e.subject = Some("alice");
    repo.append(&e).await.unwrap();

    e = ev("e4", 400, "login_failed", "{}", &h);
    e.subject = None;
    repo.append(&e).await.unwrap();
    repo
}

#[tokio::test]
async fn search_default_returns_all_newest_first() {
    let repo = populate_for_search().await;
    let out = repo.search(&AuditSearch::default()).await.unwrap();
    assert_eq!(out.len(), 4);
    // Newest first.
    assert_eq!(out[0].id, "e4");
    assert_eq!(out[3].id, "e1");
}

#[tokio::test]
async fn search_kind_filter_applies() {
    let repo = populate_for_search().await;
    let out = repo.search(&AuditSearch {
        kind: Some("login".to_owned()),
        ..AuditSearch::default()
    }).await.unwrap();
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|r| r.kind == "login"));
}

#[tokio::test]
async fn search_subject_filter_applies() {
    let repo = populate_for_search().await;
    let out = repo.search(&AuditSearch {
        subject: Some("alice".to_owned()),
        ..AuditSearch::default()
    }).await.unwrap();
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|r| r.subject.as_deref() == Some("alice")));
}

#[tokio::test]
async fn search_time_range_filters_inclusively() {
    let repo = populate_for_search().await;
    // since=200, until=300 → e2 (ts=200) and e3 (ts=300).
    let out = repo.search(&AuditSearch {
        since: Some(200),
        until: Some(300),
        ..AuditSearch::default()
    }).await.unwrap();
    assert_eq!(out.len(), 2);
    let ids: Vec<&str> = out.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"e2"));
    assert!(ids.contains(&"e3"));
}

#[tokio::test]
async fn search_limit_truncates() {
    let repo = populate_for_search().await;
    let out = repo.search(&AuditSearch {
        limit: Some(2),
        ..AuditSearch::default()
    }).await.unwrap();
    assert_eq!(out.len(), 2);
}

#[tokio::test]
async fn search_combined_filters_and() {
    let repo = populate_for_search().await;
    let out = repo.search(&AuditSearch {
        kind:    Some("login".to_owned()),
        subject: Some("alice".to_owned()),
        ..AuditSearch::default()
    }).await.unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].id, "e1");
}

#[tokio::test]
async fn search_no_match_returns_empty() {
    let repo = populate_for_search().await;
    let out = repo.search(&AuditSearch {
        kind: Some("nonexistent_kind".to_owned()),
        ..AuditSearch::default()
    }).await.unwrap();
    assert!(out.is_empty());
}

// =====================================================================
// fetch_after_seq — Phase 2 verifier helper
// =====================================================================

#[tokio::test]
async fn fetch_after_seq_zero_returns_chain_from_genesis_in_ascending_order() {
    let repo = InMemoryAuditEventRepository::with_genesis();
    let h = compute_payload_hash(b"{}");
    repo.append(&ev("a", 1, "k", "{}", &h)).await.unwrap();
    repo.append(&ev("b", 2, "k", "{}", &h)).await.unwrap();
    repo.append(&ev("c", 3, "k", "{}", &h)).await.unwrap();

    let page = repo.fetch_after_seq(0, 10).await.unwrap();
    assert_eq!(page.len(), 4, "genesis + 3 user rows");
    // Ascending seq.
    let seqs: Vec<i64> = page.iter().map(|r| r.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4]);
    assert_eq!(page[0].kind, "ChainGenesis");
}

#[tokio::test]
async fn fetch_after_seq_resumes_above_checkpoint() {
    let repo = InMemoryAuditEventRepository::with_genesis();
    let h = compute_payload_hash(b"{}");
    for n in 0..6 {
        repo.append(&ev(&format!("e{n}"), n as i64, "k", "{}", &h)).await.unwrap();
    }

    // Resume after seq=3: should get seqs 4, 5, 6, 7.
    let page = repo.fetch_after_seq(3, 100).await.unwrap();
    let seqs: Vec<i64> = page.iter().map(|r| r.seq).collect();
    assert_eq!(seqs, vec![4, 5, 6, 7]);
}

#[tokio::test]
async fn fetch_after_seq_empty_when_no_rows_above_cursor() {
    let repo = InMemoryAuditEventRepository::with_genesis();
    let h = compute_payload_hash(b"{}");
    repo.append(&ev("a", 1, "k", "{}", &h)).await.unwrap();
    // Tail is seq=2; ask for rows after seq=10.
    let page = repo.fetch_after_seq(10, 100).await.unwrap();
    assert!(page.is_empty());
}

#[tokio::test]
async fn fetch_after_seq_respects_limit() {
    let repo = InMemoryAuditEventRepository::new();
    let h = compute_payload_hash(b"{}");
    for n in 1..=10 {
        repo.append(&ev(&format!("e{n}"), n, "k", "{}", &h)).await.unwrap();
    }
    let page = repo.fetch_after_seq(0, 3).await.unwrap();
    assert_eq!(page.len(), 3);
    let seqs: Vec<i64> = page.iter().map(|r| r.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3], "first page should be the chain head");

    // Next page picks up where the first ended.
    let page2 = repo.fetch_after_seq(3, 3).await.unwrap();
    let seqs2: Vec<i64> = page2.iter().map(|r| r.seq).collect();
    assert_eq!(seqs2, vec![4, 5, 6]);
}
