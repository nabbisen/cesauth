# RFC 108 — UI template route-catalog migration

**Status**: Implemented (v0.68.0 partial → v0.69.0 catalog + admin/console → v0.70.0 closure; two pre-existing orphan UIs intentionally left out of scope, see "Known orphan UI")  
**Tier**: P1  
**Size**: Large  
**Target**: v0.68.0  
**Phase**: Drift prevention (finishing track)  
**Refs**: HANDOFF v0.66.0 残課題 §2 ("RFC 102 routes.rs の UI 移行") / PDF v0.50.1 page 13 "Form contracts" / RFC 102 / RFC 027

## Deferred-work note (multi-release implementation)

### v0.68.0 (initial partial)

- **Catalog audit and correction (WebAuthn).** `crates/core/src/routes.rs::auth::*`
  had four WebAuthn paths that never matched the worker registration:
  `/me/webauthn/register*` and `/auth/webauthn/*` aspirational constants
  vs the worker's `/webauthn/register/*` and `/webauthn/authenticate/*`
  actual routes. Corrected to match reality. Renamed `PASSKEY_REGISTER`
  → `PASSKEY_REGISTER_START` for symmetry with `_FINISH`. Added
  `MAGIC_LINK_VERIFY_FORM` (no-handle form-action variant) and
  `TOTP_ENROLL_CONFIRM` (POST target for enrollment confirm step).
- **End-user template migration (RFC PR 1).** 15 hardcoded URLs across
  `crates/ui/src/templates/{security_center,login,totp}.rs` migrated
  to `cesauth_core::routes::{me,auth}::*` references.
- **Escape contract documented.** Catalog builder fns (e.g.
  `session_revoke(id) -> String`) return raw URL strings; HTML-escape
  at the template boundary. A failing test
  (`sessions_page_session_id_is_html_escaped`) caught a missed escape
  during the migration; the fix and inline comment in
  `security_center.rs::render_session_row_for` pin the contract.

### v0.69.0 (catalog completion + admin/console migration)

- **Catalog audit and correction (tenancy console).** Second silent
  v0.66.0 drift discovered: `tenancy_console::tenant(slug)` etc.
  returned `/admin/tenancy/{slug}/...` but the worker has always
  registered `/admin/tenancy/tenants/{tid}/...`. Same shape as the
  v0.68.0 WebAuthn correction. Rewrote the entire `tenancy_console`
  module to match worker routes.
- **Catalog completion.** Expanded from ~57 entries (after v0.68.0)
  to ~80 entries covering every URL family the production templates
  need. New builders include `admin::config_edit/preview/apply`,
  `safety_verify`, `token_disable`, `threshold`; full
  `tenancy_console::*` rewrite; `tenant_admin` builders for
  `organizations_new`, `org_status`, `org_memberships*`,
  `user_role_assignments*`, `role_assignment_delete`, `group_*`,
  `memberships*`. Every const and fn now mirrors a route registered
  by `crates/worker/src/lib.rs` (124 routes total).
- **Admin nav migration (all three frames).** `admin/frame.rs`
  `Tab::href` (8 URLs), `tenant_admin/frame.rs` `TenantAdminTab::href`
  (6 URLs), `tenancy_console/frame.rs` `TenancyConsoleTab::href`
  (2 URLs) all flow through the catalog.
- **`admin/console/*` template migration.** 7 production templates
  fully migrated: `audit.rs`, `audit_chain.rs`, `overview.rs`,
  `cost.rs`, `tokens.rs`, `config.rs`, `safety.rs`, `config_edit.rs`.
  ~20 URLs migrated, including all parameterized routes via builder
  fns + the HTML-escape contract.

### v0.70.0 (closure)

- **`tenant_admin/*` template migration.** All 6 production top-level
  pages (`organizations.rs`, `role_assignments.rs`, `overview.rs`,
  `invitations.rs`, `deletions.rs`, `users.rs`) plus all 8 forms
  (`group_create`, `group_delete`, `organization_create`,
  `organization_set_status`, `membership_add`, `membership_remove`,
  `role_assignment_grant`, `role_assignment_revoke`) migrated to
  `cesauth_core::routes::tenant_admin::*`.
- **`tenancy_console/*` template migration.** All 5 remaining top-level
  pages (`tenant_detail.rs`, `role_assignments.rs`, `organizations.rs`,
  `tenants.rs`, `subscription.rs`) plus 11 forms migrated to
  `cesauth_core::routes::tenancy_console::*`. (1 form — `membership_add.rs`
  — left hardcoded as an orphan; see below.)
- **Drift-scan rule landed (RFC PR 4).** `scripts/drift-scan.sh` now
  runs a per-file scan of `crates/ui/src/` for URL literals matching
  `"/(admin|me|oidc|auth|login|logout|magic-link|\.well-known)/`. Stops
  per-file at the first `#[cfg(test)]` or `mod tests` marker (test
  assertions on URLs by string are deliberately exempt — they exist to
  fail loudly on catalog drift). Standalone `tests.rs` files exempt
  for the same reason. Currently clean.
- **~150 URLs migrated this release**, ~190 total across v0.68.0 +
  v0.69.0 + v0.70.0.

### Known orphan UI (not in RFC 108 scope)

Two templates render forms or links to URLs the worker does not
register. These are **pre-existing bugs**, surfaced by — but outside
the scope of — RFC 108. The catalog policy is "mirror worker reality,
not aspirations," so these stay hardcoded with a module-docstring
`# RFC 108 orphan UI exemption` note and an entry in the drift-scan
exemption list. Resolution belongs to follow-up work.

1. **`crates/ui/src/tenant_admin/oidc_clients.rs`** — submits to
   `/admin/t/{slug}/oidc-clients/{cid}/audience`. RFC 017 added the UI
   but never wired the worker handler. Either wire the worker route or
   remove the template.

2. **`crates/ui/src/tenancy_console/forms/membership_add.rs`** — all
   three `for_tenant` / `for_organization` / `for_group` variants POST
   to `.../memberships` (no `/new` suffix). The worker only handles
   `.../memberships/new` — these submissions return 404. The
   `tenant_admin/forms/membership_add.rs` equivalent maps cleanly,
   suggesting the `tenancy_console` variant was authored before the
   routes were finalised.

Rationale for multi-release implementation: the lifecycle policy
(RFC 019 / `rfcs/done/019-rfc-lifecycle-policy.md` §Granularity of
transitions) allows partial implementation when the partial work
captures the RFC's main design decision. The pattern was fully
established by v0.68.0 (escape contract + catalog-builder shape); the
v0.69.0 + v0.70.0 work is volume, not novelty.

## Problem

RFC 102 (v0.66.0) は `/admin/console/...` / `/admin/t/:slug/...` / `/me/security/...`
など 165 ルートのパス文字列を `crates/core/src/routes.rs` の定数 catalog に
集約した。しかし **catalog の consumers は移行されていない**。HANDOFF §2 によれば:

> RFC 102 routes.rs の UI 移行: 202 ハードコード URL 文字列を UI templates から
> `crate::routes::*` 参照に置き換えるのは未着手。catalog は完成しているが
> consumers は移行待ち。

UI テンプレート内に hardcoded URL リテラルが 202 箇所残っており、これは:

1. **ルート変更時のドリフト源** — `/me/security/sessions` を `/me/sessions`
   に rename するような変更で、catalog は更新されてもテンプレートが取り残される。
2. **PDF v0.50.1 page 13 の form contracts matrix と矛盾** — Form contracts は
   route × actor × audit kind の対応表を「ルート追加時に同時更新する」ことを
   要求しており、catalog 経由のテンプレートはこの contract を機械的に保証する。
3. **RFC 027 で導入した route-contracts.md の CI gate を補完する** — RFC 027
   は metadata table の存在を担保するが、template が catalog を経由していない
   と「table のルート」と「実際に rendered されるリンク」が乖離する可能性を残す。

## Goal

1. UI テンプレート (`crates/ui/src/...`) 内の hardcoded URL 文字列を
   `cesauth_core::routes::*` 経由の参照に置き換える。
2. 新規 hardcoded URL の混入を CI で検知する drift-scan ルールを追加する。
3. catalog の網羅性 (`routes.rs` に未登録のパスがテンプレートに出現しない) を
   保証する。

明示的に out of scope:
- Worker route registration (`crates/worker/src/lib.rs`) の catalog 統合 — RFC 102
  の範囲。RFC 102 で 165 ルートは catalog 化済。
- 外部 URL (OIDC issuer URL、callback URL 等) — `routes::*` は内部 path のみ扱う。
- 動的 path セグメント (`/admin/t/:slug/users/:id`) の URL builder — 別 RFC で
  検討 (本 RFC は const &'static str catalog のみ対象)。

## Design

### catalog の参照方法

`crates/core/src/routes.rs` (RFC 102) は const として定義されている:

```rust
pub mod me {
    pub mod security {
        pub const INDEX:    &str = "/me/security";
        pub const SESSIONS: &str = "/me/security/sessions";
        pub const TOTP_ENROLL:  &str = "/me/security/totp/enroll";
        pub const TOTP_DISABLE: &str = "/me/security/totp/disable";
        ...
    }
}
```

UI からは `cesauth_core::routes::me::security::INDEX` のようにフルパスで参照する。
short alias を導入しない (path の意味は URL hierarchy と一致するので、明示的
パス参照のほうが grep しやすい)。

### 動的セグメント (`:id` / `:slug`) の扱い

現状の `security_center.rs::render_session_row_for` のような場合:

```rust
action = "/me/security/sessions/{sid}/revoke"
```

これは `format!()` で session_id を embed している。RFC 108 では:

- **静的パス**: catalog の const をそのまま参照。
- **動的パス**: catalog に「テンプレート const」を追加する形で扱う。例:
  ```rust
  pub const SESSION_REVOKE_TEMPLATE: &str = "/me/security/sessions/{sid}/revoke";
  ```
  consumer 側で `replace("{sid}", &session_id)` ではなく、catalog に
  builder fn を提供する案も検討:
  ```rust
  pub fn session_revoke_url(session_id: &str) -> String {
      format!("/me/security/sessions/{}/revoke", session_id)
  }
  ```
  どちらを採るかは実装時に決める (本 RFC は const + template 両形式を許容)。

### Drift-scan rule

`scripts/drift-scan.sh` (RFC 012) に新規ルール追加:

```bash
# UI 内に hardcoded /admin/, /me/, /oidc/, /authorize 等が出現すべきでない
# (catalog 経由でなければ)。format!() / r#""# / "" の hardcoded URL を検出。
grep -rn -E '"/(admin|me|oidc|authorize|token|introspect|revoke)/' crates/ui/src/ \
  | grep -v '// drift-scan: catalog'
```

許容例外 (`// drift-scan: catalog` コメント付き) を残す。例えば JavaScript の
fetch URL 等で catalog 参照が技術的に難しい箇所のために。

## Implementation steps

段階移行が大きいため、4 つの PR に分割する:

### PR 1 — 静的 path 移行 (高頻度)

| Template ファイル | hardcoded path 候補 |
|---|---|
| `templates/security_center.rs` | `/me/security/sessions`, `/me/security/totp/enroll`, `/me/security/totp/disable`, `/me/security`, `/` |
| `templates/login.rs` | `/login`, `/magic-link/...` |
| `templates/totp.rs` | `/me/security/totp/...` |
| `templates/chrome.rs` (footer / skip-link) | `#main` (skip-link は exempt) |

### PR 2 — admin frame 系

`crates/ui/src/admin/*.rs` (~6,224 行) のリンクを catalog 経由に。
件数が多いので RFC 100 macro 移行 (RFC 112) と並行で進めない。

### PR 3 — tenant_admin / tenancy_console

同じ作業を `tenant_admin/` と `tenancy_console/` のリンクに適用。

### PR 4 — drift-scan rule + CI gate

`scripts/drift-scan.sh` に検出ルール追加 + `.github/workflows/drift-scan.yml`
で hardcoded URL 検出時に fail。`route-contracts.md` の metadata table 整合性
チェック (RFC 027) と連動。

## Acceptance

- [ ] `cargo-1.91 test --workspace --lib` が green
- [ ] `cargo-1.91 build --workspace --target wasm32-unknown-unknown --release` が成功
- [ ] `scripts/drift-scan.sh` の URL-hardcode rule が green
- [ ] `grep -rn -E '"/(admin|me|oidc|authorize|token|introspect|revoke)/' crates/ui/src/` の
      結果が全て `// drift-scan: catalog` exemption 付きか、catalog 経由
- [ ] `routes.rs` に存在しないパスがテンプレートに出現していない
- [ ] route-contracts.md (RFC 027) の URL 列と `routes.rs` の const 値が
      一致 (CI で検証)
- [ ] 非 deprecated warnings = 0

## Test strategy

新規テストは追加せず、既存の 1,204 テストが全て green を維持することを以て
リグレッション無しを確認する。catalog 経由化は文字列の出力結果を変えないため。

加えて、`routes.rs` に新規追加が必要だった場合は RFC 102 の既存パターン:

```rust
#[test]
fn me_security_routes_are_well_formed() {
    assert!(me::security::INDEX.starts_with("/me/security"));
    ...
}
```

を keep。

## Migration / compatibility

- 後方互換性: 不要。
- スキーマ変更: 無し。
- wire / DO: 無し。
- 運用者向け: 視覚的変更は無い。CHANGELOG に「内部リンクの catalog 化」と記載。

## Open questions

なし (動的セグメントの扱いは const + builder 両形式の併用で本 RFC 内に閉じる)。
