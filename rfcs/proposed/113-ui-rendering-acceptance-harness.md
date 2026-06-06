# RFC 113 — UI rendering acceptance harness

**Status**: Proposed  
**Tier**: P2  
**Size**: Medium  
**Target**: v0.70.0  
**Phase**: Acceptance gate (finishing track)  
**Refs**: PDF v0.50.1 page 12 "ABDD check" / page 14 "Acceptance criteria" / RFC 027 / RFC 016 (scope badge)

## Problem

PDF v0.50.1 page 14 は 6 つの acceptance criteria を列挙している:

```
✓ 主要 flow が keyboard / screen reader で完了
✓ flash と inline error が same meaning
✓ danger 操作は対象・影響・結果を明示
✓ route と権限 scope が URL と見出しで分かる
✓ EN + JA rendering test を追加
✓ version / README / docs drift を release checklist で検知
```

これらは個別の RFC (RFC 027 a11y + route contracts、RFC 016 scope badge、
RFC 071 footer version hygiene、RFC 072 html lang locale 等) で個別に対処
されているが、**横串の "acceptance gate" として 1 つのテスト harness で
保証する仕組みが無い**。具体的には:

1. 新規 admin route 追加時に scope badge が含まれるかは個別 rendering テスト
   依存 — 追加忘れの risk。
2. EN + JA 両 locale で render テストすることは推奨されているが、
   全 end-user route について exhaustive に存在するかは未検証。
3. flash と inline error の文言一致 (page 14 criterion: "flash と inline error
   が same meaning") は MessageKey の使い回しに依存。catalog 上で同じ key を
   両方が参照しているかは確認していない。
4. drift-scan は RFC 012 で導入されたが、UI 側の acceptance criteria の検証は
   含まれていない。

## Goal

1. UI rendering の **横串 acceptance harness** を `crates/ui/tests/` (integration
   tests) として導入する。
2. 全 browser-facing route について以下を assert する:
   - scope badge 含有 (admin route のみ)
   - EN + JA 両 locale で render 可能 (admin は ADR-013 で JA-only なので EN は除外)
   - flash region 含有
   - skip-link 含有 (RFC 077)
   - footer の version 文字列含有 (RFC 071)
   - `<html lang>` 属性が locale と一致 (RFC 072)
3. CI gate として `cargo-1.91 test -p cesauth-ui` の一部に組み込む。

明示的に out of scope:
- E2E ブラウザテスト (headless Chrome 等) — server-rendered HTML 文字列の
  unit test 範囲のみ。
- visual regression (screenshot diff) — 別 RFC で検討。
- accessibility scanner (axe-core 等) — 別 RFC で検討。
- 既存 RFC 027 の per-route metadata table とは別軸 (027 はメタデータ、
  113 は実 rendering)。

## Design

### Harness 配置

`crates/ui/tests/acceptance_harness.rs` (新規 integration test ファイル)。
1 file で 1 route あたりの assertion を持つ。

route enumeration は **静的テーブル** で持つ。動的取得 (worker route table から
introspect) はせず、`routes::*` catalog (RFC 102) と手で対応付ける。これにより
新規 route 追加時に harness テーブルへの追加が **必要** となり、
"acceptance gate に新 route を通す" の意識化を発生させる。

### Acceptance matrix

```rust
struct RouteSpec {
    path:             &'static str,           // catalog 経由
    scope:            Scope,                  // EndUser / SystemAdmin / TenantAdmin / Anonymous
    locales:          &'static [Locale],      // [En, Ja] or [Ja] for admin
    has_flash:        bool,                   // ほぼ全 page true
    has_skip_link:    bool,                   // ほぼ全 page true (RFC 077)
    has_footer_ver:   bool,                   // 全 page (RFC 071)
    has_scope_badge:  bool,                   // admin route のみ
}

const ROUTES: &[RouteSpec] = &[
    RouteSpec {
        path: routes::login::INDEX,
        scope: Scope::Anonymous,
        locales: &[Locale::En, Locale::Ja],
        ..
    },
    RouteSpec {
        path: routes::me::security::INDEX,
        scope: Scope::EndUser,
        locales: &[Locale::En, Locale::Ja],
        ..
    },
    RouteSpec {
        path: routes::admin::console::OVERVIEW,
        scope: Scope::SystemAdmin,
        locales: &[Locale::Ja],
        has_scope_badge: true,
        ..
    },
    // ...
];
```

各 `RouteSpec` に対し:

```rust
#[test]
fn acceptance_harness_runs() {
    for spec in ROUTES {
        for locale in spec.locales {
            let html = render_for_spec(spec, *locale);
            if spec.has_flash {
                // skip-link 等が `<main>` の前に来るので flash region は <main> 内
                assert!(html.contains("class=\"flash"), "flash region absent for {}", spec.path);
            }
            if spec.has_skip_link {
                assert!(html.contains("class=\"skip-link"), "skip-link absent for {}", spec.path);
            }
            if spec.has_footer_ver {
                assert!(html.contains("v0."), "footer version absent for {}", spec.path);
            }
            if spec.has_scope_badge {
                assert!(html.contains("scope-badge"), "scope badge absent for {}", spec.path);
            }
            // `<html lang="..">` matches locale
            assert!(html.contains(&format!("lang=\"{}\"", locale.bcp47())),
                "html lang mismatch for {} / {:?}", spec.path, locale);
        }
    }
}
```

### Catalog-flash consistency

PDF page 14 criterion: "flash と inline error が same meaning"。
これは「flash で出す失敗メッセージと、inline error で出す同種の失敗メッセージで
**同じ MessageKey** を参照する」ことを意味する。

実装は MessageKey 上のメタデータでは難しい (open mapping)。本 RFC では実装簡略化のため、
**convention 化 + 軽い CI 検出のみ** にとどめる:

- `MessageKey::*Flash` という命名規約を導入 (`SessionsRevokeFlashSuccess` 等)
- 対応する inline error は `*InlineError` などの命名規約 (現状の MessageKey 設計
  と矛盾しない)
- ペア定義は `i18n/sub_modules` に対応する MessageKey をコメントで紐付け

これは acceptance criterion を **fully automate しない** が、code review 時に
発見できる shape にする。完全自動化は別 RFC で検討。

### `render_for_spec` の実装

`render_for_spec(spec, locale) -> String` は内部で `path` から対応する template
関数をディスパッチする必要がある。これは大きな match arm になるが、
テスト範囲なので保守は許容範囲 (route 追加時の局所変更で済む)。

または、各 template 関数に `#[harness_entry]` のような属性を付ける案も検討
できるが、本 RFC では match arm の単純さを優先する。

## Implementation steps

1. `crates/ui/tests/acceptance_harness.rs` 新規作成。
2. `RouteSpec` 構造体定義 + `ROUTES` 静的テーブル定義 (全 browser-facing route
   ~30 程度を列挙)。
3. 各 path に対する `render_for_spec` 実装 (dispatch to template fn).
4. acceptance assertion を一つの `#[test]` で網羅する (全 route の assertion を
   1 テストで回す。失敗時はどの route で落ちたか panic メッセージで判明)。
5. CI gate (`cargo-1.91 test -p cesauth-ui --test acceptance_harness`) を
   `.github/workflows/*.yml` に追加。
6. drift-scan rule: 新規 `*_page_for` template fn が ROUTES table に登録なく
   存在しないことを `scripts/check-acceptance-coverage.sh` (新規) で検出。

## Acceptance

- [ ] `cargo-1.91 test -p cesauth-ui --test acceptance_harness` が green
- [ ] ROUTES table が全 browser-facing route (anonymous / end-user / admin /
      tenant admin / tenancy console) をカバー
- [ ] 1 つでも route が落ちると acceptance_harness が fail (簡単な smoke
      テストで確認)
- [ ] 新規 route 追加忘れを `check-acceptance-coverage.sh` が検出
- [ ] `cargo-1.91 build --workspace --target wasm32-unknown-unknown --release` が成功
- [ ] 非 deprecated warnings = 0

## Test strategy

harness 自体がテストなので追加テストは不要。逆に harness の **自己テスト**
として「`acceptance_harness` から 1 route を抜くと build OK だが coverage script
が fail する」ことを手動で確認するか、`check-acceptance-coverage.sh` 自体の
unit test (golden-file) を別添する。

## Migration / compatibility

- 後方互換性: 不要。
- スキーマ変更: 無し。
- wire / DO: 無し。
- 運用者向け: 開発者体験のみ (CI gate 追加)。CHANGELOG に "UI rendering
  acceptance harness 追加" と記載。

## Open questions

Q1. flash と inline error の "same meaning" 自動検証を本 RFC 内に含めるか、
別 RFC として切るか。

→ 提案: 本 RFC では convention + コメント紐付けで段階 1 とする。fully
automated 検証は将来別 RFC (e.g., RFC 11X-flash-inline-pair) で扱う。
