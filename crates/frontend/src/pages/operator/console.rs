//! システムコンソールページコンポーネント (`/admin/console/*`)
//!
//! ADR-013: 日本語のみ。ロケールネゴシエーションなし。

use leptos::prelude::*;

// ─── Overview (/admin/console) ───────────────────────────────────────────────

/// コンソール概要 (`/admin/console`)
#[component]
pub fn ConsoleOverview() -> impl IntoView {
    let data = Resource::new(|| (), |_| async {
        gloo_net::http::Request::get("/admin/console.json")
            .header("Accept", "application/json")
            .send().await
            .ok()
            .map(|r| r.status() == 200)
            .unwrap_or(false)
    });

    view! {
        <main lang="ja">
            <h1>"cesauth オペレーターコンソール"</h1>
            <nav>
                <ul>
                    <li><a href="/admin/tenancy">"テナント管理"</a></li>
                    <li><a href="/admin/console/operations">"オペレーション"</a></li>
                    <li><a href="/admin/console/audit">"監査ログ"</a></li>
                    <li><a href="/admin/console/safety">"安全性チェック"</a></li>
                    <li><a href="/admin/console/cost">"コスト"</a></li>
                    <li><a href="/admin/console/tokens">"管理トークン"</a></li>
                    <li><a href="/admin/console/alerts">"アラート"</a></li>
                    <li><a href="/admin/console/config">"設定"</a></li>
                </ul>
            </nav>
            <Suspense fallback=|| view! { <p aria-busy="true">"読み込み中…"</p> }>
                {move || data.get().map(|ok| if ok {
                    view! { <p class="status-ok">"✓ システム正常"</p> }.into_any()
                } else {
                    view! { <p class="status-warn">"⚠ 状態を確認できませんでした"</p> }.into_any()
                })}
            </Suspense>
        </main>
    }
}

// ─── Operations (/admin/console/operations) ──────────────────────────────────

/// オペレーション状況 (`/admin/console/operations`)
#[component]
pub fn ConsoleOperations() -> impl IntoView {
    view! {
        <main lang="ja">
            <h1>"オペレーション"</h1>
            <p><a href="/admin/console">"← コンソール"</a></p>
            <p>"cronジョブの状態はKVストアに保存されています。"</p>
            <ul>
                <li>"retention_sweep"</li>
                <li>"audit_chain_verify"</li>
                <li>"session_index_audit"</li>
                <li>"session_index_repair"</li>
            </ul>
        </main>
    }
}

// ─── Audit (/admin/console/audit) ───────────────────────────────────────────

/// 監査ログブラウザ (`/admin/console/audit`)
#[component]
pub fn ConsoleAudit() -> impl IntoView {
    view! {
        <main lang="ja">
            <h1>"監査ログ"</h1>
            <p><a href="/admin/console">"← コンソール"</a></p>
            <p>"監査ログの検索・表示機能はここに表示されます。"</p>
        </main>
    }
}

// ─── Tokens (/admin/console/tokens) ─────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TokensData { csrf_token: String }

async fn fetch_tokens() -> Result<TokensData, String> {
    let r = gloo_net::http::Request::get("/admin/console/tokens.json")
        .header("Accept", "application/json")
        .send().await.map_err(|e| e.to_string())?;
    match r.status() { 200 => r.json().await.map_err(|e| e.to_string()), _ => Err("error".into()) }
}

/// 管理トークン一覧 (`/admin/console/tokens`)
#[component]
pub fn ConsoleTokens() -> impl IntoView {
    let data = Resource::new(|| (), |_| async { fetch_tokens().await });

    view! {
        <main lang="ja">
            <h1>"管理トークン"</h1>
            <p><a href="/admin/console">"← コンソール"</a></p>
            <Suspense fallback=|| view! { <p aria-busy="true">"読み込み中…"</p> }>
                {move || data.get().map(|r| match r {
                    Ok(d) => view! {
                        <div>
                            <p><a href="/admin/console/tokens/new">"新しいトークンを発行"</a></p>
                            <form method="POST" action="/admin/console/tokens/disable">
                                <input type="hidden" name="csrf" value=d.csrf_token />
                                <p>"トークンの無効化はIDを指定して行います。"</p>
                            </form>
                        </div>
                    }.into_any(),
                    Err(_) => view! { <p role="alert">"エラーが発生しました。"</p> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

// ─── Generic placeholder pages ───────────────────────────────────────────────

/// 安全性チェック (`/admin/console/safety`)
#[component]
pub fn ConsoleSafety() -> impl IntoView {
    view! { <main lang="ja">
        <h1>"安全性チェック"</h1>
        <p><a href="/admin/console">"← コンソール"</a></p>
        <p>"バケット検証の結果がここに表示されます。"</p>
    </main> }
}

/// コスト (`/admin/console/cost`)
#[component]
pub fn ConsoleCost() -> impl IntoView {
    view! { <main lang="ja">
        <h1>"コスト"</h1>
        <p><a href="/admin/console">"← コンソール"</a></p>
        <p>"テナントごとのコストスナップショットがここに表示されます。"</p>
    </main> }
}

/// アラート (`/admin/console/alerts`)
#[component]
pub fn ConsoleAlerts() -> impl IntoView {
    view! { <main lang="ja">
        <h1>"アラート"</h1>
        <p><a href="/admin/console">"← コンソール"</a></p>
        <p>"オペレーターアラートがここに表示されます。"</p>
    </main> }
}

/// 設定 (`/admin/console/config`)
#[component]
pub fn ConsoleConfig() -> impl IntoView {
    view! { <main lang="ja">
        <h1>"設定"</h1>
        <p><a href="/admin/console">"← コンソール"</a></p>
        <p>"ライブ設定の確認・適用はここから行います。"</p>
    </main> }
}

/// 監査チェーン (`/admin/console/audit/chain`)
#[component]
pub fn ConsoleAuditChain() -> impl IntoView {
    view! { <main lang="ja">
        <h1>"監査チェーン検証"</h1>
        <p><a href="/admin/console/audit">"← 監査ログ"</a></p>
        <p>"チェーンの整合性検証をここから実行できます。"</p>
    </main> }
}
