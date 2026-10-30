//! テナント管理コンソールコンポーネント (`/admin/tenancy/*`)
//!
//! ADR-013: 日本語のみ。

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use cesauth_core::tenancy::types::Tenant;

// ─── Tenancy overview (/admin/tenancy) ───────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
struct OverviewData { tenant_count: usize }

/// テナント管理概要 (`/admin/tenancy`)
#[component]
pub fn TenancyOverview() -> impl IntoView {
    let data = LocalResource::new(|| async {
        // `Result::and_then` takes a synchronous closure; `.json()` is async,
        // so the fetch/parse must be sequenced with an explicit match rather
        // than chained through `and_then` (RFC 127 R3).
        match gloo_net::http::Request::get("/admin/tenancy.json")
            .header("Accept", "application/json")
            .send().await
        {
            Ok(r)  => r.json::<OverviewData>().await.ok(),
            Err(_) => None,
        }
    });

    view! {
        <main lang="ja">
            <h1>"テナント管理"</h1>
            <nav>
                <ul>
                    <li><a href="/admin/tenancy/tenants">"テナント一覧"</a></li>
                    <li><a href="/admin/tenancy/tenants/new">"テナント作成"</a></li>
                    <li><a href="/admin/console">"← コンソール"</a></li>
                </ul>
            </nav>
            <Suspense fallback=|| view! { <p aria-busy="true">"読み込み中…"</p> }>
                {move || data.get().map(|d| match d {
                    Some(d) => view! {
                        <p>"登録テナント数: " <strong>{d.tenant_count}</strong></p>
                    }.into_any(),
                    None => view! { <p>"テナント数を取得できませんでした。"</p> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

// ─── Tenants list (/admin/tenancy/tenants) ───────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
struct TenantsData { tenants: Vec<Tenant> }

/// テナント一覧 (`/admin/tenancy/tenants`)
#[component]
pub fn TenancyTenants() -> impl IntoView {
    let data = LocalResource::new(|| async {
        match gloo_net::http::Request::get("/admin/tenancy/tenants.json")
            .header("Accept", "application/json")
            .send().await
        {
            Ok(r)  => r.json::<TenantsData>().await.ok(),
            Err(_) => None,
        }
    });

    view! {
        <main lang="ja">
            <h1>"テナント一覧"</h1>
            <p><a href="/admin/tenancy">"← テナント管理"</a></p>
            <p><a href="/admin/tenancy/tenants/new">"新規テナント作成"</a></p>
            <Suspense fallback=|| view! { <p aria-busy="true">"読み込み中…"</p> }>
                {move || data.get().map(|d| match d {
                    Some(d) if d.tenants.is_empty() => view! {
                        <p>"テナントがまだ登録されていません。"</p>
                    }.into_any(),
                    Some(d) => view! {
                        <table>
                            <thead><tr>
                                <th>"スラッグ"</th>
                                <th>"表示名"</th>
                                <th>"ステータス"</th>
                                <th>"操作"</th>
                            </tr></thead>
                            <tbody>
                                <For each=move || d.tenants.clone()
                                     key=|t| t.id.clone()
                                     children=|t| view! {
                                         <tr>
                                             <td><code>{t.slug.clone()}</code></td>
                                             <td>{t.display_name.clone()}</td>
                                             <td>{format!("{:?}", t.status)}</td>
                                             <td>
                                                 <a href=format!("/admin/tenancy/tenants/{}", t.id)>
                                                     "詳細"
                                                 </a>
                                             </td>
                                         </tr>
                                     }
                                />
                            </tbody>
                        </table>
                    }.into_any(),
                    None => view! { <p role="alert">"データを取得できませんでした。"</p> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

// ─── Tenant detail (/admin/tenancy/tenants/:tid) ─────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
struct TenantDetailData { csrf_token: String }

/// テナント詳細 (`/admin/tenancy/tenants/:tid`)
#[component]
pub fn TenancyTenantDetail() -> impl IntoView {
    let params = use_params_map();
    let tid = move || params.with(|p| p.get("tid").unwrap_or_default());
    let data = {
        let tid = tid.clone();
        LocalResource::new(move || {
            let tid = tid();
            async move {
                match gloo_net::http::Request::get(&format!("/admin/tenancy/tenants/{tid}/detail.json"))
                    .header("Accept", "application/json")
                    .send().await
                {
                    Ok(r)  => r.json::<TenantDetailData>().await.ok(),
                    Err(_) => None,
                }
            }
        })
    };

    view! {
        <main lang="ja">
            <h1>"テナント詳細"</h1>
            <p><a href="/admin/tenancy/tenants">"← テナント一覧"</a></p>
            <Suspense fallback=|| view! { <p aria-busy="true">"読み込み中…"</p> }>
                {move || {
                    let t = tid();
                    data.get().map(|d| match d {
                        Some(d) => view! {
                            <div>
                                <section>
                                    <h2>"操作"</h2>
                                    <ul>
                                        <li>
                                            <a href=format!("/admin/tenancy/tenants/{t}/status")>
                                                "ステータス変更"
                                            </a>
                                        </li>
                                        <li>
                                            <a href=format!("/admin/tenancy/tenants/{t}/subscription/history")>
                                                "サブスクリプション履歴"
                                            </a>
                                        </li>
                                        <li>
                                            <a href=format!("/admin/tenancy/tenants/{t}/subscription/plan")>
                                                "プラン変更"
                                            </a>
                                        </li>
                                        <li>
                                            <a href=format!("/admin/tenancy/tenants/{t}/memberships/new")>
                                                "メンバー追加"
                                            </a>
                                        </li>
                                    </ul>
                                </section>
                                <p class="sr-only">"csrf: "{d.csrf_token}</p>
                            </div>
                        }.into_any(),
                        None => view! { <p role="alert">{tenant_detail_fetch_failure_message()}</p> }.into_any(),
                    })
                }}
            </Suspense>
        </main>
    }
}

/// Fixed text `TenancyTenantDetail` shows when its fetch does not
/// succeed -- a network error, a non-200 status, or (what the broken
/// `/admin/tenancy/tenants/{tid}.json` URL this RFC fixes actually
/// produced) a 200 whose body isn't `TenantDetailData`-shaped all
/// collapse into `None` via `.ok()`, undistinguished. RFC 162 §2
/// leaves that collapse exactly as it was rather than fixing it in
/// passing; this pins the one thing that IS a decision -- the message
/// itself -- as the witness for what the caller sees when it fails.
fn tenant_detail_fetch_failure_message() -> &'static str {
    "データを取得できませんでした。"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_failure_message_is_the_pinned_text() {
        assert_eq!(tenant_detail_fetch_failure_message(), "データを取得できませんでした。");
    }
}
