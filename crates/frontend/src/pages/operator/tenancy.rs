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
    let data = Resource::new(|| (), |_| async {
        gloo_net::http::Request::get("/admin/tenancy.json")
            .header("Accept", "application/json")
            .send().await
            .and_then(|r| async move { r.json::<OverviewData>().await })
            .await.ok()
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
    let data = Resource::new(|| (), |_| async {
        gloo_net::http::Request::get("/admin/tenancy/tenants.json")
            .header("Accept", "application/json")
            .send().await
            .and_then(|r| async move { r.json::<TenantsData>().await })
            .await.ok()
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
    let data = Resource::new(tid.clone(), |tid| async move {
        gloo_net::http::Request::get(&format!("/admin/tenancy/tenants/{tid}.json"))
            .header("Accept", "application/json")
            .send().await
            .and_then(|r| async move { r.json::<TenantDetailData>().await })
            .await.ok()
    });

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
                        None => view! { <p role="alert">"データを取得できませんでした。"</p> }.into_any(),
                    })
                }}
            </Suspense>
        </main>
    }
}

// ─── Generic placeholder for form pages ─────────────────────────────────────

/// 汎用フォームコンポーネント (テナント管理フォーム)
#[component]
pub fn TenancyFormPlaceholder(
    title:       String,
    back_href:   String,
    form_action: String,
) -> impl IntoView {
    let json_url = format!("{}.json", form_action);
    let data = Resource::new(move || json_url.clone(), |url| async move {
        gloo_net::http::Request::get(&url)
            .header("Accept", "application/json")
            .send().await.ok()
            .and_then(|r| if r.status() == 200 {
                // synchronous parse not straightforward here; use a workaround
                Some(r)
            } else { None })
    });

    view! {
        <main lang="ja">
            <h1>{title}</h1>
            <p><a href=back_href>"← 戻る"</a></p>
            <p>"フォームの読み込み中..."</p>
        </main>
    }
}
