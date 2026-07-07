//! Leptos application root with client-side router.
//!
//! The `App` component is the single mount point for the Leptos CSR
//! bundle.  It owns the `<Router>` and declares every client-side
//! route.  Routes are added here as screens are migrated from the
//! old string-template layer.
//!
//! ## Route ownership
//!
//! `leptos_router` handles URL parsing and renders the matching
//! `<Route>` component.  The backend still owns the initial HTTP
//! response (returning the HTML shell); the router takes over all
//! subsequent navigation.
//!
//! ## Adding a new screen
//!
//! 1. Create `crates/frontend/src/pages/<screen>.rs`.
//! 2. Add `pub mod <screen>;` to `crates/frontend/src/pages/mod.rs`.
//! 3. Add a `<Route path=… view=…/>` entry below.
//! 4. Add/update the corresponding backend route to return the Leptos
//!    HTML shell instead of the old string template.

use leptos::prelude::*;
use leptos_router::components::{Router, Routes, Route};

use crate::pages::login::Login;
use crate::pages::security_center::SecurityCenter;
use crate::pages::sessions::Sessions;
use crate::pages::totp::{TotpDisable, TotpEnroll, TotpVerify};

// ─── Root component ──────────────────────────────────────────────────────────

/// Root Leptos component — mounted by `leptos_start()` in `lib.rs`.
#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <Routes fallback=|| view! { <NotFound/> }>
                // ── Migrated screens (Phase C) ───────────────────────
                <Route path="/"                              view=Login />
                <Route path="/login"                         view=Login />
                <Route path="/me/security"                   view=SecurityCenter />
                <Route path="/me/security/sessions"          view=Sessions />
                <Route path="/me/security/totp/enroll"       view=TotpEnroll />
                <Route path="/me/security/totp/verify"       view=TotpVerify />
                <Route path="/me/security/totp/disable"      view=TotpDisable />

                // ── Phase B PoC (remove in v0.80.0) ─────────────────
                <Route path="/__leptos" view=PocCounter />
            </Routes>
        </Router>
    }
}

// ─── Phase B PoC counter (temporary) ─────────────────────────────────────────

#[component]
fn PocCounter() -> impl IntoView {
    let (count, set_count) = signal(0_i32);
    view! {
        <div style="font-family:sans-serif;padding:2rem">
            <h1>"cesauth — Leptos Phase B PoC"</h1>
            <p>"Counter: " <strong>{count}</strong></p>
            <button on:click=move |_| set_count.update(|n| *n += 1)>"+1"</button>
            " "
            <button on:click=move |_| set_count.set(0)>"Reset"</button>
        </div>
    }
}

// ─── 404 fallback ────────────────────────────────────────────────────────────

#[component]
fn NotFound() -> impl IntoView {
    view! {
        <main>
            <h1>"Page not found"</h1>
            <p><a href="/">"Return to sign-in"</a></p>
        </main>
    }
}
