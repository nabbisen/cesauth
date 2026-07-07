//! Leptos application root (Phase B proof-of-concept).
//!
//! This module is the entry point for the Leptos CSR bundle.  During
//! Phase B of the Leptos migration the sole purpose is to prove that
//! the build pipeline (Trunk → WASM bundle → Workers Static Assets →
//! HTML shell → browser hydration) works end-to-end.
//!
//! The `App` component will be replaced with a real Leptos router and
//! page components as individual screens are migrated in Phase C
//! (v0.79.2 onward).

use leptos::prelude::*;

/// Root component — mounted by `leptos_start()` in `lib.rs`.
///
/// Phase B: renders a single counter page at `/__leptos` to confirm
/// the pipeline is operational.  Replace with `<Router>` + pages in
/// Phase C.
#[component]
pub fn App() -> impl IntoView {
    view! {
        <main>
            <Counter/>
        </main>
    }
}

/// A minimal counter demonstrating reactive state.
///
/// This is the canonical "Leptos works" smoke test.  It has no
/// product meaning and will be removed when Phase C replaces this
/// module with real screens.
#[component]
fn Counter() -> impl IntoView {
    let (count, set_count) = signal(0_i32);

    view! {
        <div class="leptos-poc" style="font-family:sans-serif;padding:2rem">
            <h1>"cesauth — Leptos Phase B PoC"</h1>
            <p>
                "This page confirms that the Trunk → WASM → Workers "
                "Static Assets → HTML shell pipeline is working."
            </p>
            <hr/>
            <p>"Counter: " <strong>{count}</strong></p>
            <button on:click=move |_| set_count.update(|n| *n += 1)>
                "+1"
            </button>
            " "
            <button on:click=move |_| set_count.set(0)>
                "Reset"
            </button>
            <hr/>
            <p style="color:gray;font-size:0.85rem">
                "Phase C will replace this with real screens. "
                "See RFC 115 and the migration plan."
            </p>
        </div>
    }
}
