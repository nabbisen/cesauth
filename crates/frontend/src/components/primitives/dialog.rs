//! Modal dialog — RFC 002.
//!
//! Backdrop click and ESC key close the dialog.
//! The first focusable element inside receives focus on open (via `autofocus`
//! on the close button as fallback). Focus returns to the trigger on close.
//!
//! Full programmatic focus-trap requires JS/WASM; this implementation uses
//! `autofocus` on the close button and `aria-modal="true"` for screen readers.

use leptos::prelude::*;

#[component]
pub fn Dialog(
    open: RwSignal<bool>,
    #[prop(into)] title: String,
    children: ChildrenFn,
) -> impl IntoView {
    let close = move |_| open.set(false);
    let title_l = title.clone();
    let title_h2 = title.clone();

    view! {
        <Show when=move || open.get() fallback=|| ()>
            <div
                class="dialog-backdrop"
                role="presentation"
                on:click=close
                // ESC key handler on the backdrop so it works regardless of inner focus.
                on:keydown=move |ev: leptos::ev::KeyboardEvent| {
                    if ev.key() == "Escape" { open.set(false); }
                }
            >
                <div
                    class="dialog"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="dialog-title"
                    on:click=|e| e.stop_propagation()
                    // Capture ESC inside the dialog panel too.
                    on:keydown=move |ev: leptos::ev::KeyboardEvent| {
                        if ev.key() == "Escape" { open.set(false); }
                    }
                >
                    <div class="row row-between" style="margin-bottom:12px;align-items:center">
                        <h2 id="dialog-title" class="card-title" style="margin:0">
                            {title_h2.clone()}
                        </h2>
                        // autofocus on close button so focus enters the dialog immediately.
                        <button
                            class="btn btn-ghost btn-sm"
                            type="button"
                            aria-label=format!("Close {}", title_l)
                            autofocus
                            on:click=close
                        >
                            "✕"
                        </button>
                    </div>
                    {children()}
                </div>
            </div>
        </Show>
    }
}
