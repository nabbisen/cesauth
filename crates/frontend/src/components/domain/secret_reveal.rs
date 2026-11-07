//! SecretRevealControl — controlled reveal/copy of one-time values.
//!
//! Imported from the mockup repository's `src/components/
//! domain/secret_reveal.rs` at pin `df3d9d0` (RFC 180, R2b). Used for
//! recovery codes and freshly issued admin tokens. The "reveal" action
//! is explicit (button), and the copy state shows feedback.
//!
//! **This is still a mockup component** — no real clipboard write
//! happens; `on:click` only flips local UI state. Imported as-is,
//! since wiring a real clipboard write is R3's job (pairing this with
//! a route), not this cycle's. The `RwSignal`s here are local button
//! state, not a locale mechanism, so RFC 180 §5's "no reactive
//! context" bar does not apply to them — only `locale` itself, a
//! plain prop, decides which strings render.

use leptos::prelude::*;

use cesauth_core::i18n::{lookup, Locale, MessageKey};

#[component]
pub fn SecretRevealControl(
    #[prop(into)] value: String,
    /// Optional aria-label for the copy button.
    #[prop(into, optional)]
    aria_label: Option<String>,
    #[prop(default = Locale::default())] locale: Locale,
) -> impl IntoView {
    let revealed = RwSignal::new(false);
    let copied = RwSignal::new(false);

    let aria = aria_label.unwrap_or_else(|| "Copy value".to_string());
    let val_for_view = value.clone();
    view! {
        <div class="card card-compact">
            <div class="row row-between">
                <code class="text-mono">
                    {move || if revealed.get() {
                        val_for_view.clone()
                    } else {
                        "•".repeat(16)
                    }}
                </code>
                <div class="row">
                    <button
                        class="btn btn-secondary btn-sm"
                        type="button"
                        on:click=move |_| revealed.update(|r| *r = !*r)
                    >
                        {move || if revealed.get() { "Hide" } else { "Reveal" }}
                    </button>
                    <button
                        class="btn btn-primary btn-sm"
                        type="button"
                        aria-label=aria.clone()
                        on:click=move |_| copied.set(true)
                    >
                        {move || if copied.get() { lookup(MessageKey::ActionCopied, locale) } else { lookup(MessageKey::ActionCopy, locale) }}
                    </button>
                </div>
            </div>
            <p class="text-small text-muted" style="margin-top:8px;margin-bottom:0">
                {lookup(MessageKey::OneTimeRevealNotice, locale)}
            </p>
        </div>
    }
}
