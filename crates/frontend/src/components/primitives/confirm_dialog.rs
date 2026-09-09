//! ConfirmActionDialog — RFC 002 typed-phrase variant.

use crate::components::primitives::dialog::Dialog;
use leptos::prelude::*;

#[component]
pub fn ConfirmActionDialog(
    open: RwSignal<bool>,
    #[prop(into)] title: String,
    #[prop(into)] consequence: String,
    #[prop(into)] required_phrase: String,
    #[prop(into)] audit_event: String,
    on_confirm: Box<dyn Fn() + Send + Sync + 'static>,
) -> impl IntoView {
    let typed = RwSignal::new(String::new());
    let on_confirm = std::sync::Arc::new(on_confirm);
    // StoredValues hold non-reactive text that's read inside view!.
    let conseq = StoredValue::new(consequence);
    let ae = StoredValue::new(audit_event);
    let phrase = StoredValue::new(required_phrase);
    let on_confirm = std::sync::Arc::new(on_confirm);
    let title_h = StoredValue::new(title);

    // Memo: recomputed whenever `typed` changes.
    let can_confirm =
        Memo::new(move |_| typed.get().trim().to_lowercase() == phrase.get_value().to_lowercase());

    view! {
        <Dialog open=open title=title_h.get_value()>
            <p class="text-small" style="margin-bottom:12px">{conseq.get_value()}</p>
            <div class="alert alert-warning" role="note" style="margin-bottom:12px">
                <span class="alert-icon">"⚙"</span>
                <div class="alert-body">
                    "Audit event: " <code>{ae.get_value()}</code>
                    ". This action cannot be undone without a restore operation."
                </div>
            </div>
            <div class="field">
                <label class="field-label field-required" for="confirm-phrase">
                    "Type " <code>{phrase.get_value()}</code> " to confirm"
                </label>
                <input
                    class="field-input"
                    id="confirm-phrase"
                    type="text"
                    autocomplete="off"
                    on:input=move |ev| typed.set(event_target_value(&ev))
                    aria-describedby="confirm-hint"
                />
                <p id="confirm-hint" class="field-hint">
                    "This confirms you understand the consequences."
                </p>
            </div>
            <div class="row" style="margin-top:16px;gap:8px">
                <button
                    class="btn btn-danger"
                    type="button"
                    disabled=move || !can_confirm.get()
                    aria-disabled=move || (!can_confirm.get()).to_string()
                    on:click={ let oc = on_confirm.clone(); move |_| {
                        if can_confirm.get_untracked() { oc(); }
                    }}
                >
                    "Confirm"
                </button>
                <button class="btn btn-ghost" type="button"
                    on:click=move |_| open.set(false)>
                    "Cancel"
                </button>
            </div>
        </Dialog>
    }
}
