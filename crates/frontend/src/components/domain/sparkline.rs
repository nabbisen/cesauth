//! SignInVolumeSparkline — RFC 026.
//!
//! Imported from the mockup repository's `src/components/
//! domain/sparkline.rs` at pin `df3d9d0` (RFC 180, R2b). Pure SVG
//! sparkline. Accessible via role="img" + aria-label + figcaption.
//!
//! **Fixed a mockup quirk**: the source locally defined its own `fn
//! t(msg) -> &'static str { crate::i18n::en::lookup(msg) }`, which
//! always rendered the "last 24h" caption in English regardless of
//! locale. This import gives the component a proper `locale: Locale`
//! prop through `cesauth_core::i18n::lookup` instead of carrying that
//! inconsistency forward.

use leptos::prelude::*;

use cesauth_core::i18n::{lookup, Locale, MessageKey};

#[component]
pub fn SignInVolumeSparkline(
    #[prop(into)] title: String,
    successes: Vec<u32>,
    #[prop(optional)] failures: Option<Vec<u32>>,
    total: u32,
    #[prop(optional)] total_failures: Option<u32>,
    #[prop(into)] annotation: String,
    #[prop(default = Locale::default())] locale: Locale,
) -> impl IntoView {
    let max_val = successes
        .iter()
        .copied()
        .chain(
            failures
                .as_ref()
                .map(|v| v.iter().copied())
                .into_iter()
                .flatten(),
        )
        .max()
        .unwrap_or(1)
        .max(1);
    let n = successes.len().max(1);
    let w = 280.0f32;
    let h = 40.0f32;
    let step = w / (n as f32 - 1.0).max(1.0);

    let polyline = |series: &[u32], color: &'static str, dashed: bool| -> String {
        let pts: String = series
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let x = i as f32 * step;
                let y = h - (v as f32 / max_val as f32 * (h - 4.0)) - 2.0;
                format!("{x:.1},{y:.1}")
            })
            .collect::<Vec<_>>()
            .join(" ");
        let dash = if dashed {
            " stroke-dasharray=\"4 2\""
        } else {
            ""
        };
        format!(
            "<polyline fill=\"none\" stroke=\"{color}\" stroke-width=\"2\"{dash} points=\"{pts}\"/>"
        )
    };

    let success_line = polyline(&successes, "var(--color-action-primary)", false);
    let failure_line = failures
        .as_ref()
        .map(|f| polyline(f, "var(--color-status-danger-text)", true))
        .unwrap_or_default();

    let summary = match (total_failures, &failures) {
        (Some(tf), Some(_)) => format!("{total} successful · {tf} failed"),
        _ => format!("{total} sign-ins"),
    };

    let aria_label = format!("{title}. {summary}. {annotation}");
    let title_c = title.clone();

    view! {
        <figure role="img" aria-label=aria_label class="sparkline-figure">
            <div class="row row-between" style="margin-bottom:4px">
                <span class="text-small" style="font-weight:600">{title_c}</span>
                <span class="text-small text-muted">{lookup(MessageKey::SignInVolumeLast24h, locale)}</span>
            </div>
            <div style="font-size:1.25rem;font-weight:700;margin-bottom:4px">{summary.clone()}</div>
            <div inner_html=format!(
                "<svg viewBox=\"0 0 {w} {h}\" xmlns=\"http://www.w3.org/2000/svg\" aria-hidden=\"true\">{success_line}{failure_line}</svg>"
            ) style="overflow:hidden;border-radius:2px"/>
            <figcaption class="text-small text-muted" style="margin-top:4px">{annotation}</figcaption>
        </figure>
    }
}
