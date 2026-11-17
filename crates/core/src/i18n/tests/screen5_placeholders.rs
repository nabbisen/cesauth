//! RFC 185 §5.3 screen 5, T6.
//!
//! Four keys carry a `{name}` placeholder that the frontend substitutes
//! at render time — two via `split_once` (the delete/rotate confirm
//! sentences, which keep the client name bold) and two via a plain
//! `.replace` (the secret-reveal headings, which never bolded the name).
//! Either substitution silently drops the client name if a translator's
//! edit removes the placeholder, or silently mangles the sentence if an
//! edit doubles it — `split_once` would then split on the first copy and
//! leave the second sitting in rendered prose. This is the assertion
//! nothing else makes: `no_two_keys_share_text_within_a_locale` doesn't
//! look inside a value, and the ceiling only counts literals outside the
//! catalog.

use super::super::*;

fn placeholder_count(key: MessageKey, locale: Locale) -> usize {
    lookup(key, locale).matches("{name}").count()
}

#[test]
fn delete_confirm_body_has_exactly_one_placeholder_in_both_locales() {
    assert_eq!(placeholder_count(MessageKey::ClientsDeleteConfirmBody, Locale::Ja), 1);
    assert_eq!(placeholder_count(MessageKey::ClientsDeleteConfirmBody, Locale::En), 1);
}

#[test]
fn rotate_confirm_body_has_exactly_one_placeholder_in_both_locales() {
    assert_eq!(placeholder_count(MessageKey::ClientsRotateConfirmBody, Locale::Ja), 1);
    assert_eq!(placeholder_count(MessageKey::ClientsRotateConfirmBody, Locale::En), 1);
}

#[test]
fn secret_reveal_heading_rotate_has_exactly_one_placeholder_in_both_locales() {
    assert_eq!(placeholder_count(MessageKey::ClientsSecretRevealHeadingRotate, Locale::Ja), 1);
    assert_eq!(placeholder_count(MessageKey::ClientsSecretRevealHeadingRotate, Locale::En), 1);
}

#[test]
fn secret_reveal_heading_create_has_exactly_one_placeholder_in_both_locales() {
    assert_eq!(placeholder_count(MessageKey::ClientsSecretRevealHeadingCreate, Locale::Ja), 1);
    assert_eq!(placeholder_count(MessageKey::ClientsSecretRevealHeadingCreate, Locale::En), 1);
}
