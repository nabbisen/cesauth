//! Originally part of `crates/core/src/i18n/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;

// Plural (RFC 107 — ADR-013 §Q4 plural-side closure)
// =====================================================================

#[test]
fn plural_for_en_follows_cldr_cardinal_rules() {
    // CLDR EN: `one` ↔ `n == 1`; everything else (including 0) is `other`.
    assert_eq!(plural_for(Locale::En, 0),   Plural::Other);
    assert_eq!(plural_for(Locale::En, 1),   Plural::One);
    assert_eq!(plural_for(Locale::En, 2),   Plural::Other);
    assert_eq!(plural_for(Locale::En, 5),   Plural::Other);
    assert_eq!(plural_for(Locale::En, 100), Plural::Other);
    // Big number: rule applies to u64 range without overflow.
    assert_eq!(plural_for(Locale::En, u64::MAX), Plural::Other);
}

#[test]
fn plural_for_ja_is_always_other() {
    // Japanese is plural-invariant in CLDR.
    for n in [0u64, 1, 2, 5, 100, 1_000_000, u64::MAX] {
        assert_eq!(plural_for(Locale::Ja, n), Plural::Other,
            "JA plural rule violated for n={n}");
    }
}

#[test]
fn lookup_plural_en_uses_singular_for_one() {
    let s = lookup_plural(MessageKey::SecurityRecoveryRemaining, Locale::En, 1);
    assert_eq!(s, "1 valid recovery code");
    // The singular form bakes "1" into the string, so no placeholder.
    assert!(!s.contains("{n}"),
        "EN One form should not carry a placeholder — it's hard-coded singular");
}

#[test]
fn lookup_plural_en_uses_plural_with_placeholder_for_other() {
    let s = lookup_plural(MessageKey::SecurityRecoveryRemaining, Locale::En, 5);
    assert_eq!(s, "{n} valid recovery codes");
    assert!(s.contains("{n}"),
        "EN Other form must carry {{n}} placeholder for caller substitution");
}

#[test]
fn lookup_plural_ja_is_plural_invariant() {
    // Every count returns the same JA string.
    let s0 = lookup_plural(MessageKey::SecurityRecoveryRemaining, Locale::Ja, 0);
    let s1 = lookup_plural(MessageKey::SecurityRecoveryRemaining, Locale::Ja, 1);
    let s2 = lookup_plural(MessageKey::SecurityRecoveryRemaining, Locale::Ja, 2);
    let s5 = lookup_plural(MessageKey::SecurityRecoveryRemaining, Locale::Ja, 5);
    assert_eq!(s0, s1);
    assert_eq!(s1, s2);
    assert_eq!(s2, s5);
    assert!(s0.contains("{n}"),
        "JA form must carry {{n}} placeholder for caller substitution");
}

#[test]
fn is_plural_aware_registers_security_recovery_remaining() {
    // Closed-set documentation. Adding a plural-aware key requires
    // updating this list AND adding match arms in lookup_plural.
    assert!(is_plural_aware(MessageKey::SecurityRecoveryRemaining));
}

#[test]
fn is_plural_aware_rejects_non_plural_keys() {
    // Sample non-plural-aware keys. Calling lookup_plural on these
    // would panic; is_plural_aware lets callers gate without the panic.
    assert!(!is_plural_aware(MessageKey::SecurityRecoveryZeroTitle));
    assert!(!is_plural_aware(MessageKey::SecurityRecoveryOneTitle));
    assert!(!is_plural_aware(MessageKey::FlashTotpEnabled));
}

#[test]
#[should_panic(expected = "not plural-aware")]
fn lookup_plural_panics_on_non_plural_aware_key() {
    // Guardrail: passing a non-plural-aware key is a programming error,
    // not a runtime fallback. Panic surfaces it during dev.
    let _ = lookup_plural(MessageKey::FlashTotpEnabled, Locale::En, 1);
}
