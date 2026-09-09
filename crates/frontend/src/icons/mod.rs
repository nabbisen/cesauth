//! Inline SVG icon library.
//!
//! All icons are small, monochrome, and inherit `currentColor` so they pick
//! up the surrounding text color from semantic tokens. No external icon font.

use leptos::prelude::*;

#[component]
pub fn IconLogo() -> impl IntoView {
    view! {
        <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true">
            <circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="2"/>
            <path d="M6 10 L9 13 L14 7" fill="none" stroke="currentColor" stroke-width="2"
                  stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

#[component]
pub fn IconKey() -> impl IntoView {
    view! {
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
            <circle cx="5" cy="11" r="3" fill="none" stroke="currentColor" stroke-width="1.5"/>
            <path d="M7 9 L13 3 M11 4 L13 6" fill="none" stroke="currentColor" stroke-width="1.5"
                  stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconMail() -> impl IntoView {
    view! {
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
            <rect x="1.5" y="3" width="13" height="10" rx="1" fill="none"
                  stroke="currentColor" stroke-width="1.5"/>
            <path d="M2 4 L8 9 L14 4" fill="none" stroke="currentColor" stroke-width="1.5"
                  stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconShield() -> impl IntoView {
    view! {
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
            <path d="M8 1 L14 3 V8 C14 11 11 13.5 8 15 C5 13.5 2 11 2 8 V3 Z"
                  fill="none" stroke="currentColor" stroke-width="1.5"
                  stroke-linejoin="round"/>
        </svg>
    }
}

#[component]
pub fn IconUsers() -> impl IntoView {
    view! {
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
            <circle cx="6" cy="6" r="2.5" fill="none" stroke="currentColor" stroke-width="1.5"/>
            <path d="M2 13 C2 10.5 4 9 6 9 C8 9 10 10.5 10 13"
                  fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            <circle cx="11.5" cy="6.5" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/>
            <path d="M11 9 C13 9 14.5 10.5 14.5 12.5"
                  fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconBuilding() -> impl IntoView {
    view! {
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
            <rect x="3" y="2" width="10" height="12" fill="none" stroke="currentColor" stroke-width="1.5"/>
            <rect x="5" y="4" width="2" height="2" fill="currentColor"/>
            <rect x="9" y="4" width="2" height="2" fill="currentColor"/>
            <rect x="5" y="8" width="2" height="2" fill="currentColor"/>
            <rect x="9" y="8" width="2" height="2" fill="currentColor"/>
            <rect x="7" y="11" width="2" height="3" fill="currentColor"/>
        </svg>
    }
}

#[component]
pub fn IconLock() -> impl IntoView {
    view! {
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
            <rect x="3" y="7" width="10" height="7" rx="1" fill="none"
                  stroke="currentColor" stroke-width="1.5"/>
            <path d="M5 7 V5 C5 3 6.5 2 8 2 C9.5 2 11 3 11 5 V7"
                  fill="none" stroke="currentColor" stroke-width="1.5"/>
        </svg>
    }
}

#[component]
pub fn IconClock() -> impl IntoView {
    view! {
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
            <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5"/>
            <path d="M8 4 V8 L11 10" fill="none" stroke="currentColor" stroke-width="1.5"
                  stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconChart() -> impl IntoView {
    view! {
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
            <path d="M2 14 H14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            <rect x="3" y="8" width="2" height="5" fill="currentColor"/>
            <rect x="7" y="5" width="2" height="8" fill="currentColor"/>
            <rect x="11" y="10" width="2" height="3" fill="currentColor"/>
        </svg>
    }
}

#[component]
pub fn IconWarning() -> impl IntoView {
    view! {
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
            <path d="M8 2 L14.5 13.5 H1.5 Z" fill="none" stroke="currentColor"
                  stroke-width="1.5" stroke-linejoin="round"/>
            <path d="M8 6 V10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            <circle cx="8" cy="12" r="0.6" fill="currentColor"/>
        </svg>
    }
}

#[component]
pub fn IconArrowRight() -> impl IntoView {
    view! {
        <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
            <path d="M3 7 H11 M8 4 L11 7 L8 10" fill="none" stroke="currentColor"
                  stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}
