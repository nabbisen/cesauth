//! Stepper.
//!
//! Used in role assignment, TOTP enrollment, magic link + TOTP flow.

use leptos::prelude::*;

#[derive(Clone, Debug)]
pub struct Step {
    pub label: String,
    pub state: StepState,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StepState {
    Done,
    Current,
    Upcoming,
}

#[component]
pub fn Stepper(steps: Vec<Step>) -> impl IntoView {
    view! {
        <ol class="steps" aria-label="Progress">
            {steps.into_iter().enumerate().map(|(i, s)| {
                let cls = match s.state {
                    StepState::Done => "step step-done",
                    StepState::Current => "step step-current",
                    StepState::Upcoming => "step",
                };
                let n = (i + 1).to_string();
                let label = s.label.clone();
                view! {
                    <li
                        class=cls
                        aria-current=if s.state == StepState::Current { "step" } else { "" }
                    >
                        <span class="step-num">{n}</span>
                        <span>{label}</span>
                    </li>
                }
            }).collect::<Vec<_>>()}
        </ol>
    }
}
