//! Domain-specific widgets with no fixed home in a single shell.

pub mod role_impact;
pub use role_impact::RoleImpactPreview;
pub mod secret_reveal;
pub use secret_reveal::SecretRevealControl;
pub mod sparkline;
pub use sparkline::SignInVolumeSparkline;
