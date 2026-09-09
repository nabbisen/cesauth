//! Generic UI primitives.

pub mod alert;
pub mod badge;
pub mod confirm_dialog;
pub mod danger_zone;
pub mod dialog;
pub mod empty_state;
pub mod error_summary;
pub mod flash;
pub mod page_header;
pub mod scope_breadcrumb;
pub mod stepper;
pub mod tabs;
pub use confirm_dialog::ConfirmActionDialog;
pub use error_summary::ErrorSummary;
pub mod entity_list;
pub use entity_list::{Column, EntityCard, EntityCardRow, EntityList};
pub mod density_toggle;
pub use density_toggle::DensityToggle;
pub mod disclosure;
pub use disclosure::Disclosure;
pub mod metric_strip;
pub use metric_strip::{MetricChip, MetricStrip};
