//! Page-level layout shells, one per audience.

pub mod auth_shell;
pub use auth_shell::AuthShell;
pub mod operator_shell;
pub use operator_shell::{Environment, OperatorShell};
pub mod personal_shell;
pub use personal_shell::PersonalShell;
pub mod tenant_admin_shell;
pub use tenant_admin_shell::TenantAdminShell;
