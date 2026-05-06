//! Admin-console domain types.
//!
//! Kept to plain data structures with `Serialize`/`Deserialize` derives -
//! every storage adapter can carry these through JSON / D1 columns
//! without an intermediate struct.

use serde::{Deserialize, Serialize};

// -------------------------------------------------------------------------
// Roles & principals
// -------------------------------------------------------------------------

/// Admin role. Four levels per the spec §6.1. Stored in D1 as a lowercase
/// snake-case string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// May view every dashboard. May NOT make any change.
    ReadOnly,
    /// May view everything + re-verify safety attestations + revoke
    /// active sessions (existing admin API).
    Security,
    /// Security + may edit safety attestations, create users (existing
    /// admin API), edit thresholds.
    Operations,
    /// Operations + may manage admin tokens.
    Super,
}

impl Role {
    /// Parse from the string form stored in D1 / carried on the wire.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read_only"  => Some(Role::ReadOnly),
            "security"   => Some(Role::Security),
            "operations" => Some(Role::Operations),
            "super"      => Some(Role::Super),
            _            => None,
        }
    }

    /// Stable string representation. Matches the `rename_all` serde tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::ReadOnly   => "read_only",
            Role::Security   => "security",
            Role::Operations => "operations",
            Role::Super      => "super",
        }
    }

    /// Human-facing label for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Role::ReadOnly   => "Read-only admin",
            Role::Security   => "Security admin",
            Role::Operations => "Operations admin",
            Role::Super      => "Super admin",
        }
    }

    /// Whether this role may invoke the tenancy-console mutation forms
    /// (v0.9.0+). Mirrors `policy::role_allows(role, ManageTenancy)`
    /// — kept on `Role` itself so UI templates don't have to import
    /// the policy module just to decide whether to render an
    /// "Edit" button.
    ///
    /// Implementation note: this is a presentation-layer hint only.
    /// The authoritative gate is on the route handler. Showing or
    /// hiding the button never substitutes for `ensure_role_allows`.
    pub fn can_manage_tenancy(self) -> bool {
        matches!(self, Role::Operations | Role::Super)
    }
}

/// The resolved identity carried through an admin request.
///
/// `Serialize` is derived so the token-management JSON endpoint can
/// return a `Vec<AdminPrincipal>` as-is. Kept `Deserialize`-free on
/// purpose: adapters construct these from their own row shapes, and
/// nothing on the wire should be reviving an `AdminPrincipal` from
/// a client-provided blob.
#[derive(Debug, Clone, Serialize)]
pub struct AdminPrincipal {
    /// Opaque id. For the `ADMIN_API_KEY` bootstrap secret this is the
    /// sentinel `"super-bootstrap"`; for rows in `admin_tokens` this is
    /// the row id.
    pub id:    String,
    /// Operator-supplied label, if any. Surfaced in the UI next to the
    /// role so operators can distinguish multiple active tokens.
    pub name:  Option<String>,
    pub role:  Role,

    /// User id this token is bound to, if any. `None` means the token
    /// is a system-admin token (the kind v0.3.x and v0.4.x have
    /// always issued); `Some(uid)` means the token was issued under
    /// the v0.13.0+ user-as-bearer mechanism and is scoped to a
    /// specific row in `users`.
    ///
    /// Added in v0.11.0 as foundation work for the tenant-scoped admin
    /// surface — see ADR-002. v0.11.0 itself does not populate this
    /// field; every existing call site constructs `AdminPrincipal`
    /// with `user_id: None`. v0.13.0 introduces the resolution path
    /// that loads the value from `admin_tokens.user_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

impl AdminPrincipal {
    /// True iff this principal is a system-admin (no user binding).
    /// Used by the v0.13.0+ resolution layer to decide whether the
    /// caller is allowed to hit `/admin/tenancy/*` (system-admin only)
    /// vs `/admin/t/<slug>/*` (user-as-bearer only).
    ///
    /// Added in v0.11.0 alongside `user_id`. Until v0.13.0 wires up
    /// the resolution path, every constructed `AdminPrincipal` has
    /// `user_id == None`, so this method returns `true` everywhere
    /// — preserving the v0.10.0 behavior where the system-admin
    /// console accepts every authenticated principal.
    pub fn is_system_admin(&self) -> bool {
        self.user_id.is_none()
    }
}

// -------------------------------------------------------------------------
// Actions & policy
// -------------------------------------------------------------------------

/// Coarse categories of operations the console exposes. The
/// [`policy::role_allows`](super::policy::role_allows) function maps
/// (role, action) -> bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAction {
    /// Read any console dashboard (Overview, Cost, Safety, Audit, Config,
    /// Alerts). Everyone with a valid token can do this.
    ViewConsole,
    /// Stamp `last_verified_at` on a bucket safety row without changing
    /// the attested values.
    VerifyBucketSafety,
    /// Change the attested values on a bucket safety row. This is the
    /// §7 "危険操作" class - preview + confirm, audit logged.
    EditBucketSafety,
    /// Update an alert threshold.
    EditThreshold,
    /// Existing admin API: create a user.
    CreateUser,
    /// Existing admin API: revoke a session.
    RevokeSession,
    /// Create / disable an admin token. Super-only per §6.1.
    ManageAdminTokens,

    /// Read tenancy data (tenants / organizations / groups / role
    /// assignments / subscriptions). New in v0.7.0; the API surface
    /// at `/api/v1/...` gates list / get operations on this. Every
    /// valid role can do this — admin tokens already pass a trust
    /// boundary, so read-only inspection of the tenancy state is
    /// freely available to operator staff.
    ViewTenancy,

    /// Mutate tenancy data (create / update / delete tenants,
    /// organizations, groups; assign / revoke roles; change plans
    /// or subscription status). Operations+ per the 4-role matrix
    /// — Security alone does not get to provision new tenants. The
    /// audit trail recorded by every mutation handler captures
    /// who-did-what for forensic recovery.
    ManageTenancy,
}

// -------------------------------------------------------------------------
// Cost snapshots & dashboards
// -------------------------------------------------------------------------

/// A single metric value taken at a single moment. Values are `u64`
/// so the JSON wire format is unambiguous across browsers and jq.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metric {
    pub key:   String,
    pub value: u64,
    pub unit:  MetricUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricUnit {
    Count,
    Bytes,
    Permille,
    Seconds,
}

impl MetricUnit {
    /// Human-facing suffix for the UI.
    pub fn label(self) -> &'static str {
        match self {
            MetricUnit::Count    => "",
            MetricUnit::Bytes    => "bytes",
            MetricUnit::Permille => "‰",
            MetricUnit::Seconds  => "s",
        }
    }
}

/// Snapshot for a single service at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSnapshot {
    pub service:  ServiceId,
    pub taken_at: i64,
    pub metrics:  Vec<Metric>,
}

/// The six services the console tracks, per §3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceId {
    Workers,
    D1,
    DurableObjects,
    Kv,
    R2,
    Turnstile,
}

impl ServiceId {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceId::Workers        => "workers",
            ServiceId::D1             => "d1",
            ServiceId::DurableObjects => "durable_objects",
            ServiceId::Kv             => "kv",
            ServiceId::R2             => "r2",
            ServiceId::Turnstile      => "turnstile",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ServiceId::Workers        => "Workers",
            ServiceId::D1             => "D1",
            ServiceId::DurableObjects => "Durable Objects",
            ServiceId::Kv             => "KV",
            ServiceId::R2             => "R2",
            ServiceId::Turnstile      => "Turnstile",
        }
    }

    pub const ALL: [ServiceId; 6] = [
        ServiceId::Workers,
        ServiceId::D1,
        ServiceId::DurableObjects,
        ServiceId::Kv,
        ServiceId::R2,
        ServiceId::Turnstile,
    ];
}

/// Delta between a "current" snapshot and a "previous" baseline. The
/// previous may be missing (first observation); in that case
/// `previous_taken_at` is `None` and `change_permille` is `None`.
#[derive(Debug, Clone, Serialize)]
pub struct CostTrend {
    pub service:            ServiceId,
    pub current:            CostSnapshot,
    pub previous_taken_at:  Option<i64>,
    /// Change relative to previous, per metric. In permille (parts per
    /// thousand) so a UI can print "+12.3%" as "12.3‰" × 0.1.
    pub changes_permille:   Vec<(String, Option<i64>)>,
    /// Whether any metric exceeds its configured threshold.
    pub breaches_threshold: bool,
    /// Short human-facing note, e.g. "informational only, see CF dashboard
    /// for authoritative numbers".
    pub note:               Option<&'static str>,
}

// -------------------------------------------------------------------------
// Data safety
// -------------------------------------------------------------------------

/// Operator-attested state of one R2 bucket. The actual bucket
/// configuration lives on Cloudflare's side; this is what the operator
/// LAST CONFIRMED it to be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketSafetyState {
    pub bucket:               String,
    pub public:               bool,
    pub cors_configured:      bool,
    pub bucket_lock:          bool,
    pub lifecycle_configured: bool,
    pub event_notifications:  bool,
    pub notes:                Option<String>,
    /// Unix seconds of the last `verify` click. None means never verified.
    pub last_verified_at:     Option<i64>,
    /// Principal name or id that stamped it.
    pub last_verified_by:     Option<String>,
    pub updated_at:           i64,
}

/// Whole-report shape for the Data Safety Dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct DataSafetyReport {
    pub buckets:              Vec<BucketSafetyState>,
    /// True iff every tracked bucket has been verified within the
    /// `safety.bucket.verification_staleness_days` threshold.
    pub all_fresh:            bool,
    /// Number of buckets with `public == true`. Surfaced prominently
    /// because accidental public R2 is a top-category data incident.
    pub public_bucket_count:  u32,
    pub staleness_threshold_days: u32,
}

// -------------------------------------------------------------------------
// Alerts
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertLevel {
    Info,
    Warn,
    Critical,
}

impl AlertLevel {
    pub fn label(self) -> &'static str {
        match self {
            AlertLevel::Info     => "info",
            AlertLevel::Warn     => "warn",
            AlertLevel::Critical => "critical",
        }
    }
}

/// A single alert produced by the alert engine. Intentionally a small
/// shape: the UI will mostly show `title` + `detail` + `level`.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub level:   AlertLevel,
    pub kind:    AlertKind,
    pub title:   String,
    pub detail:  String,
    /// Unix seconds when the condition was observed. Alerts are not
    /// persisted across requests; this is "as of now".
    pub raised_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// A cost metric crossed its configured threshold.
    CostThresholdExceeded,
    /// A bucket safety attestation is older than the staleness threshold.
    BucketSafetyStale,
    /// A bucket is attested public. Always flagged, even for ASSETS
    /// bucket - operator should confirm intent.
    BucketIsPublic,
    /// No snapshot has been recorded in this window; the trend display
    /// can't compute a change.
    MissingBaseline,
    /// Admin token auth failed repeatedly in the recent past.
    AdminLoginAnomaly,
}

// -------------------------------------------------------------------------
// Overview
// -------------------------------------------------------------------------

/// Payload behind the Overview page (§4.1).
#[derive(Debug, Clone, Serialize)]
pub struct OverviewSummary {
    pub as_of:                 i64,
    pub principal:             AdminPrincipalSummary,
    pub alert_counts:          AlertCounts,
    pub recent_alerts:         Vec<Alert>,
    pub last_audit_events:     Vec<AdminAuditEntry>,
    pub last_verified_buckets: Vec<BucketSafetyState>,
}

/// Role + name in a form that's safe to serialize (principal.id omitted
/// from the serialized overview to avoid surfacing it in HTML).
#[derive(Debug, Clone, Serialize)]
pub struct AdminPrincipalSummary {
    pub name: Option<String>,
    pub role: Role,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AlertCounts {
    pub critical: u32,
    pub warn:     u32,
    pub info:     u32,
}

impl AlertCounts {
    pub fn from_alerts(alerts: &[Alert]) -> Self {
        let mut c = Self::default();
        for a in alerts {
            match a.level {
                AlertLevel::Critical => c.critical += 1,
                AlertLevel::Warn     => c.warn     += 1,
                AlertLevel::Info     => c.info     += 1,
            }
        }
        c
    }
}

// -------------------------------------------------------------------------
// Audit entries
// -------------------------------------------------------------------------

/// A single admin-relevant audit entry as the console will render it.
/// Projected from `cesauth_core::ports::audit::AuditEventRow` for the
/// admin search and overview views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditEntry {
    pub ts:      i64,
    pub id:      String,
    pub kind:    String,
    pub subject: Option<String>,
    pub client:  Option<String>,
    pub reason:  Option<String>,
    /// Stable reference for the UI to link or display alongside
    /// the row. v0.32.0+: the chain sequence number formatted as
    /// `seq=N`. The UI renders this verbatim; treat as opaque.
    pub key:     String,
}

/// Filter applied when searching audit events.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Date prefix `audit/YYYY/MM/DD/`. Carried for backward
    /// compatibility with the v0.31.x admin search form; the
    /// v0.32.0 D1 backend ignores it (the date is derived from
    /// the `since`/`until` filters or the default
    /// "newest first" ordering).
    pub prefix: Option<String>,
    pub limit:  Option<u32>,
    /// Match events whose `kind` contains this substring.
    pub kind_contains:    Option<String>,
    pub subject_contains: Option<String>,
}

// -------------------------------------------------------------------------
// Change operations
// -------------------------------------------------------------------------

/// Input to [`service::apply_bucket_safety_change`]. The caller has
/// already confirmed via a two-step preview; this struct is the commit
/// payload.
#[derive(Debug, Clone)]
pub struct BucketSafetyChange {
    pub bucket:                    String,
    pub public:                    bool,
    pub cors_configured:           bool,
    pub bucket_lock:               bool,
    pub lifecycle_configured:      bool,
    pub event_notifications:       bool,
    pub notes:                     Option<String>,
}

/// Shape of the "preview" payload for §7's two-step confirmation: shows
/// what's currently stored vs what the caller proposed.
#[derive(Debug, Clone, Serialize)]
pub struct BucketSafetyDiff {
    pub bucket:   String,
    pub current:  BucketSafetyState,
    pub proposed: BucketSafetyChange,
    /// Fields that actually change. Presented in the UI as an itemized
    /// list so the operator can see what they're about to do.
    pub changed_fields: Vec<&'static str>,
}

impl serde::Serialize for BucketSafetyChange {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("BucketSafetyChange", 7)?;
        st.serialize_field("bucket",                    &self.bucket)?;
        st.serialize_field("public",                    &self.public)?;
        st.serialize_field("cors_configured",           &self.cors_configured)?;
        st.serialize_field("bucket_lock",               &self.bucket_lock)?;
        st.serialize_field("lifecycle_configured",      &self.lifecycle_configured)?;
        st.serialize_field("event_notifications",       &self.event_notifications)?;
        st.serialize_field("notes",                     &self.notes)?;
        st.end()
    }
}

/// Outcome of a completed change - returned from a commit endpoint so
/// the UI can render a before/after summary.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeOutcome<T> {
    pub before: T,
    pub after:  T,
}

// -------------------------------------------------------------------------
// Thresholds
// -------------------------------------------------------------------------

/// Alert threshold row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Threshold {
    pub name:        String,
    pub value:       i64,
    pub unit:        String,
    pub description: Option<String>,
    pub updated_at:  i64,
}

/// Well-known threshold names. Using constants rather than an enum
/// because adapters read these as free-form `TEXT` and we want to allow
/// operator-added custom thresholds without a schema change.
pub mod threshold_names {
    pub const D1_ROW_COUNT_WARN:                 &str = "cost.d1.row_count.warn";
    pub const R2_OBJECT_COUNT_WARN:              &str = "cost.r2.object_count.warn";
    pub const R2_BYTES_WARN:                     &str = "cost.r2.bytes.warn";
    pub const BUCKET_VERIFICATION_STALENESS_DAYS: &str = "safety.bucket.verification_staleness_days";
    pub const AUDIT_WRITE_FAILURE_RATIO_WARN:    &str = "audit.write_failure_ratio.warn";
}
