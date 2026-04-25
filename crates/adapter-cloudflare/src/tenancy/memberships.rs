//! `MembershipRepository` D1 adapter.
//!
//! One Rust struct backs three D1 tables. Each method is a simple
//! INSERT/DELETE/SELECT pair; no JOIN is needed because the trait
//! is shaped around lookups by either side of the relation.

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::tenancy::ports::MembershipRepository;
use cesauth_core::tenancy::types::{
    GroupMembership, OrganizationMembership, OrganizationRole,
    TenantMembership, TenantMembershipRole,
};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareMembershipRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareMembershipRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareMembershipRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareMembershipRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

// -------------------------------------------------------------------------
// Row shapes
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct TenantMembershipRow {
    tenant_id: String,
    user_id:   String,
    role:      String,
    joined_at: i64,
}
fn parse_tenant_role(s: &str) -> PortResult<TenantMembershipRole> {
    Ok(match s {
        "owner"  => TenantMembershipRole::Owner,
        "admin"  => TenantMembershipRole::Admin,
        "member" => TenantMembershipRole::Member,
        _        => return Err(PortError::Serialization),
    })
}
fn tenant_role_str(r: TenantMembershipRole) -> &'static str {
    match r {
        TenantMembershipRole::Owner  => "owner",
        TenantMembershipRole::Admin  => "admin",
        TenantMembershipRole::Member => "member",
    }
}
impl TenantMembershipRow {
    fn into_domain(self) -> PortResult<TenantMembership> {
        Ok(TenantMembership {
            tenant_id: self.tenant_id, user_id: self.user_id,
            role: parse_tenant_role(&self.role)?, joined_at: self.joined_at,
        })
    }
}

#[derive(Deserialize)]
struct OrgMembershipRow {
    organization_id: String,
    user_id:         String,
    role:            String,
    joined_at:       i64,
}
fn parse_org_role(s: &str) -> PortResult<OrganizationRole> {
    Ok(match s {
        "admin"  => OrganizationRole::Admin,
        "member" => OrganizationRole::Member,
        _        => return Err(PortError::Serialization),
    })
}
fn org_role_str(r: OrganizationRole) -> &'static str {
    match r {
        OrganizationRole::Admin  => "admin",
        OrganizationRole::Member => "member",
    }
}
impl OrgMembershipRow {
    fn into_domain(self) -> PortResult<OrganizationMembership> {
        Ok(OrganizationMembership {
            organization_id: self.organization_id, user_id: self.user_id,
            role: parse_org_role(&self.role)?, joined_at: self.joined_at,
        })
    }
}

#[derive(Deserialize)]
struct GroupMembershipRow {
    group_id:  String,
    user_id:   String,
    joined_at: i64,
}
impl GroupMembershipRow {
    fn into_domain(self) -> GroupMembership {
        GroupMembership {
            group_id: self.group_id, user_id: self.user_id,
            joined_at: self.joined_at,
        }
    }
}

// -------------------------------------------------------------------------
// Helper: classify INSERT errors
// -------------------------------------------------------------------------

fn map_insert_err(context: &'static str, e: worker::Error) -> PortError {
    let msg = format!("{e}").to_ascii_lowercase();
    if msg.contains("unique") || msg.contains("constraint") {
        PortError::Conflict
    } else {
        run_err(context, e)
    }
}

// -------------------------------------------------------------------------
// Trait impl
// -------------------------------------------------------------------------

impl MembershipRepository for CloudflareMembershipRepository<'_> {
    // ----- tenant -----

    async fn add_tenant_membership(&self, m: &TenantMembership) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "INSERT INTO user_tenant_memberships (tenant_id, user_id, role, joined_at) \
             VALUES (?1, ?2, ?3, ?4)"
        )
            .bind(&[
                m.tenant_id.as_str().into(), m.user_id.as_str().into(),
                tenant_role_str(m.role).into(), d1_int(m.joined_at),
            ])
            .map_err(|e| run_err("tenant_membership.add bind", e))?
            .run().await
            .map_err(|e| map_insert_err("tenant_membership.add run", e))?;
        Ok(())
    }

    async fn remove_tenant_membership(&self, t: &str, u: &str) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "DELETE FROM user_tenant_memberships WHERE tenant_id = ?1 AND user_id = ?2"
        )
            .bind(&[t.into(), u.into()])
            .map_err(|e| run_err("tenant_membership.remove bind", e))?
            .run().await.map_err(|e| run_err("tenant_membership.remove run", e))?;
        Ok(())
    }

    async fn list_tenant_members(&self, t: &str) -> PortResult<Vec<TenantMembership>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT tenant_id, user_id, role, joined_at \
             FROM user_tenant_memberships WHERE tenant_id = ?1 ORDER BY joined_at"
        )
            .bind(&[t.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<TenantMembershipRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(TenantMembershipRow::into_domain).collect()
    }

    async fn list_tenants_for_user(&self, u: &str) -> PortResult<Vec<TenantMembership>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT tenant_id, user_id, role, joined_at \
             FROM user_tenant_memberships WHERE user_id = ?1 ORDER BY joined_at"
        )
            .bind(&[u.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<TenantMembershipRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(TenantMembershipRow::into_domain).collect()
    }

    // ----- organization -----

    async fn add_organization_membership(&self, m: &OrganizationMembership) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "INSERT INTO user_organization_memberships (organization_id, user_id, role, joined_at) \
             VALUES (?1, ?2, ?3, ?4)"
        )
            .bind(&[
                m.organization_id.as_str().into(), m.user_id.as_str().into(),
                org_role_str(m.role).into(), d1_int(m.joined_at),
            ])
            .map_err(|e| run_err("org_membership.add bind", e))?
            .run().await.map_err(|e| map_insert_err("org_membership.add run", e))?;
        Ok(())
    }

    async fn remove_organization_membership(&self, o: &str, u: &str) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "DELETE FROM user_organization_memberships \
             WHERE organization_id = ?1 AND user_id = ?2"
        )
            .bind(&[o.into(), u.into()])
            .map_err(|e| run_err("org_membership.remove bind", e))?
            .run().await.map_err(|e| run_err("org_membership.remove run", e))?;
        Ok(())
    }

    async fn list_organization_members(&self, o: &str) -> PortResult<Vec<OrganizationMembership>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT organization_id, user_id, role, joined_at \
             FROM user_organization_memberships WHERE organization_id = ?1 ORDER BY joined_at"
        )
            .bind(&[o.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<OrgMembershipRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(OrgMembershipRow::into_domain).collect()
    }

    async fn list_organizations_for_user(&self, u: &str) -> PortResult<Vec<OrganizationMembership>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT organization_id, user_id, role, joined_at \
             FROM user_organization_memberships WHERE user_id = ?1 ORDER BY joined_at"
        )
            .bind(&[u.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<OrgMembershipRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(OrgMembershipRow::into_domain).collect()
    }

    // ----- group -----

    async fn add_group_membership(&self, m: &GroupMembership) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "INSERT INTO user_group_memberships (group_id, user_id, joined_at) \
             VALUES (?1, ?2, ?3)"
        )
            .bind(&[
                m.group_id.as_str().into(), m.user_id.as_str().into(),
                d1_int(m.joined_at),
            ])
            .map_err(|e| run_err("group_membership.add bind", e))?
            .run().await.map_err(|e| map_insert_err("group_membership.add run", e))?;
        Ok(())
    }

    async fn remove_group_membership(&self, g: &str, u: &str) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "DELETE FROM user_group_memberships WHERE group_id = ?1 AND user_id = ?2"
        )
            .bind(&[g.into(), u.into()])
            .map_err(|e| run_err("group_membership.remove bind", e))?
            .run().await.map_err(|e| run_err("group_membership.remove run", e))?;
        Ok(())
    }

    async fn list_group_members(&self, g: &str) -> PortResult<Vec<GroupMembership>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT group_id, user_id, joined_at \
             FROM user_group_memberships WHERE group_id = ?1 ORDER BY joined_at"
        )
            .bind(&[g.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<GroupMembershipRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(GroupMembershipRow::into_domain).collect())
    }

    async fn list_groups_for_user(&self, u: &str) -> PortResult<Vec<GroupMembership>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT group_id, user_id, joined_at \
             FROM user_group_memberships WHERE user_id = ?1 ORDER BY joined_at"
        )
            .bind(&[u.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<GroupMembershipRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(GroupMembershipRow::into_domain).collect())
    }
}
