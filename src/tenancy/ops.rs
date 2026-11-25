//! Sole-writer tenancy management operations behind `/internal/tenancy/v1/*`.
//!
//! Each operation runs in one transaction on a raw connection and returns the WebSocket
//! kicks to deliver after commit. Tenant rows are locked `FOR UPDATE` on PostgreSQL.

use chrono::{DateTime, NaiveDateTime};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    db::{
        DbConnInner,
        models::{
            Device, TENANT_STATUS_ACTIVE, Tenant, TenantErasedSubject, TenantPendingDeletion, UserId, committed_bytes,
            lock_subject, lock_tenant, release_pending_reservations,
        },
        schema::{
            archives, attachments, auth_requests, ciphers, ciphers_collections, collections, collections_groups,
            devices, emergency_access, event, favorites, folders, folders_ciphers, groups, groups_users, org_policies,
            organization_api_key, organizations, sends, sso_users, tenant_erased_subjects, tenant_pending_deletions,
            tenant_recovery_bundles, tenants, twofactor, twofactor_incomplete, users, users_collections,
            users_organizations,
        },
    },
    error::Error,
    tenancy::{
        attachment_object_key, canonical_issuer, format_oidc_identifier, is_cell_served, is_valid_cell_slug,
        send_object_key, tenant_prefix_object_key,
    },
    util::get_uuid,
};

pub const MAX_BATCH: usize = 500;
#[expect(clippy::cast_possible_wrap, reason = "small constant")]
const MAX_BATCH_SQL: i64 = MAX_BATCH as i64;
const MAX_ID_LEN: usize = 255;
const MAX_ISSUER_LEN: usize = 1024;
const MAX_NAME_LEN: usize = 256;
const MAX_QUOTAS_LEN: usize = 8192;
const MAX_ERROR_LEN: usize = 500;
const MAX_GRANT_TTL_SECS: i64 = 900;

const STATUS_DELETED: &str = "deleted";
const STATUS_ERASING: &str = "erasing";
const STATUS_PURGE_PENDING: &str = "purge_pending";
const TOMBSTONED: [&str; 3] = [STATUS_DELETED, STATUS_ERASING, STATUS_PURGE_PENDING];
const ORG_STATUSES: [&str; 4] = [TENANT_STATUS_ACTIVE, "suspended", "deletion_scheduled", STATUS_DELETED];

const KIND_ATTACHMENT: &str = "attachment";
const KIND_SEND: &str = "send";
const KIND_TENANT_PREFIX: &str = "tenant_prefix";
const SEND_TYPE_FILE: i32 = 1;

type OpResult<T> = Result<T, Error>;

fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + serde::Deserialize<'de>,
{
    Ok(<Option<T> as serde::Deserialize>::deserialize(deserializer)?.unwrap_or_default())
}

/// WebSocket disconnects to deliver locally and across replicas once the transaction commits.
#[derive(Debug, Default)]
pub struct Kicks {
    pub users: Vec<UserId>,
    pub tenants: Vec<String>,
}

fn is_tombstoned(status: &str) -> bool {
    TOMBSTONED.contains(&status)
}

fn naive(ts: i64) -> NaiveDateTime {
    DateTime::from_timestamp(ts, 0).unwrap_or_default().naive_utc()
}

fn bad_request(msg: &str) -> Error {
    Error::new_msg(msg).with_code(400)
}

fn cell_not_served_err() -> Error {
    Error::new_msg("Tenant belongs to a cell not served by this deployment").with_code(403)
}

fn ensure_served_cells_configured(served_cells: &[String]) -> OpResult<()> {
    if served_cells.is_empty() {
        return Err(cell_not_served_err());
    }
    Ok(())
}

fn ensure_tenant_cell_served(conn: &mut DbConnInner, tid: &str, served_cells: &[String]) -> OpResult<Tenant> {
    ensure_served_cells_configured(served_cells)?;
    let Some(t) = lock_tenant(conn, tid)? else {
        return Err(cell_not_served_err());
    };
    if !is_cell_served(served_cells, &t.home_region) {
        return Err(cell_not_served_err());
    }
    Ok(t)
}

fn check_id(field: &str, value: &str, max: usize) -> OpResult<()> {
    if value.trim().is_empty() || value.len() > max {
        return Err(bad_request(&format!("Invalid {field}")));
    }
    Ok(())
}

/// Cell-scoped object key relative to the attachments root, identical to `Attachment::get_file_path_in_cell`.
fn attachment_key(cell: Option<&str>, tenant_id: Option<&str>, cipher_uuid: &str, att_id: &str) -> String {
    match (cell, tenant_id) {
        (Some(c), Some(tid)) => attachment_object_key(c, tid, cipher_uuid, att_id),
        _ => format!("{cipher_uuid}/{att_id}"),
    }
}

/// Cell-scoped object key relative to the sends root, identical to `Send::get_file_path_in_cell`.
fn send_key(cell: Option<&str>, tenant_id: Option<&str>, send_uuid: &str, file_id: &str) -> String {
    match (cell, tenant_id) {
        (Some(c), Some(tid)) => send_object_key(c, tid, send_uuid, file_id),
        _ => format!("{send_uuid}/{file_id}"),
    }
}

fn send_file_id(data: &str) -> Option<String> {
    serde_json::from_str::<Value>(data).ok()?.get("id")?.as_str().map(str::to_owned)
}

fn pending(
    tenant_id: &str,
    user_uuid: Option<&str>,
    kind: &str,
    key: String,
    now: NaiveDateTime,
) -> TenantPendingDeletion {
    TenantPendingDeletion {
        id: get_uuid(),
        tenant_id: tenant_id.to_owned(),
        user_uuid: user_uuid.map(|u| UserId::from(u.to_owned())),
        storage_kind: kind.to_owned(),
        object_key: key,
        attempts: 0,
        last_error: None,
        reserved_bytes: 0,
        created_at: now,
    }
}

fn insert_pending(conn: &mut DbConnInner, rows: &[TenantPendingDeletion]) -> QueryResult<usize> {
    for row in rows {
        diesel::insert_into(tenant_pending_deletions::table).values(row).execute(conn)?;
    }
    Ok(rows.len())
}

fn pending_count(conn: &mut DbConnInner, tenant_id: &str) -> QueryResult<i64> {
    tenant_pending_deletions::table.filter(tenant_pending_deletions::tenant_id.eq(tenant_id)).count().get_result(conn)
}

/// Whether `purge_begin` has removed the tenant's vault rows. Reconciliation can mark a tenant
/// `purge_pending` before that runs, so finishing its cleanup jobs alone does not finalize it.
fn vault_rows_purged(conn: &mut DbConnInner, tenant_id: &str) -> QueryResult<bool> {
    diesel::select(
        diesel::dsl::not(diesel::dsl::exists(users::table.filter(users::tenant_id.eq(tenant_id))))
            .and(diesel::dsl::not(diesel::dsl::exists(
                organizations::table.filter(organizations::tenant_id.eq(tenant_id)),
            )))
            .and(diesel::dsl::not(diesel::dsl::exists(ciphers::table.filter(ciphers::tenant_id.eq(tenant_id)))))
            .and(diesel::dsl::not(diesel::dsl::exists(sends::table.filter(sends::tenant_id.eq(tenant_id))))),
    )
    .get_result(conn)
}

/// Permanent `(issuer, subject)` tombstone; an existing tombstone is kept unchanged.
fn record_tombstone(conn: &mut DbConnInner, row: &TenantErasedSubject) -> QueryResult<()> {
    let exists = tenant_erased_subjects::table.find((&row.issuer, &row.subject)).count().get_result::<i64>(conn)? > 0;
    if !exists {
        diesel::insert_into(tenant_erased_subjects::table).values(row).execute(conn)?;
    }
    Ok(())
}

fn tombstone(issuer: &str, subject: &str, tenant_id: &str, revision: i64, now: NaiveDateTime) -> TenantErasedSubject {
    TenantErasedSubject {
        issuer: canonical_issuer(issuer).to_owned(),
        subject: subject.trim().to_owned(),
        tenant_id: tenant_id.to_owned(),
        revision,
        erased_at: now,
    }
}

/// Splits a stored `{issuer}/{subject}` identifier. Issuer URLs contain `/`, so the configured
/// authority is matched as a prefix first; otherwise the subject is the last path segment.
fn split_identifier<'a>(identifier: &'a str, sso_authority: &'a str) -> Option<(&'a str, &'a str)> {
    let authority = canonical_issuer(sso_authority);
    if !authority.is_empty()
        && let Some(subject) = identifier.strip_prefix(authority).and_then(|r| r.strip_prefix('/'))
        && !subject.is_empty()
    {
        return Some((authority, subject));
    }
    identifier.rsplit_once('/').filter(|(iss, sub)| !iss.is_empty() && !sub.is_empty())
}

/// Rotates refresh tokens (each device gets a fresh random token; never a shared empty value,
/// since login reuses the stored token) and forgets remembered 2FA.
fn rotate_devices(conn: &mut DbConnInner, keys: Vec<(String, String)>) -> QueryResult<()> {
    for (device, user) in keys {
        diesel::update(devices::table.filter(devices::uuid.eq(device)).filter(devices::user_uuid.eq(user)))
            .set((
                devices::refresh_token.eq(Device::generate_refresh_token()),
                devices::twofactor_remember.eq(None::<String>),
            ))
            .execute(conn)?;
    }
    Ok(())
}

/// Invalidates every access and refresh token of one user.
fn fence_user(conn: &mut DbConnInner, uid: &str, now: NaiveDateTime) -> QueryResult<()> {
    diesel::update(users::table.filter(users::uuid.eq(uid)))
        .set((
            users::security_stamp.eq(get_uuid()),
            users::stamp_exception.eq(None::<String>),
            users::updated_at.eq(now),
        ))
        .execute(conn)?;
    let keys =
        devices::table.filter(devices::user_uuid.eq(uid)).select((devices::uuid, devices::user_uuid)).load(conn)?;
    rotate_devices(conn, keys)
}

/// Invalidates every access and refresh token of every user in a tenant.
fn fence_tenant_users(conn: &mut DbConnInner, tenant_id: &str, now: NaiveDateTime) -> QueryResult<()> {
    let uids: Vec<String> = users::table.filter(users::tenant_id.eq(tenant_id)).select(users::uuid).load(conn)?;
    for uid in uids {
        fence_user(conn, &uid, now)?;
    }
    Ok(())
}

/// `(user_uuid, user.tenant_id)` for the exact `{issuer}/{subject}` SSO link, restricted to
/// `tenant_id` when given. Never matches by email or bare subject.
fn find_sso_user(
    conn: &mut DbConnInner,
    issuer: &str,
    subject: &str,
    tenant_id: Option<&str>,
) -> QueryResult<Option<(String, Option<String>)>> {
    let ident = format_oidc_identifier(issuer, subject);
    let found: Option<(String, Option<String>)> = sso_users::table
        .inner_join(users::table)
        .filter(sso_users::identifier.eq(ident))
        .select((users::uuid, users::tenant_id))
        .first(conn)
        .optional()?;
    Ok(found.filter(|(_, utid)| match tenant_id.filter(|t| !t.is_empty()) {
        Some(tid) => utid.as_deref() == Some(tid),
        None => true,
    }))
}

// ---------------------------------------------------------------------------
// orgs/reconcile

#[derive(Debug, Deserialize)]
pub struct OrgSnapshot {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub home_region: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub revision: i64,
    #[serde(default)]
    pub quotas: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ReconcileRequest {
    #[serde(default, deserialize_with = "null_as_default")]
    pub orgs: Vec<OrgSnapshot>,
    #[serde(default)]
    pub touch_all_active: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct ReconcileResponse {
    pub applied: usize,
    pub fenced_tenant_ids: Vec<String>,
    pub purge_required_tenant_ids: Vec<String>,
    pub region_mismatch_tenant_ids: Vec<String>,
}

fn quotas_json(org: &OrgSnapshot) -> OpResult<String> {
    let json = match &org.quotas {
        None | Some(Value::Null) => "{}".to_owned(),
        Some(v @ Value::Object(_)) => v.to_string(),
        Some(_) => return Err(bad_request("quotas must be an object")),
    };
    if json.len() > MAX_QUOTAS_LEN {
        return Err(bad_request("quotas too large"));
    }
    Ok(json)
}

pub fn reconcile_orgs(
    conn: &mut DbConnInner,
    req: &ReconcileRequest,
    served_cells: &[String],
    now: i64,
) -> OpResult<(ReconcileResponse, Kicks)> {
    ensure_served_cells_configured(served_cells)?;
    if req.orgs.len() > MAX_BATCH {
        return Err(bad_request("Too many orgs"));
    }
    let mut quotas = Vec::with_capacity(req.orgs.len());
    for org in &req.orgs {
        check_id("org id", &org.id, MAX_ID_LEN)?;
        if !ORG_STATUSES.contains(&org.status.as_str()) {
            return Err(bad_request("Invalid org status"));
        }
        if !is_valid_cell_slug(&org.home_region) {
            return Err(bad_request("Invalid home_region"));
        }
        quotas.push(quotas_json(org)?);
    }
    // Lock rows in a stable order.
    let mut order: Vec<usize> = (0..req.orgs.len()).collect();
    order.sort_by(|a, b| req.orgs[*a].id.cmp(&req.orgs[*b].id));
    let now_dt = naive(now);

    conn.transaction(|conn| {
        let mut resp = ReconcileResponse::default();
        let mut kicks = Kicks::default();
        for i in order {
            let org = &req.orgs[i];
            let existing = lock_tenant(conn, &org.id)?;

            // C4: orgs never move between cells or regions. If an existing tenant's stored
            // home_region differs from the incoming snapshot, never mutate home_region or org
            // metadata — fail closed by clearing authority freshness, fencing active sessions
            // and storage grants, and reporting the mismatch to the caller.
            if let Some(mut t) = existing.clone()
                && t.home_region != org.home_region
            {
                error!(
                    "C4 violation: org {} home_region changed from '{}' to '{}'; refusing move and fencing tenant",
                    t.id, t.home_region, org.home_region
                );
                t.authority_refreshed_at = None;
                t.access_epoch = t.access_epoch.saturating_add(1);
                t.storage_ceiling_bytes = 0;
                t.storage_grant_expires_at = None;
                t.updated_at = now_dt;
                fence_tenant_users(conn, &t.id, now_dt)?;
                diesel::update(tenants::table.find(&t.id)).set(&t).execute(conn)?;
                resp.fenced_tenant_ids.push(t.id.clone());
                resp.region_mismatch_tenant_ids.push(t.id.clone());
                kicks.tenants.push(t.id);
                continue;
            }

            // C5: refuse every org whose home_region is not one of this deployment's served cells.
            if !is_cell_served(served_cells, &org.home_region) {
                return Err(cell_not_served_err());
            }

            if let Some(t) = &existing {
                if is_tombstoned(&t.status) {
                    if t.status != STATUS_DELETED || t.erased_at.is_none() {
                        resp.purge_required_tenant_ids.push(t.id.clone());
                    }
                    continue;
                }
                if org.revision > 0 && t.revision > 0 && org.revision < t.revision {
                    diesel::update(tenants::table.find(&t.id))
                        .set(tenants::authority_refreshed_at.eq(Some(now)))
                        .execute(conn)?;
                    continue;
                }
            }
            let created = existing.is_none();
            let mut t = existing.unwrap_or_else(|| Tenant::new(org.id.clone(), org.home_region.clone()));
            let was_locally_active = !created && t.is_active() && is_cell_served(served_cells, &t.home_region);

            if org.status == STATUS_DELETED {
                STATUS_PURGE_PENDING.clone_into(&mut t.status);
                resp.purge_required_tenant_ids.push(t.id.clone());
            } else {
                t.status.clone_from(&org.status);
            }
            t.app_enabled = org.enabled;
            t.revision = t.revision.max(org.revision);
            t.quotas_json.clone_from(&quotas[i]);
            t.authority_refreshed_at = Some(now);
            t.updated_at = now_dt;

            let non_active = !org.enabled || org.status != TENANT_STATUS_ACTIVE;
            if non_active && (was_locally_active || created) {
                t.access_epoch = t.access_epoch.saturating_add(1);
                t.storage_ceiling_bytes = 0;
                t.storage_grant_expires_at = None;
                fence_tenant_users(conn, &t.id, now_dt)?;
                resp.fenced_tenant_ids.push(t.id.clone());
                kicks.tenants.push(t.id.clone());
            }

            if created {
                t.created_at = now_dt;
                diesel::insert_into(tenants::table).values(&t).execute(conn)?;
            } else {
                diesel::update(tenants::table.find(&t.id)).set(&t).execute(conn)?;
            }
            resp.applied += 1;
        }

        if req.touch_all_active {
            let live = tenants::table
                .filter(tenants::status.ne_all(TOMBSTONED))
                .filter(tenants::home_region.eq_any(served_cells))
                .filter(tenants::authority_refreshed_at.is_not_null())
                .filter(tenants::id.ne_all(&resp.region_mismatch_tenant_ids));
            diesel::update(live).set(tenants::authority_refreshed_at.eq(Some(now))).execute(conn)?;
        }
        Ok((resp, kicks))
    })
}

// ---------------------------------------------------------------------------
// users/logout, users/sync, users/erase

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub found: bool,
    pub user_uuid: Option<String>,
}

fn check_subject(issuer: &str, subject: &str) -> OpResult<()> {
    check_id("issuer", issuer, MAX_ISSUER_LEN)?;
    check_id("subject", subject, MAX_ID_LEN)
}

pub fn logout_user(
    conn: &mut DbConnInner,
    req: &LogoutRequest,
    served_cells: &[String],
    now: i64,
) -> OpResult<(LogoutResponse, Kicks)> {
    ensure_served_cells_configured(served_cells)?;
    check_subject(&req.issuer, &req.subject)?;
    let req_tid = req.tenant_id.as_deref().filter(|t| !t.is_empty());
    if let Some(tid) = req_tid {
        check_id("tenant_id", tid, MAX_ID_LEN)?;
    }
    conn.transaction(|conn| {
        if let Some(tid) = req_tid {
            ensure_tenant_cell_served(conn, tid, served_cells)?;
        }
        let mut kicks = Kicks::default();
        let found = find_sso_user(conn, &req.issuer, &req.subject, req_tid)?;
        if let Some((uid, utid)) = &found {
            let tid = utid.as_deref().ok_or_else(cell_not_served_err)?;
            ensure_tenant_cell_served(conn, tid, served_cells)?;
            fence_user(conn, uid, naive(now))?;
            kicks.users.push(UserId::from(uid.clone()));
        }
        Ok((
            LogoutResponse {
                found: found.is_some(),
                user_uuid: found.map(|(uid, _)| uid),
            },
            kicks,
        ))
    })
}

#[derive(Debug, Deserialize)]
pub struct SyncRequest {
    pub event_type: String,
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    pub active: bool,
}

#[derive(Debug, Serialize)]
pub struct UserStatusResponse {
    pub status: &'static str,
    pub user_uuid: Option<String>,
}

pub fn sync_user(
    conn: &mut DbConnInner,
    req: &SyncRequest,
    served_cells: &[String],
    now: i64,
) -> OpResult<(UserStatusResponse, Kicks)> {
    ensure_served_cells_configured(served_cells)?;
    if !["user.created", "user.updated", "user.deleted"].contains(&req.event_type.as_str()) {
        return Err(bad_request("Invalid event_type"));
    }
    check_subject(&req.issuer, &req.subject)?;
    let req_tid = req.tenant_id.as_deref().filter(|t| !t.is_empty());
    if let Some(tid) = req_tid {
        check_id("tenant_id", tid, MAX_ID_LEN)?;
    }
    if req.display_name.as_ref().is_some_and(|n| n.chars().count() > MAX_NAME_LEN) {
        return Err(bad_request("display_name too long"));
    }
    let now_dt = naive(now);
    conn.transaction(|conn| {
        if let Some(tid) = req_tid {
            ensure_tenant_cell_served(conn, tid, served_cells)?;
        }
        let mut kicks = Kicks::default();
        let erased = tenant_erased_subjects::table
            .find((canonical_issuer(&req.issuer), req.subject.trim()))
            .count()
            .get_result::<i64>(conn)?
            > 0;
        if erased {
            return Ok((
                UserStatusResponse {
                    status: "erased_tombstone",
                    user_uuid: None,
                },
                kicks,
            ));
        }
        let Some((uid, user_tenant)) = find_sso_user(conn, &req.issuer, &req.subject, req_tid)? else {
            return Ok((
                UserStatusResponse {
                    status: "not_found",
                    user_uuid: None,
                },
                kicks,
            ));
        };
        let user_tenant_id = user_tenant.as_deref().ok_or_else(cell_not_served_err)?;
        let tenant = ensure_tenant_cell_served(conn, user_tenant_id, served_cells)?;

        if req.event_type == "user.deleted" || !req.active {
            diesel::update(users::table.find(&uid)).set(users::enabled.eq(false)).execute(conn)?;
            fence_user(conn, &uid, now_dt)?;
            kicks.users.push(UserId::from(uid.clone()));
        } else {
            if let Some(name) = req.display_name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
                diesel::update(users::table.find(&uid))
                    .set((users::name.eq(name), users::updated_at.eq(now_dt)))
                    .execute(conn)?;
            }
            if tenant.is_active() && tenant.authority_refreshed_at.is_some() {
                diesel::update(users::table.find(&uid)).set(users::enabled.eq(true)).execute(conn)?;
            }
        }
        Ok((
            UserStatusResponse {
                status: "ok",
                user_uuid: Some(uid),
            },
            kicks,
        ))
    })
}

#[derive(Debug, Deserialize)]
pub struct EraseRequest {
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub revision: i64,
}

#[derive(Debug, Serialize)]
pub struct EraseResponse {
    pub status: &'static str,
    pub tombstone_recorded: bool,
    pub user_existed: bool,
    pub pending_deletions_queued: usize,
}

pub fn erase_user(
    conn: &mut DbConnInner,
    req: &EraseRequest,
    served_cells: &[String],
    now: i64,
) -> OpResult<(EraseResponse, Kicks)> {
    ensure_served_cells_configured(served_cells)?;
    check_subject(&req.issuer, &req.subject)?;
    let req_tid = req.tenant_id.as_deref().filter(|t| !t.is_empty());
    if let Some(tid) = req_tid {
        check_id("tenant_id", tid, MAX_ID_LEN)?;
    }
    let now_dt = naive(now);
    conn.transaction(|conn| {
        // Serializes with hosted sign-up, which rechecks the tombstone under this lock.
        lock_subject(conn, &req.issuer, &req.subject)?;
        let mut kicks = Kicks::default();
        let req_tenant = match req_tid {
            Some(tid) => Some(ensure_tenant_cell_served(conn, tid, served_cells)?),
            None => None,
        };
        let found = find_sso_user(conn, &req.issuer, &req.subject, req_tid)?;
        let user_tid = found.as_ref().and_then(|(_, t)| t.clone());
        let tenant = match (&found, &req_tenant) {
            (Some((_, Some(utid))), _) => ensure_tenant_cell_served(conn, utid, served_cells)?,
            (None, Some(t)) => t.clone(),
            (Some((_, None)), _) | (None, None) => return Err(cell_not_served_err()),
        };
        let stone_tid = tenant.id.clone();
        record_tombstone(conn, &tombstone(&req.issuer, &req.subject, &stone_tid, req.revision, now_dt))?;

        let mut queued = 0;
        if let Some((uid, _)) = &found {
            queued = erase_personal_data(conn, uid, &tenant.home_region, user_tid.as_deref(), &stone_tid, now_dt)?;
            kicks.users.push(UserId::from(uid.clone()));
            // Usage dropped; a tenant that no longer reports (e.g. suspended) must report it once.
            diesel::update(tenants::table.find(&stone_tid)).set(tenants::storage_dirty.eq(true)).execute(conn)?;
        }
        Ok((
            EraseResponse {
                status: "erased",
                tombstone_recorded: true,
                user_existed: found.is_some(),
                pending_deletions_queued: queued,
            },
            kicks,
        ))
    })
}

/// Deletes one user's personal and derived rows, preserving organization-owned ciphers,
/// collections, groups and other members' key envelopes. Object deletions are queued first.
fn erase_personal_data(
    conn: &mut DbConnInner,
    uid: &str,
    cell: &str,
    user_tid: Option<&str>,
    pending_tid: &str,
    now: NaiveDateTime,
) -> QueryResult<usize> {
    let personal = || {
        ciphers::table
            .filter(ciphers::user_uuid.eq(uid))
            .filter(ciphers::organization_uuid.is_null())
            .select(ciphers::uuid)
    };
    let folders_of = || folders::table.filter(folders::user_uuid.eq(uid)).select(folders::uuid);
    let memberships =
        || users_organizations::table.filter(users_organizations::user_uuid.eq(uid)).select(users_organizations::uuid);

    let atts: Vec<(String, String, Option<String>)> = attachments::table
        .filter(attachments::cipher_uuid.eq_any(personal()))
        .select((attachments::id, attachments::cipher_uuid, attachments::tenant_id))
        .load(conn)?;
    let file_sends: Vec<(String, String, Option<String>)> = sends::table
        .filter(sends::user_uuid.eq(uid))
        .filter(sends::organization_uuid.is_null())
        .filter(sends::atype.eq(SEND_TYPE_FILE))
        .select((sends::uuid, sends::data, sends::tenant_id))
        .load(conn)?;

    let mut rows = Vec::new();
    for (id, cipher, tid) in atts {
        let key = attachment_key(Some(cell), tid.as_deref().or(user_tid), &cipher, &id);
        rows.push(pending(pending_tid, Some(uid), KIND_ATTACHMENT, key, now));
    }
    for (send, data, tid) in file_sends {
        if let Some(file_id) = send_file_id(&data) {
            let key = send_key(Some(cell), tid.as_deref().or(user_tid), &send, &file_id);
            rows.push(pending(pending_tid, Some(uid), KIND_SEND, key, now));
        }
    }
    let queued = insert_pending(conn, &rows)?;

    diesel::delete(attachments::table.filter(attachments::cipher_uuid.eq_any(personal()))).execute(conn)?;
    diesel::delete(
        folders_ciphers::table.filter(
            folders_ciphers::cipher_uuid.eq_any(personal()).or(folders_ciphers::folder_uuid.eq_any(folders_of())),
        ),
    )
    .execute(conn)?;
    diesel::delete(ciphers_collections::table.filter(ciphers_collections::cipher_uuid.eq_any(personal())))
        .execute(conn)?;
    diesel::delete(favorites::table.filter(favorites::user_uuid.eq(uid).or(favorites::cipher_uuid.eq_any(personal()))))
        .execute(conn)?;
    diesel::delete(archives::table.filter(archives::user_uuid.eq(uid).or(archives::cipher_uuid.eq_any(personal()))))
        .execute(conn)?;
    diesel::delete(ciphers::table.filter(ciphers::user_uuid.eq(uid)).filter(ciphers::organization_uuid.is_null()))
        .execute(conn)?;
    // Organization-owned rows survive; only the creator reference goes.
    diesel::update(ciphers::table.filter(ciphers::user_uuid.eq(uid)))
        .set(ciphers::user_uuid.eq(None::<String>))
        .execute(conn)?;
    diesel::delete(folders::table.filter(folders::user_uuid.eq(uid))).execute(conn)?;
    diesel::delete(sends::table.filter(sends::user_uuid.eq(uid)).filter(sends::organization_uuid.is_null()))
        .execute(conn)?;
    diesel::update(sends::table.filter(sends::user_uuid.eq(uid)))
        .set(sends::user_uuid.eq(None::<String>))
        .execute(conn)?;

    diesel::delete(devices::table.filter(devices::user_uuid.eq(uid))).execute(conn)?;
    diesel::delete(twofactor::table.filter(twofactor::user_uuid.eq(uid))).execute(conn)?;
    diesel::delete(twofactor_incomplete::table.filter(twofactor_incomplete::user_uuid.eq(uid))).execute(conn)?;
    diesel::delete(auth_requests::table.filter(auth_requests::user_uuid.eq(uid))).execute(conn)?;
    diesel::delete(
        emergency_access::table
            .filter(emergency_access::grantor_uuid.eq(uid).or(emergency_access::grantee_uuid.eq(uid))),
    )
    .execute(conn)?;
    diesel::delete(tenant_recovery_bundles::table.filter(tenant_recovery_bundles::user_uuid.eq(uid))).execute(conn)?;
    diesel::delete(sso_users::table.filter(sso_users::user_uuid.eq(uid))).execute(conn)?;
    diesel::delete(groups_users::table.filter(groups_users::users_organizations_uuid.eq_any(memberships())))
        .execute(conn)?;
    diesel::delete(users_collections::table.filter(users_collections::user_uuid.eq(uid))).execute(conn)?;
    diesel::delete(users_organizations::table.filter(users_organizations::user_uuid.eq(uid))).execute(conn)?;
    diesel::delete(event::table.filter(event::user_uuid.eq(uid).or(event::act_user_uuid.eq(uid)))).execute(conn)?;
    diesel::delete(users::table.find(uid)).execute(conn)?;
    Ok(queued)
}

// ---------------------------------------------------------------------------
// tenants/<id>/purge/begin

#[derive(Debug, Serialize)]
pub struct PurgeResponse {
    pub status: &'static str,
    pub pending_deletions: i64,
}

pub fn purge_begin(
    conn: &mut DbConnInner,
    tenant_id: &str,
    sso_authority: &str,
    served_cells: &[String],
    now: i64,
) -> OpResult<(PurgeResponse, Kicks)> {
    ensure_served_cells_configured(served_cells)?;
    check_id("tenant_id", tenant_id, MAX_ID_LEN)?;
    let now_dt = naive(now);
    conn.transaction(|conn| {
        let mut kicks = Kicks::default();
        let mut t = ensure_tenant_cell_served(conn, tenant_id, served_cells)?;
        if t.status == STATUS_DELETED && t.erased_at.is_some() && pending_count(conn, tenant_id)? == 0 {
            return Ok((
                PurgeResponse {
                    status: STATUS_DELETED,
                    pending_deletions: 0,
                },
                kicks,
            ));
        }

        let cell = t.home_region.clone();
        STATUS_PURGE_PENDING.clone_into(&mut t.status);
        t.app_enabled = false;
        t.access_epoch = t.access_epoch.saturating_add(1);
        t.storage_ceiling_bytes = 0;
        t.storage_grant_expires_at = None;
        t.storage_reserved_bytes = 0;
        t.storage_pending_seq = None;
        t.storage_pending_used_bytes = None;
        t.deleted_at = t.deleted_at.or(Some(now_dt));
        t.erased_at = None;
        t.updated_at = now_dt;
        diesel::update(tenants::table.find(tenant_id)).set(&t).execute(conn)?;

        purge_tenant_rows(conn, tenant_id, &cell, sso_authority, now_dt)?;
        kicks.tenants.push(tenant_id.to_owned());
        Ok((
            PurgeResponse {
                status: STATUS_PURGE_PENDING,
                pending_deletions: pending_count(conn, tenant_id)?,
            },
            kicks,
        ))
    })
}

/// Queues every tenant object, records subject tombstones, then deletes all tenant-owned
/// vault rows in foreign-key order. Rows are selected by `tenant_id` or by ownership through a
/// tenant user/organization, so the FK chain is complete; nothing else is touched.
fn purge_tenant_rows(
    conn: &mut DbConnInner,
    tid: &str,
    cell: &str,
    sso_authority: &str,
    now: NaiveDateTime,
) -> QueryResult<()> {
    let u = || users::table.filter(users::tenant_id.eq(tid)).select(users::uuid);
    let un = || users::table.filter(users::tenant_id.eq(tid)).select(users::uuid.nullable());
    let o = || organizations::table.filter(organizations::tenant_id.eq(tid)).select(organizations::uuid);
    let on = || organizations::table.filter(organizations::tenant_id.eq(tid)).select(organizations::uuid.nullable());
    let c = || {
        ciphers::table
            .filter(
                ciphers::tenant_id
                    .eq(tid)
                    .or(ciphers::user_uuid.eq_any(un()))
                    .or(ciphers::organization_uuid.eq_any(on())),
            )
            .select(ciphers::uuid)
    };
    let colls = || collections::table.filter(collections::org_uuid.eq_any(o())).select(collections::uuid);
    let grps = || groups::table.filter(groups::organizations_uuid.eq_any(o())).select(groups::uuid);
    let members = || {
        users_organizations::table
            .filter(users_organizations::user_uuid.eq_any(u()).or(users_organizations::org_uuid.eq_any(o())))
            .select(users_organizations::uuid)
    };
    let tenant_sends = || {
        sends::table.filter(
            sends::tenant_id.eq(tid).or(sends::user_uuid.eq_any(un())).or(sends::organization_uuid.eq_any(on())),
        )
    };

    // 1. Durable object manifest before any reference disappears.
    let atts: Vec<(String, String, Option<String>)> = attachments::table
        .filter(attachments::tenant_id.eq(tid).or(attachments::cipher_uuid.eq_any(c())))
        .select((attachments::id, attachments::cipher_uuid, attachments::tenant_id))
        .load(conn)?;
    let file_sends: Vec<(String, String, Option<String>)> = tenant_sends()
        .filter(sends::atype.eq(SEND_TYPE_FILE))
        .select((sends::uuid, sends::data, sends::tenant_id))
        .load(conn)?;
    let mut rows = Vec::new();
    for (id, cipher, att_tid) in atts {
        rows.push(pending(
            tid,
            None,
            KIND_ATTACHMENT,
            attachment_key(Some(cell), Some(att_tid.as_deref().unwrap_or(tid)), &cipher, &id),
            now,
        ));
    }
    for (send, data, send_tid) in file_sends {
        if let Some(file_id) = send_file_id(&data) {
            rows.push(pending(
                tid,
                None,
                KIND_SEND,
                send_key(Some(cell), Some(send_tid.as_deref().unwrap_or(tid)), &send, &file_id),
                now,
            ));
        }
    }
    let prefix_queued = tenant_pending_deletions::table
        .filter(tenant_pending_deletions::tenant_id.eq(tid))
        .filter(tenant_pending_deletions::storage_kind.eq(KIND_TENANT_PREFIX))
        .count()
        .get_result::<i64>(conn)?
        > 0;
    if !prefix_queued {
        rows.push(pending(tid, None, KIND_TENANT_PREFIX, tenant_prefix_object_key(cell, tid), now));
    }
    insert_pending(conn, &rows)?;

    // 2. Permanent subject tombstones.
    let idents: Vec<String> = sso_users::table
        .filter(sso_users::user_uuid.eq_any(u()).or(sso_users::tenant_id.eq(tid)))
        .select(sso_users::identifier)
        .load(conn)?;
    for ident in idents {
        if let Some((iss, sub)) = split_identifier(&ident, sso_authority) {
            record_tombstone(conn, &tombstone(iss, sub, tid, 0, now))?;
        }
    }

    // 3. Rows hanging off ciphers, collections, groups and memberships.
    diesel::delete(attachments::table.filter(attachments::tenant_id.eq(tid).or(attachments::cipher_uuid.eq_any(c()))))
        .execute(conn)?;
    diesel::delete(
        folders_ciphers::table.filter(
            folders_ciphers::cipher_uuid.eq_any(c()).or(folders_ciphers::folder_uuid
                .eq_any(folders::table.filter(folders::user_uuid.eq_any(u())).select(folders::uuid))),
        ),
    )
    .execute(conn)?;
    diesel::delete(
        ciphers_collections::table.filter(
            ciphers_collections::cipher_uuid.eq_any(c()).or(ciphers_collections::collection_uuid.eq_any(colls())),
        ),
    )
    .execute(conn)?;
    diesel::delete(favorites::table.filter(favorites::cipher_uuid.eq_any(c()).or(favorites::user_uuid.eq_any(u()))))
        .execute(conn)?;
    diesel::delete(archives::table.filter(archives::cipher_uuid.eq_any(c()).or(archives::user_uuid.eq_any(u()))))
        .execute(conn)?;
    diesel::delete(collections_groups::table.filter(
        collections_groups::collections_uuid.eq_any(colls()).or(collections_groups::groups_uuid.eq_any(grps())),
    ))
    .execute(conn)?;
    diesel::delete(
        users_collections::table
            .filter(users_collections::user_uuid.eq_any(u()).or(users_collections::collection_uuid.eq_any(colls()))),
    )
    .execute(conn)?;
    diesel::delete(
        groups_users::table.filter(
            groups_users::groups_uuid.eq_any(grps()).or(groups_users::users_organizations_uuid.eq_any(members())),
        ),
    )
    .execute(conn)?;
    diesel::delete(org_policies::table.filter(org_policies::org_uuid.eq_any(o()))).execute(conn)?;
    diesel::delete(organization_api_key::table.filter(organization_api_key::org_uuid.eq_any(o()))).execute(conn)?;
    diesel::delete(
        auth_requests::table
            .filter(auth_requests::user_uuid.eq_any(u()).or(auth_requests::organization_uuid.eq_any(on()))),
    )
    .execute(conn)?;
    diesel::delete(
        event::table.filter(
            event::org_uuid.eq_any(on()).or(event::user_uuid.eq_any(un())).or(event::act_user_uuid.eq_any(un())),
        ),
    )
    .execute(conn)?;

    // 4. Primary content, then memberships and organization structure.
    diesel::delete(ciphers::table.filter(
        ciphers::tenant_id.eq(tid).or(ciphers::user_uuid.eq_any(un())).or(ciphers::organization_uuid.eq_any(on())),
    ))
    .execute(conn)?;
    diesel::delete(tenant_sends()).execute(conn)?;
    diesel::delete(collections::table.filter(collections::org_uuid.eq_any(o()))).execute(conn)?;
    diesel::delete(groups::table.filter(groups::organizations_uuid.eq_any(o()))).execute(conn)?;
    diesel::delete(
        users_organizations::table
            .filter(users_organizations::user_uuid.eq_any(u()).or(users_organizations::org_uuid.eq_any(o()))),
    )
    .execute(conn)?;

    // 5. Per-user state, then users and organizations themselves.
    diesel::delete(folders::table.filter(folders::user_uuid.eq_any(u()))).execute(conn)?;
    diesel::delete(devices::table.filter(devices::user_uuid.eq_any(u()))).execute(conn)?;
    diesel::delete(twofactor::table.filter(twofactor::user_uuid.eq_any(u()))).execute(conn)?;
    diesel::delete(twofactor_incomplete::table.filter(twofactor_incomplete::user_uuid.eq_any(u()))).execute(conn)?;
    diesel::delete(
        emergency_access::table
            .filter(emergency_access::grantor_uuid.eq_any(u()).or(emergency_access::grantee_uuid.eq_any(un()))),
    )
    .execute(conn)?;
    diesel::delete(
        tenant_recovery_bundles::table
            .filter(tenant_recovery_bundles::tenant_id.eq(tid).or(tenant_recovery_bundles::user_uuid.eq_any(u()))),
    )
    .execute(conn)?;
    diesel::delete(sso_users::table.filter(sso_users::user_uuid.eq_any(u()).or(sso_users::tenant_id.eq(tid))))
        .execute(conn)?;
    diesel::delete(users::table.filter(users::tenant_id.eq(tid))).execute(conn)?;
    diesel::delete(organizations::table.filter(organizations::tenant_id.eq(tid))).execute(conn)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// cleanup/pending, cleanup/complete

#[derive(Debug, Serialize, Queryable)]
pub struct PendingItem {
    pub id: String,
    pub tenant_id: String,
    pub user_uuid: Option<String>,
    pub storage_kind: String,
    pub object_key: String,
    pub attempts: i32,
}

/// Marker stored in `tenant_pending_deletions.last_error` while an attachment upload is actively
/// writing to object storage. `cleanup_pending` hides rows with this marker until either upload
/// finalization fails (clearing the marker immediately) or `UPLOAD_STAGING_GRACE_SECS` elapses
/// after a crash so an abandoned upload is still reclaimed.
pub const UPLOAD_IN_FLIGHT_MARKER: &str = "upload_in_flight";
pub const UPLOAD_STAGING_GRACE_SECS: i64 = 900;

#[derive(Debug, Serialize)]
pub struct PendingResponse {
    pub items: Vec<PendingItem>,
}

pub fn cleanup_pending(
    conn: &mut DbConnInner,
    limit: Option<i64>,
    served_cells: &[String],
    now: i64,
) -> OpResult<PendingResponse> {
    ensure_served_cells_configured(served_cells)?;
    let limit = limit.unwrap_or(100).clamp(1, MAX_BATCH_SQL);
    let staging_cutoff = naive(now.saturating_sub(UPLOAD_STAGING_GRACE_SECS));
    let served_tenants = tenants::table.filter(tenants::home_region.eq_any(served_cells)).select(tenants::id);
    let items = tenant_pending_deletions::table
        .filter(tenant_pending_deletions::tenant_id.eq_any(served_tenants))
        .filter(
            tenant_pending_deletions::last_error
                .is_null()
                .or(tenant_pending_deletions::last_error.ne(UPLOAD_IN_FLIGHT_MARKER))
                .or(tenant_pending_deletions::created_at.le(staging_cutoff)),
        )
        // Fewest attempts first, so objects that keep failing cannot starve newer cleanup.
        .order((
            tenant_pending_deletions::attempts.asc(),
            tenant_pending_deletions::created_at.asc(),
            tenant_pending_deletions::id.asc(),
        ))
        .limit(limit)
        .select((
            tenant_pending_deletions::id,
            tenant_pending_deletions::tenant_id,
            tenant_pending_deletions::user_uuid,
            tenant_pending_deletions::storage_kind,
            tenant_pending_deletions::object_key,
            tenant_pending_deletions::attempts,
        ))
        .load(conn)?;
    Ok(PendingResponse {
        items,
    })
}

#[derive(Debug, Deserialize)]
pub struct FailedItem {
    pub id: String,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct CompleteRequest {
    #[serde(default, deserialize_with = "null_as_default")]
    pub completed_ids: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub failed: Vec<FailedItem>,
}

#[derive(Debug, Default, Serialize)]
pub struct CompleteResponse {
    pub deleted: usize,
    pub failed_updated: usize,
    pub finalized_tenant_ids: Vec<String>,
}

pub fn cleanup_complete(
    conn: &mut DbConnInner,
    req: &CompleteRequest,
    served_cells: &[String],
    now: i64,
) -> OpResult<CompleteResponse> {
    ensure_served_cells_configured(served_cells)?;
    if req.completed_ids.len() + req.failed.len() > MAX_BATCH {
        return Err(bad_request("Too many cleanup results"));
    }
    for id in req.completed_ids.iter().chain(req.failed.iter().map(|f| &f.id)) {
        check_id("id", id, MAX_ID_LEN)?;
    }
    conn.transaction(|conn| {
        let mut resp = CompleteResponse::default();
        let all_ids: Vec<&str> =
            req.completed_ids.iter().map(String::as_str).chain(req.failed.iter().map(|f| f.id.as_str())).collect();
        let mut all_tenants: Vec<String> = tenant_pending_deletions::table
            .filter(tenant_pending_deletions::id.eq_any(&all_ids))
            .select(tenant_pending_deletions::tenant_id)
            .distinct()
            .load(conn)?;
        all_tenants.sort();
        for tid in &all_tenants {
            ensure_tenant_cell_served(conn, tid, served_cells)?;
        }

        let mut affected: Vec<String> = tenant_pending_deletions::table
            .filter(tenant_pending_deletions::id.eq_any(&req.completed_ids))
            .select(tenant_pending_deletions::tenant_id)
            .distinct()
            .load(conn)?;
        affected.sort();
        drop_abandoned_v2_rows(conn, &all_ids)?;
        let completed: Vec<&str> = req.completed_ids.iter().map(String::as_str).collect();
        release_pending_reservations(conn, &completed)?;
        resp.deleted = diesel::delete(
            tenant_pending_deletions::table.filter(tenant_pending_deletions::id.eq_any(&req.completed_ids)),
        )
        .execute(conn)?;
        for f in &req.failed {
            let err: String = f.error.chars().take(MAX_ERROR_LEN).collect();
            resp.failed_updated += diesel::update(tenant_pending_deletions::table.find(&f.id))
                .set((
                    tenant_pending_deletions::attempts.eq(tenant_pending_deletions::attempts + 1),
                    tenant_pending_deletions::last_error.eq(Some(err)),
                ))
                .execute(conn)?;
        }
        for tid in affected {
            let Some(t) = lock_tenant(conn, &tid)? else {
                continue;
            };
            if (t.status == STATUS_PURGE_PENDING || t.status == STATUS_ERASING)
                && pending_count(conn, &tid)? == 0
                && vault_rows_purged(conn, &tid)?
            {
                diesel::update(tenants::table.find(&tid))
                    .set((
                        tenants::status.eq(STATUS_DELETED),
                        tenants::erased_at.eq(Some(naive(now))),
                        tenants::updated_at.eq(naive(now)),
                    ))
                    .execute(conn)?;
                resp.finalized_tenant_ids.push(tid);
            }
        }
        Ok(resp)
    })
}

/// A cleanup row the worker reports while it still carries the in-flight marker belongs to an
/// upload that crashed: the worker deletes its object, so its v2 attachment row goes too. No newer
/// upload can own that row, since none can start while the cleanup row exists.
fn drop_abandoned_v2_rows(conn: &mut DbConnInner, ids: &[&str]) -> QueryResult<()> {
    let rows: Vec<(String, String)> = tenant_pending_deletions::table
        .filter(tenant_pending_deletions::id.eq_any(ids))
        .filter(tenant_pending_deletions::storage_kind.eq("attachment"))
        .filter(tenant_pending_deletions::last_error.eq(UPLOAD_IN_FLIGHT_MARKER))
        .order(tenant_pending_deletions::tenant_id.asc())
        .select((tenant_pending_deletions::tenant_id, tenant_pending_deletions::object_key))
        .load(conn)?;
    for (tid, key) in rows {
        let mut parts = key.rsplitn(3, '/');
        let (Some(aid), Some(cid)) = (parts.next(), parts.next()) else {
            continue;
        };
        // Tenant first, as the upload paths lock it before touching attachment rows.
        let Some(t) = lock_tenant(conn, &tid)? else {
            continue;
        };
        if attachment_object_key(&t.home_region, &tid, cid, aid) != key {
            continue;
        }
        diesel::delete(
            attachments::table
                .filter(attachments::id.eq(aid))
                .filter(attachments::cipher_uuid.eq(cid))
                .filter(attachments::tenant_id.eq(&tid)),
        )
        .execute(conn)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// storage/prepare, storage/apply, storage/repair-seq

const fn default_want_bytes() -> i64 {
    268_435_456
}

const fn default_storage_limit() -> i64 {
    500
}

/// `renew_before_secs` is accepted and ignored: active tenants report on every call.
#[derive(Debug, Deserialize)]
pub struct PrepareRequest {
    #[serde(default = "default_want_bytes")]
    pub want_bytes_default: i64,
    #[serde(default = "default_storage_limit")]
    pub limit: i64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct StorageReport {
    pub org_id: String,
    pub used_bytes: i64,
    pub seq: i64,
    pub want_bytes: i64,
}

#[derive(Debug, Serialize)]
pub struct PrepareResponse {
    pub reports: Vec<StorageReport>,
}

pub fn storage_prepare(
    conn: &mut DbConnInner,
    req: &PrepareRequest,
    served_cells: &[String],
    now: i64,
) -> OpResult<PrepareResponse> {
    ensure_served_cells_configured(served_cells)?;
    let limit = usize::try_from(req.limit).unwrap_or(1).clamp(1, MAX_BATCH);
    let want_default = req.want_bytes_default.max(0);

    // Least recently reported first, so a capped batch rotates through every tenant even while
    // some reports keep failing upstream; then soonest-expiring (or missing) grants.
    // Only tenants with something to report, mirroring `needs` below, and only one batch of them.
    let ids: Vec<String> = tenants::table
        .filter(tenants::status.ne_all(TOMBSTONED))
        .filter(tenants::storage_seq_stale.eq(false))
        .filter(tenants::home_region.eq_any(served_cells))
        .filter(
            tenants::storage_pending_seq
                .is_not_null()
                .and(tenants::storage_pending_used_bytes.is_not_null())
                .or(tenants::app_enabled
                    .eq(true)
                    .and(tenants::status.eq(TENANT_STATUS_ACTIVE))
                    .and(tenants::deleted_at.is_null())
                    .and(tenants::erased_at.is_null())
                    .and(tenants::authority_refreshed_at.is_not_null()))
                .or(tenants::storage_ceiling_bytes.gt(0))
                .or(tenants::storage_grant_expires_at.is_not_null())
                .or(tenants::storage_last_applied_seq.eq(0))
                .or(tenants::storage_dirty.eq(true)),
        )
        .order((
            tenants::storage_prepared_at.is_not_null().asc(),
            tenants::storage_prepared_at.asc(),
            tenants::storage_grant_expires_at.is_not_null().asc(),
            tenants::storage_grant_expires_at.asc(),
            tenants::id.asc(),
        ))
        .limit(i64::try_from(limit).unwrap_or(i64::MAX))
        .select(tenants::id)
        .load(conn)?;

    let mut reports = Vec::new();
    for id in ids {
        if reports.len() >= limit {
            break;
        }
        let report = conn.transaction::<_, Error, _>(|conn| {
            let Some(t) = lock_tenant(conn, &id)? else {
                return Ok(None);
            };
            if is_tombstoned(&t.status) || t.storage_seq_stale || !is_cell_served(served_cells, &t.home_region) {
                return Ok(None);
            }
            let live_and_authorized = t.is_active() && t.authority_refreshed_at.is_some();
            let want = if live_and_authorized && t.storage_over_since.is_none() {
                want_default
            } else {
                0
            };
            if let (Some(seq), Some(used)) = (t.storage_pending_seq, t.storage_pending_used_bytes) {
                diesel::update(tenants::table.find(&t.id))
                    .set(tenants::storage_prepared_at.eq(Some(now)))
                    .execute(conn)?;
                return Ok(Some(StorageReport {
                    org_id: t.id,
                    used_bytes: used,
                    seq,
                    want_bytes: want,
                }));
            }
            let needs = live_and_authorized
                || t.storage_ceiling_bytes > 0
                || t.storage_grant_expires_at.is_some()
                || t.storage_last_applied_seq == 0
                || t.storage_dirty;
            if !needs {
                return Ok(None);
            }
            let used = committed_bytes(conn, &t.id)?.saturating_add(t.storage_reserved_bytes.max(0));
            let seq = t.storage_report_seq.saturating_add(1);
            diesel::update(tenants::table.find(&t.id))
                .set((
                    tenants::storage_report_seq.eq(seq),
                    tenants::storage_pending_seq.eq(Some(seq)),
                    tenants::storage_pending_used_bytes.eq(Some(used)),
                    tenants::storage_prepared_at.eq(Some(now)),
                    tenants::storage_dirty.eq(false),
                ))
                .execute(conn)?;
            Ok(Some(StorageReport {
                org_id: t.id,
                used_bytes: used,
                seq,
                want_bytes: want,
            }))
        })?;
        reports.extend(report);
    }
    Ok(PrepareResponse {
        reports,
    })
}

#[derive(Debug, Deserialize)]
pub struct ApplyItem {
    pub org_id: String,
    pub result: String,
    /// Seq of the report this answers. Missing means 0, which is never current.
    #[serde(default, deserialize_with = "null_as_default")]
    pub report_seq: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub seq: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub ceiling_bytes: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub ttl_seconds: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub pool_bytes: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub org_used_bytes: i64,
    #[serde(default)]
    pub over_since: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ApplyRequest {
    pub sent_at: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub results: Vec<ApplyItem>,
}

#[derive(Debug, Default, Serialize)]
pub struct ApplyResponse {
    pub applied: usize,
    pub stale_tenant_ids: Vec<String>,
}

pub fn storage_apply(
    conn: &mut DbConnInner,
    req: &ApplyRequest,
    served_cells: &[String],
    now: i64,
) -> OpResult<ApplyResponse> {
    ensure_served_cells_configured(served_cells)?;
    if req.results.len() > MAX_BATCH {
        return Err(bad_request("Too many results"));
    }
    for r in &req.results {
        check_id("org_id", &r.org_id, MAX_ID_LEN)?;
        if !["ok", "stale", "unknown_org"].contains(&r.result.as_str()) {
            return Err(bad_request("Invalid result"));
        }
    }
    // Atomic C5 pre-check: refuse the whole batch if any org is unknown or in an unserved cell.
    let mut unique_ids: Vec<&str> = req.results.iter().map(|r| r.org_id.as_str()).collect();
    unique_ids.sort_unstable();
    unique_ids.dedup();
    if !unique_ids.is_empty() {
        let rows: Vec<(String, String)> = tenants::table
            .filter(tenants::id.eq_any(&unique_ids))
            .select((tenants::id, tenants::home_region))
            .load(conn)?;
        if rows.len() != unique_ids.len() || rows.iter().any(|(_, hr)| !is_cell_served(served_cells, hr)) {
            return Err(cell_not_served_err());
        }
    }
    // A skewed worker clock can never stretch a grant past now + TTL.
    let sent_at = req.sent_at.min(now);
    let mut resp = ApplyResponse::default();
    for r in &req.results {
        let applied = conn.transaction::<_, Error, _>(|conn| {
            let t = ensure_tenant_cell_served(conn, &r.org_id, served_cells)?;
            if is_tombstoned(&t.status) {
                return Ok(false);
            }
            // Drop answers to older reports before any variant touches state. An ok may
            // replay the last applied report; stale and unknown_org must answer the pending one.
            let current = if r.result == "ok" {
                r.report_seq > 0
                    && r.seq == r.report_seq
                    && r.report_seq <= t.storage_report_seq
                    && r.report_seq >= t.storage_last_applied_seq
                    && t.storage_pending_seq.is_none_or(|p| r.report_seq >= p)
            } else {
                t.storage_pending_seq == Some(r.report_seq)
            };
            if !current {
                return Ok(false);
            }
            let row = tenants::table.find(&r.org_id);
            match r.result.as_str() {
                "ok" => {
                    // A report sent before a fence can be answered after it: keep the
                    // bookkeeping, never reinstall a grant on a non-active or C4-fenced tenant.
                    let (ceiling, expires) = if t.is_active() && t.authority_refreshed_at.is_some() {
                        (
                            r.ceiling_bytes.max(0),
                            Some(sent_at.saturating_add(r.ttl_seconds.clamp(1, MAX_GRANT_TTL_SECS))),
                        )
                    } else {
                        (0, None)
                    };
                    diesel::update(row)
                        .set((
                            tenants::storage_last_applied_seq.eq(r.seq),
                            tenants::storage_pending_seq.eq(None::<i64>),
                            tenants::storage_pending_used_bytes.eq(None::<i64>),
                            tenants::storage_ceiling_bytes.eq(ceiling),
                            tenants::storage_grant_expires_at.eq(expires),
                            tenants::storage_pool_bytes.eq(r.pool_bytes.max(0)),
                            tenants::storage_org_used_bytes.eq(r.org_used_bytes.max(0)),
                            tenants::storage_over_since.eq(r.over_since),
                            tenants::storage_seq_stale.eq(false),
                        ))
                        .execute(conn)?;
                }
                "stale" => {
                    diesel::update(row)
                        .set((
                            tenants::storage_seq_stale.eq(true),
                            tenants::storage_pending_seq.eq(None::<i64>),
                            tenants::storage_pending_used_bytes.eq(None::<i64>),
                        ))
                        .execute(conn)?;
                }
                _ => {
                    diesel::update(row)
                        .set((
                            tenants::storage_pending_seq.eq(None::<i64>),
                            tenants::storage_pending_used_bytes.eq(None::<i64>),
                            tenants::storage_ceiling_bytes.eq(0),
                            tenants::storage_grant_expires_at.eq(None::<i64>),
                        ))
                        .execute(conn)?;
                }
            }
            Ok(true)
        })?;
        if applied {
            resp.applied += 1;
            if r.result == "stale" {
                resp.stale_tenant_ids.push(r.org_id.clone());
            }
        }
    }
    Ok(resp)
}

#[derive(Debug, Deserialize)]
pub struct RepairSeqRequest {
    pub org_id: String,
    pub next_seq: i64,
}

#[derive(Debug, Serialize)]
pub struct RepairSeqResponse {
    pub org_id: String,
    pub storage_report_seq: i64,
    pub storage_seq_stale: bool,
}

pub fn storage_repair_seq(
    conn: &mut DbConnInner,
    req: &RepairSeqRequest,
    served_cells: &[String],
) -> OpResult<RepairSeqResponse> {
    ensure_served_cells_configured(served_cells)?;
    check_id("org_id", &req.org_id, MAX_ID_LEN)?;
    conn.transaction(|conn| {
        let t = ensure_tenant_cell_served(conn, &req.org_id, served_cells)?;
        if req.next_seq <= t.storage_report_seq {
            return Err(bad_request("next_seq must exceed the current storage_report_seq"));
        }
        let seq = req.next_seq - 1;
        diesel::update(tenants::table.find(&t.id))
            .set((
                tenants::storage_report_seq.eq(seq),
                tenants::storage_pending_seq.eq(None::<i64>),
                tenants::storage_pending_used_bytes.eq(None::<i64>),
                tenants::storage_seq_stale.eq(false),
            ))
            .execute(conn)?;
        Ok(RepairSeqResponse {
            org_id: t.id,
            storage_report_seq: seq,
            storage_seq_stale: false,
        })
    })
}

#[cfg(all(test, sqlite))]
mod tests {
    use super::*;
    use crate::db::{
        models::{Abandoned, Attachment, AttachmentId, CipherId, V2UploadLease},
        test_sqlite_conn,
    };

    const NOW: i64 = 1_750_000_000;
    const ISS: &str = "https://id.busnes.app";
    const REGION: &str = "us-east-1";

    fn cells() -> Vec<String> {
        vec![REGION.to_owned()]
    }

    fn exec(c: &mut DbConnInner, sql: &str) {
        diesel::sql_query(sql).execute(c).unwrap_or_else(|e| panic!("{sql}: {e}"));
    }

    fn tenant(c: &mut DbConnInner, id: &str) -> Tenant {
        lock_tenant(c, id).unwrap().unwrap_or_else(|| panic!("tenant {id} missing"))
    }

    fn active_tenant_in(c: &mut DbConnInner, id: &str, cell: &str) {
        let mut t = Tenant::new(id.to_owned(), cell.to_owned());
        t.app_enabled = true;
        t.authority_refreshed_at = Some(NOW);
        diesel::insert_into(tenants::table).values(&t).execute(c).unwrap();
    }

    fn active_tenant(c: &mut DbConnInner, id: &str) {
        active_tenant_in(c, id, REGION);
    }

    fn user(c: &mut DbConnInner, uid: &str, tid: &str, subject: &str) {
        exec(
            c,
            &format!(
                "INSERT INTO users (uuid, enabled, created_at, updated_at, email, name, password_hash, salt, \
                 password_iterations, akey, security_stamp, equivalent_domains, excluded_globals, client_kdf_type, \
                 client_kdf_iter, tenant_id) VALUES ('{uid}', 1, '2025-01-01 00:00:00', '2025-01-01 00:00:00', \
                 '{uid}@example.com', '{uid}', x'00', x'00', 600000, 'akey', 'stamp-{uid}', '[]', '[]', 0, 600000, '{tid}')"
            ),
        );
        exec(
            c,
            &format!(
                "INSERT INTO sso_users (user_uuid, identifier, tenant_id) VALUES ('{uid}', '{ISS}/{subject}', '{tid}')"
            ),
        );
        exec(
            c,
            &format!(
                "INSERT INTO devices (uuid, created_at, updated_at, user_uuid, name, atype, refresh_token) VALUES \
                 ('dev-{uid}', '2025-01-01 00:00:00', '2025-01-01 00:00:00', '{uid}', 'd', 0, 'rt-{uid}')"
            ),
        );
    }

    fn org(c: &mut DbConnInner, oid: &str, tid: &str) {
        exec(
            c,
            &format!(
                "INSERT INTO organizations (uuid, name, billing_email, tenant_id) VALUES ('{oid}', 'o', 'b@e.c', '{tid}')"
            ),
        );
    }

    fn member(c: &mut DbConnInner, mid: &str, uid: &str, oid: &str) {
        exec(
            c,
            &format!(
                "INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, akey, status, atype) VALUES \
                 ('{mid}', '{uid}', '{oid}', 1, 'envelope-{mid}', 2, 0)"
            ),
        );
    }

    fn cipher(c: &mut DbConnInner, cid: &str, uid: Option<&str>, oid: Option<&str>, tid: &str) {
        let q = |v: Option<&str>| v.map_or_else(|| "NULL".to_owned(), |s| format!("'{s}'"));
        exec(
            c,
            &format!(
                "INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, atype, name, data, \
                 tenant_id) VALUES ('{cid}', '2025-01-01 00:00:00', '2025-01-01 00:00:00', {}, {}, 1, 'n', \
                 '0123456789', '{tid}')",
                q(uid),
                q(oid)
            ),
        );
    }

    fn attachment(c: &mut DbConnInner, aid: &str, cid: &str, tid: &str) {
        exec(
            c,
            &format!(
                "INSERT INTO attachments (id, cipher_uuid, file_name, file_size, tenant_id) VALUES ('{aid}', '{cid}', 'f', 100, '{tid}')"
            ),
        );
    }

    fn file_send(c: &mut DbConnInner, sid: &str, uid: &str, tid: &str, file_id: &str) {
        exec(
            c,
            &format!(
                "INSERT INTO sends (uuid, user_uuid, name, atype, data, akey, access_count, creation_date, \
                 revision_date, deletion_date, disabled, tenant_id) VALUES ('{sid}', '{uid}', 'n', 1, \
                 '{{\"id\":\"{file_id}\",\"size\":50}}', 'k', 0, '2025-01-01 00:00:00', '2025-01-01 00:00:00', \
                 '2030-01-01 00:00:00', 0, '{tid}')"
            ),
        );
    }

    fn stamp(c: &mut DbConnInner, uid: &str) -> String {
        users::table.find(uid).select(users::security_stamp).first(c).unwrap()
    }

    fn refresh_token(c: &mut DbConnInner, uid: &str) -> String {
        devices::table.filter(devices::user_uuid.eq(uid)).select(devices::refresh_token).first(c).unwrap()
    }

    fn snap(id: &str, status: &str, enabled: bool, revision: i64) -> OrgSnapshot {
        OrgSnapshot {
            id: id.to_owned(),
            status: status.to_owned(),
            home_region: REGION.to_owned(),
            enabled,
            revision,
            quotas: None,
        }
    }

    fn reconcile(c: &mut DbConnInner, orgs: Vec<OrgSnapshot>, touch: bool, now: i64) -> ReconcileResponse {
        reconcile_orgs(
            c,
            &ReconcileRequest {
                orgs,
                touch_all_active: touch,
            },
            &cells(),
            now,
        )
        .unwrap()
        .0
    }

    #[test]
    fn object_keys_match_storage_paths() {
        let mut att =
            Attachment::new(AttachmentId("att".to_owned()), CipherId::from("c1".to_owned()), "f".to_owned(), 1, None);
        att.tenant_id = Some("t1".to_owned());
        assert_eq!(
            attachment_key(Some(REGION), Some("t1"), "c1", "att"),
            att.get_file_path_in_cell(Some(REGION)).unwrap()
        );
        assert_eq!(
            attachment_key(Some(REGION), Some("t1"), "c1", "att"),
            "cells/us-east-1/tenants/t1/attachments/c1/att"
        );
        assert_eq!(send_key(Some(REGION), Some("t1"), "s1", "f1"), "cells/us-east-1/tenants/t1/sends/s1/f1");
    }

    #[test]
    fn identifier_split_handles_issuer_paths() {
        assert_eq!(split_identifier("https://id.busnes.app/usr_1", ISS), Some((ISS, "usr_1")));
        assert_eq!(
            split_identifier("https://id.busnes.app/realms/x/usr_1", "https://id.busnes.app/realms/x/"),
            Some(("https://id.busnes.app/realms/x", "usr_1"))
        );
        assert_eq!(split_identifier("https://other.example/a/usr_2", ISS), Some(("https://other.example/a", "usr_2")));
        assert_eq!(split_identifier("nosubject/", ""), None);
    }

    #[test]
    fn reconcile_creates_fences_and_never_resurrects() {
        let c = &mut test_sqlite_conn();
        let r = reconcile(c, vec![snap("t1", "active", true, 1)], false, NOW);
        assert_eq!(r.applied, 1);
        assert_eq!(r.fenced_tenant_ids, Vec::<String>::new());
        let t = tenant(c, "t1");
        assert!(t.is_active());
        assert_eq!(t.authority_refreshed_at, Some(NOW));

        user(c, "u1", "t1", "sub1");
        diesel::update(tenants::table.find("t1"))
            .set((tenants::storage_ceiling_bytes.eq(1000), tenants::storage_grant_expires_at.eq(Some(NOW + 600))))
            .execute(c)
            .unwrap();

        let r = reconcile(c, vec![snap("t1", "suspended", true, 2)], false, NOW + 1);
        assert_eq!(r.fenced_tenant_ids, vec!["t1"]);
        let t = tenant(c, "t1");
        assert_eq!((t.status.as_str(), t.access_epoch, t.storage_ceiling_bytes), ("suspended", 2, 0));
        assert_eq!(t.storage_grant_expires_at, None);
        assert_ne!(stamp(c, "u1"), "stamp-u1");
        assert_ne!(refresh_token(c, "u1"), "rt-u1");
        assert_ne!(refresh_token(c, "u1"), "");

        // Already fenced: no second epoch bump.
        let r = reconcile(c, vec![snap("t1", "suspended", true, 3)], false, NOW + 2);
        assert_eq!(r.fenced_tenant_ids, Vec::<String>::new());
        assert_eq!(tenant(c, "t1").access_epoch, 2);

        // Stale revision: fields untouched, authority refreshed.
        let r = reconcile(c, vec![snap("t1", "active", true, 1)], false, NOW + 3);
        assert_eq!(r.applied, 0);
        let t = tenant(c, "t1");
        assert_eq!((t.status.as_str(), t.revision, t.authority_refreshed_at), ("suspended", 3, Some(NOW + 3)));

        // Unserved cell refused with 403 and zero rows written (C5).
        let mut far = snap("t2", "active", true, 1);
        far.home_region = "eu-west-1".to_owned();
        let err = reconcile_orgs(
            c,
            &ReconcileRequest {
                orgs: vec![far, snap("t3", "active", false, 1)],
                touch_all_active: false,
            },
            &cells(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.error_code(), 403);
        assert!(lock_tenant(c, "t2").unwrap().is_none());
        assert!(lock_tenant(c, "t3").unwrap().is_none());

        // New non-active tenant in a served cell is created fenced.
        let r = reconcile(c, vec![snap("t3", "active", false, 1)], false, NOW);
        assert_eq!(r.applied, 1);
        assert_eq!(r.fenced_tenant_ids, vec!["t3"]);

        // Deleted: purge_pending, never back to active.
        let r = reconcile(c, vec![snap("t1", "deleted", false, 4)], false, NOW);
        assert_eq!(r.purge_required_tenant_ids, vec!["t1"]);
        assert_eq!(tenant(c, "t1").status, STATUS_PURGE_PENDING);
        let r = reconcile(c, vec![snap("t1", "active", true, 9)], false, NOW);
        assert_eq!((r.applied, r.purge_required_tenant_ids), (0, vec!["t1".to_owned()]));
        assert_eq!(tenant(c, "t1").status, STATUS_PURGE_PENDING);
    }

    #[test]
    fn reconcile_touch_all_refreshes_live_served_cell_tenants_only() {
        let c = &mut test_sqlite_conn();
        reconcile(c, vec![snap("live", "active", true, 1), snap("gone", "deleted", false, 1)], false, NOW);
        let mut foreign = Tenant::new("foreign".to_owned(), "eu-west-1".to_owned());
        foreign.authority_refreshed_at = Some(NOW);
        diesel::insert_into(tenants::table).values(&foreign).execute(c).unwrap();

        reconcile(c, vec![], true, NOW + 500);
        assert_eq!(tenant(c, "live").authority_refreshed_at, Some(NOW + 500));
        assert_eq!(tenant(c, "gone").authority_refreshed_at, Some(NOW));
        assert_eq!(tenant(c, "foreign").authority_refreshed_at, Some(NOW));
    }

    #[test]
    fn reconcile_rejects_invalid_input() {
        let c = &mut test_sqlite_conn();
        let mut bad_quotas = snap("t", "active", true, 1);
        bad_quotas.quotas = Some(Value::from(5));
        let mut bad_cell = snap("t", "active", true, 1);
        bad_cell.home_region = "../escape".to_owned();
        for orgs in [
            vec![snap("t", "bogus", true, 1)],
            vec![snap("", "active", true, 1)],
            vec![bad_quotas],
            vec![bad_cell],
            (0..=MAX_BATCH).map(|i| snap(&i.to_string(), "active", true, 1)).collect(),
        ] {
            let req = ReconcileRequest {
                orgs,
                touch_all_active: false,
            };
            assert!(reconcile_orgs(c, &req, &cells(), NOW).is_err());
        }
        assert_eq!(tenants::table.count().get_result::<i64>(c).unwrap(), 0);
    }

    #[test]
    fn test_db_enforces_foreign_keys() {
        let c = &mut test_sqlite_conn();
        let orphan = diesel::sql_query(
            "INSERT INTO devices (uuid, created_at, updated_at, user_uuid, name, atype, refresh_token) VALUES \
             ('d', '2025-01-01 00:00:00', '2025-01-01 00:00:00', 'missing-user', 'd', 0, 'rt')",
        )
        .execute(c);
        assert!(orphan.is_err(), "erase/purge FK ordering is only proven with enforced foreign keys");
    }

    #[test]
    fn logout_matches_exact_identifier_and_tenant() {
        let c = &mut test_sqlite_conn();
        active_tenant(c, "t1");
        active_tenant(c, "t2");
        user(c, "u1", "t1", "sub1");
        let req = |subject: &str, tenant_id: Option<&str>| LogoutRequest {
            issuer: format!("{ISS}/"),
            subject: subject.to_owned(),
            tenant_id: tenant_id.map(str::to_owned),
        };

        let (r, _) = logout_user(c, &req("sub1", Some("t2")), &cells(), NOW).unwrap();
        assert!(!r.found);
        let (r, _) = logout_user(c, &req("sub", None), &cells(), NOW).unwrap();
        assert!(!r.found);
        assert_eq!(stamp(c, "u1"), "stamp-u1");

        let (r, kicks) = logout_user(c, &req("sub1", Some("t1")), &cells(), NOW).unwrap();
        assert_eq!((r.found, r.user_uuid.as_deref()), (true, Some("u1")));
        assert_eq!(kicks.users.len(), 1);
        assert_ne!(stamp(c, "u1"), "stamp-u1");
        assert_ne!(refresh_token(c, "u1"), "rt-u1");
    }

    #[test]
    fn sync_disables_reenables_and_respects_tombstones() {
        let c = &mut test_sqlite_conn();
        active_tenant(c, "t1");
        user(c, "u1", "t1", "sub1");
        let req = |event: &str, subject: &str, active: bool| SyncRequest {
            event_type: event.to_owned(),
            issuer: ISS.to_owned(),
            subject: subject.to_owned(),
            tenant_id: Some("t1".to_owned()),
            display_name: Some("Alice".to_owned()),
            active,
        };
        let enabled = |c: &mut DbConnInner| users::table.find("u1").select(users::enabled).first::<bool>(c).unwrap();

        assert!(sync_user(c, &req("user.bogus", "sub1", true), &cells(), NOW).is_err());
        assert_eq!(sync_user(c, &req("user.updated", "nobody", true), &cells(), NOW).unwrap().0.status, "not_found");

        let (r, kicks) = sync_user(c, &req("user.deleted", "sub1", true), &cells(), NOW).unwrap();
        assert_eq!(r.status, "ok");
        assert_eq!(kicks.users.len(), 1);
        assert!(!enabled(c));
        assert_ne!(stamp(c, "u1"), "stamp-u1");

        sync_user(c, &req("user.updated", "sub1", true), &cells(), NOW).unwrap();
        assert!(enabled(c));
        let name: String = users::table.find("u1").select(users::name).first(c).unwrap();
        assert_eq!(name, "Alice");

        // Inactive tenant: never re-enabled.
        sync_user(c, &req("user.updated", "sub1", false), &cells(), NOW).unwrap();
        diesel::update(tenants::table.find("t1")).set(tenants::status.eq("suspended")).execute(c).unwrap();
        sync_user(c, &req("user.updated", "sub1", true), &cells(), NOW).unwrap();
        assert!(!enabled(c));

        record_tombstone(c, &tombstone(ISS, "sub1", "t1", 1, naive(NOW))).unwrap();
        assert_eq!(
            sync_user(c, &req("user.created", "sub1", true), &cells(), NOW).unwrap().0.status,
            "erased_tombstone"
        );
        assert!(!enabled(c));
    }

    #[test]
    fn erase_removes_personal_data_and_keeps_org_content() {
        let c = &mut test_sqlite_conn();
        active_tenant(c, "t1");
        user(c, "u1", "t1", "sub1");
        user(c, "u2", "t1", "sub2");
        org(c, "o1", "t1");
        member(c, "m1", "u1", "o1");
        member(c, "m2", "u2", "o1");
        cipher(c, "pc", Some("u1"), None, "t1");
        cipher(c, "oc", Some("u1"), Some("o1"), "t1");
        attachment(c, "pa", "pc", "t1");
        attachment(c, "oa", "oc", "t1");
        file_send(c, "s1", "u1", "t1", "file1");
        exec(
            c,
            "INSERT INTO folders (uuid, created_at, updated_at, user_uuid, name) VALUES ('f1', '2025-01-01 00:00:00', '2025-01-01 00:00:00', 'u1', 'f')",
        );
        exec(c, "INSERT INTO folders_ciphers (cipher_uuid, folder_uuid) VALUES ('oc', 'f1')");
        exec(c, "INSERT INTO collections (uuid, org_uuid, name) VALUES ('col1', 'o1', 'c')");
        exec(
            c,
            "INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage) VALUES ('u1', 'col1', 0, 0, 0)",
        );
        exec(c, "INSERT INTO ciphers_collections (cipher_uuid, collection_uuid) VALUES ('oc', 'col1')");
        exec(c, "INSERT INTO favorites (user_uuid, cipher_uuid) VALUES ('u1', 'oc')");
        exec(
            c,
            "INSERT INTO tenant_recovery_bundles (uuid, tenant_id, user_uuid, bundle_type, version, kdf_params_json, wrapped_user_key, created_at, updated_at) VALUES ('rb1', 't1', 'u1', 'personal_kit', 1, '{}', 'k', '2025-01-01 00:00:00', '2025-01-01 00:00:00')",
        );

        let req = EraseRequest {
            issuer: ISS.to_owned(),
            subject: "sub1".to_owned(),
            tenant_id: Some("t1".to_owned()),
            revision: 7,
        };
        let (r, kicks) = erase_user(c, &req, &cells(), NOW).unwrap();
        assert!(r.user_existed && r.tombstone_recorded);
        assert_eq!(r.pending_deletions_queued, 2);
        assert_eq!(kicks.users.len(), 1);

        let mut keys: Vec<String> =
            tenant_pending_deletions::table.select(tenant_pending_deletions::object_key).load(c).unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec!["cells/us-east-1/tenants/t1/attachments/pc/pa", "cells/us-east-1/tenants/t1/sends/s1/file1"]
        );

        assert_eq!(users::table.filter(users::uuid.eq("u1")).count().get_result::<i64>(c).unwrap(), 0);
        assert_eq!(sso_users::table.filter(sso_users::user_uuid.eq("u1")).count().get_result::<i64>(c).unwrap(), 0);
        assert_eq!(ciphers::table.filter(ciphers::uuid.eq("pc")).count().get_result::<i64>(c).unwrap(), 0);
        let oc: Option<String> = ciphers::table.find("oc").select(ciphers::user_uuid).first(c).unwrap();
        assert_eq!(oc, None, "org cipher kept without creator reference");
        assert_eq!(attachments::table.select(attachments::id).load::<String>(c).unwrap(), vec!["oa"]);
        assert_eq!(ciphers_collections::table.count().get_result::<i64>(c).unwrap(), 1);
        assert_eq!(users_organizations::table.select(users_organizations::uuid).load::<String>(c).unwrap(), vec!["m2"]);
        assert_eq!(users::table.filter(users::uuid.eq("u2")).count().get_result::<i64>(c).unwrap(), 1);
        assert_eq!(tenant_recovery_bundles::table.count().get_result::<i64>(c).unwrap(), 0);
        let stone: i64 = tenant_erased_subjects::table
            .find((ISS, "sub1"))
            .select(tenant_erased_subjects::revision)
            .first(c)
            .unwrap();
        assert_eq!(stone, 7);

        // Replay: idempotent, tombstone kept.
        let (r, _) = erase_user(c, &req, &cells(), NOW).unwrap();
        assert!(!r.user_existed && r.tombstone_recorded);
        assert_eq!(r.pending_deletions_queued, 0);
    }

    #[test]
    fn purge_is_tenant_scoped_and_finalizes_after_cleanup() {
        let c = &mut test_sqlite_conn();
        for (t, u, o) in [("ta", "ua", "oa"), ("tb", "ub", "ob")] {
            active_tenant(c, t);
            user(c, u, t, &format!("sub-{u}"));
            org(c, o, t);
            member(c, &format!("m-{u}"), u, o);
            cipher(c, &format!("pc-{u}"), Some(u), None, t);
            cipher(c, &format!("oc-{u}"), None, Some(o), t);
            attachment(c, &format!("att-{u}"), &format!("oc-{u}"), t);
            file_send(c, &format!("s-{u}"), u, t, "file1");
        }
        // Cross-tenant member of ta's org is removed from that org only.
        member(c, "m-ub-oa", "ub", "oa");

        let (r, kicks) = purge_begin(c, "ta", ISS, &cells(), NOW).unwrap();
        assert_eq!((r.status, r.pending_deletions), (STATUS_PURGE_PENDING, 3));
        assert_eq!(kicks.tenants, vec!["ta"]);
        let t = tenant(c, "ta");
        assert_eq!((t.app_enabled, t.access_epoch, t.storage_reserved_bytes), (false, 2, 0));
        assert!(t.deleted_at.is_some() && t.erased_at.is_none());

        let mut keys: Vec<(String, String)> = tenant_pending_deletions::table
            .select((tenant_pending_deletions::storage_kind, tenant_pending_deletions::object_key))
            .load(c)
            .unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                ("attachment".to_owned(), "cells/us-east-1/tenants/ta/attachments/oc-ua/att-ua".to_owned()),
                ("send".to_owned(), "cells/us-east-1/tenants/ta/sends/s-ua/file1".to_owned()),
                ("tenant_prefix".to_owned(), "cells/us-east-1/tenants/ta/".to_owned()),
            ]
        );
        assert!(tenant_erased_subjects::table.find((ISS, "sub-ua")).first::<TenantErasedSubject>(c).is_ok());
        assert!(tenant_erased_subjects::table.find((ISS, "sub-ub")).first::<TenantErasedSubject>(c).is_err());

        for (tbl, n_a) in [
            (users::table.filter(users::tenant_id.eq("ta")).count().get_result::<i64>(c).unwrap(), 0),
            (ciphers::table.filter(ciphers::tenant_id.eq("ta")).count().get_result::<i64>(c).unwrap(), 0),
            (organizations::table.filter(organizations::tenant_id.eq("ta")).count().get_result::<i64>(c).unwrap(), 0),
            (sends::table.filter(sends::tenant_id.eq("ta")).count().get_result::<i64>(c).unwrap(), 0),
        ] {
            assert_eq!(tbl, n_a);
        }
        assert_eq!(users::table.filter(users::tenant_id.eq("tb")).count().get_result::<i64>(c).unwrap(), 1);
        assert_eq!(ciphers::table.filter(ciphers::tenant_id.eq("tb")).count().get_result::<i64>(c).unwrap(), 2);
        assert_eq!(attachments::table.filter(attachments::tenant_id.eq("tb")).count().get_result::<i64>(c).unwrap(), 1);
        assert_eq!(
            users_organizations::table.select(users_organizations::uuid).load::<String>(c).unwrap(),
            vec!["m-ub"]
        );
        assert_eq!(stamp(c, "ub"), "stamp-ub");

        // Re-run is idempotent: no duplicate prefix sweep.
        assert_eq!(purge_begin(c, "ta", ISS, &cells(), NOW).unwrap().0.pending_deletions, 3);

        let items = cleanup_pending(c, Some(2), &cells(), NOW).unwrap().items;
        assert_eq!(items.len(), 2);
        let all: Vec<String> =
            cleanup_pending(c, None, &cells(), NOW).unwrap().items.into_iter().map(|i| i.id).collect();
        let r = cleanup_complete(
            c,
            &CompleteRequest {
                completed_ids: all[..2].to_vec(),
                failed: vec![FailedItem {
                    id: all[2].clone(),
                    error: "x".repeat(900),
                }],
            },
            &cells(),
            NOW,
        )
        .unwrap();
        assert_eq!((r.deleted, r.failed_updated), (2, 1));
        assert_eq!(r.finalized_tenant_ids, Vec::<String>::new());
        let (attempts, err): (i32, Option<String>) = tenant_pending_deletions::table
            .find(&all[2])
            .select((tenant_pending_deletions::attempts, tenant_pending_deletions::last_error))
            .first(c)
            .unwrap();
        assert_eq!((attempts, err.map(|e| e.len())), (1, Some(MAX_ERROR_LEN)));

        let r = cleanup_complete(
            c,
            &CompleteRequest {
                completed_ids: vec![all[2].clone()],
                failed: vec![],
            },
            &cells(),
            NOW + 5,
        )
        .unwrap();
        assert_eq!(r.finalized_tenant_ids, vec!["ta"]);
        let t = tenant(c, "ta");
        assert_eq!((t.status.as_str(), t.erased_at), (STATUS_DELETED, Some(naive(NOW + 5))));

        let r = purge_begin(c, "ta", ISS, &cells(), NOW).unwrap().0;
        assert_eq!((r.status, r.pending_deletions), (STATUS_DELETED, 0));

        // Unknown tenant is refused with 403 under C5 (never creates a phantom empty-cell row).
        let err = purge_begin(c, "never-seen", ISS, &cells(), NOW).unwrap_err();
        assert_eq!(err.error_code(), 403);
        assert!(lock_tenant(c, "never-seen").unwrap().is_none());

        assert!(
            cleanup_complete(
                c,
                &CompleteRequest {
                    completed_ids: (0..=MAX_BATCH).map(|i| i.to_string()).collect(),
                    failed: vec![],
                },
                &cells(),
                NOW
            )
            .is_err()
        );
    }

    #[test]
    fn storage_prepare_apply_replay_stale_and_repair() {
        let c = &mut test_sqlite_conn();
        active_tenant(c, "t1");
        user(c, "u1", "t1", "sub1");
        cipher(c, "pc", Some("u1"), None, "t1"); // 10 bytes of data
        attachment(c, "pa", "pc", "t1"); // 100 bytes plus a 1-byte name
        diesel::update(tenants::table.find("t1")).set(tenants::storage_reserved_bytes.eq(5)).execute(c).unwrap();
        let prep = |c: &mut DbConnInner| {
            storage_prepare(
                c,
                &PrepareRequest {
                    want_bytes_default: 1000,
                    limit: 500,
                },
                &cells(),
                NOW,
            )
            .unwrap()
            .reports
        };
        let apply = |c: &mut DbConnInner, result: &str, seq: i64, sent_at: i64| {
            storage_apply(
                c,
                &ApplyRequest {
                    sent_at,
                    results: vec![ApplyItem {
                        org_id: "t1".to_owned(),
                        result: result.to_owned(),
                        report_seq: seq,
                        seq,
                        ceiling_bytes: 5000,
                        ttl_seconds: 3600,
                        pool_bytes: 9000,
                        org_used_bytes: 117,
                        over_since: None,
                    }],
                },
                &cells(),
                NOW,
            )
            .unwrap()
        };
        let first = StorageReport {
            org_id: "t1".to_owned(),
            used_bytes: 117,
            seq: 1,
            want_bytes: 1000,
        };
        assert_eq!(prep(c), vec![first]);

        // Unapplied report replays the exact seq and bytes even after usage changed.
        attachment(c, "pb", "pc", "t1");
        assert_eq!(prep(c)[0].seq, 1);
        assert_eq!(prep(c)[0].used_bytes, 117);

        // Future-dated sent_at is clamped to now; TTL capped at 900 s.
        assert_eq!(apply(c, "ok", 1, NOW + 10_000).applied, 1);
        let t = tenant(c, "t1");
        assert_eq!(t.storage_grant_expires_at, Some(NOW + MAX_GRANT_TTL_SECS));
        assert_eq!((t.storage_ceiling_bytes, t.storage_last_applied_seq, t.storage_pending_seq), (5000, 1, None));

        let next = prep(c);
        assert_eq!((next[0].seq, next[0].used_bytes), (2, 218));
        // Out-of-order and never-issued sequences are ignored.
        assert_eq!(apply(c, "ok", 1, NOW).applied, 0);
        assert_eq!(apply(c, "ok", 99, NOW).applied, 0);
        assert_eq!(tenant(c, "t1").storage_pending_seq, Some(2));
        // Delayed stale or unknown_org answers to the applied report 1 change nothing.
        assert_eq!(apply(c, "stale", 1, NOW).applied, 0);
        assert_eq!(apply(c, "unknown_org", 1, NOW).applied, 0);
        let t = tenant(c, "t1");
        assert_eq!((t.storage_pending_seq, t.storage_ceiling_bytes, t.storage_seq_stale), (Some(2), 5000, false));

        // A report sent while active and answered after a fence installs no grant.
        reconcile(c, vec![snap("t1", "suspended", true, 5)], false, NOW);
        assert_eq!(apply(c, "ok", 2, NOW).applied, 1);
        let t = tenant(c, "t1");
        assert_eq!((t.storage_ceiling_bytes, t.storage_grant_expires_at, t.storage_last_applied_seq), (0, None, 2));
        reconcile(c, vec![snap("t1", "active", true, 6)], false, NOW);
        assert_eq!(prep(c)[0].seq, 3);
        assert_eq!(apply(c, "ok", 3, NOW).applied, 1);
        assert_eq!(tenant(c, "t1").storage_ceiling_bytes, 5000);
        assert_eq!(prep(c)[0].seq, 4);

        let r = apply(c, "stale", 4, NOW);
        assert_eq!(r.stale_tenant_ids, vec!["t1"]);
        let t = tenant(c, "t1");
        assert!(t.storage_seq_stale);
        assert_eq!((t.storage_report_seq, t.storage_ceiling_bytes), (4, 5000), "grant kept, seq never reset");
        assert_eq!(prep(c), vec![], "stale tenants wait for operator repair");

        let repair = |c: &mut DbConnInner, next_seq| {
            storage_repair_seq(
                c,
                &RepairSeqRequest {
                    org_id: "t1".to_owned(),
                    next_seq,
                },
                &cells(),
            )
        };
        assert!(repair(c, 2).is_err());
        assert!(repair(c, 0).is_err());
        let r = repair(c, 42).unwrap();
        assert_eq!((r.storage_report_seq, r.storage_seq_stale), (41, false));
        assert_eq!(prep(c)[0].seq, 42);

        assert_eq!(apply(c, "unknown_org", 0, NOW).applied, 0, "an answer must name its report");
        assert_eq!(apply(c, "unknown_org", 42, NOW).applied, 1);
        let t = tenant(c, "t1");
        assert_eq!((t.storage_ceiling_bytes, t.storage_grant_expires_at, t.storage_pending_seq), (0, None, None));

        // Suspended tenant releases its grant with want_bytes 0; tombstoned tenants never report.
        diesel::update(tenants::table.find("t1"))
            .set((tenants::status.eq("suspended"), tenants::storage_ceiling_bytes.eq(10)))
            .execute(c)
            .unwrap();
        assert_eq!(prep(c)[0].want_bytes, 0);
        diesel::update(tenants::table.find("t1")).set(tenants::status.eq(STATUS_PURGE_PENDING)).execute(c).unwrap();
        assert_eq!(prep(c), vec![]);
        assert_eq!(
            storage_repair_seq(
                c,
                &RepairSeqRequest {
                    org_id: "nope".to_owned(),
                    next_seq: 1,
                },
                &cells(),
            )
            .unwrap_err()
            .error_code(),
            403
        );
    }

    #[test]
    fn go_wire_null_fields_deserialize_cleanly() {
        let erase: EraseRequest = serde_json::from_str(
            r#"{"issuer":"https://id.busnes.app","subject":"sub1","tenant_id":null,"revision":null}"#,
        )
        .unwrap();
        assert_eq!(erase.revision, 0);
        assert!(erase.tenant_id.is_none());

        let apply: ApplyRequest = serde_json::from_str(
            r#"{"sent_at":1750000000,"results":[{"org_id":"t1","result":"unknown_org","seq":null,"ceiling_bytes":null,"ttl_seconds":null,"pool_bytes":null,"org_used_bytes":null,"over_since":null}]}"#,
        )
        .unwrap();
        assert_eq!(apply.results.len(), 1);
        assert_eq!(apply.results[0].seq, 0);

        let rec: ReconcileRequest = serde_json::from_str(r#"{"orgs":null,"touch_all_active":true}"#).unwrap();
        assert_eq!(rec.orgs.len(), 0);

        let comp: CompleteRequest = serde_json::from_str(r#"{"completed_ids":null,"failed":null}"#).unwrap();
        assert_eq!(comp.completed_ids.len(), 0);
        assert_eq!(comp.failed.len(), 0);
    }

    #[test]
    fn c4_home_region_change_never_mutates_and_fences_tenant() {
        let c = &mut test_sqlite_conn();
        let multi_cells = vec!["us-east-1".to_owned(), "us-east-2".to_owned()];
        reconcile_orgs(
            c,
            &ReconcileRequest {
                orgs: vec![snap("t1", "active", true, 1)],
                touch_all_active: false,
            },
            &multi_cells,
            NOW,
        )
        .unwrap();
        user(c, "u1", "t1", "sub1");
        diesel::update(tenants::table.find("t1"))
            .set((tenants::storage_ceiling_bytes.eq(5000), tenants::storage_grant_expires_at.eq(Some(NOW + 600))))
            .execute(c)
            .unwrap();
        assert_eq!(stamp(c, "u1"), "stamp-u1");

        // C4: moving t1 even to ANOTHER served cell ("us-east-2") must NOT overwrite home_region,
        // must fence the tenant, clear authority_refreshed_at (even with touch_all_active=true),
        // and report t1 in region_mismatch_tenant_ids.
        let mut moved = snap("t1", "active", true, 2);
        moved.home_region = "us-east-2".to_owned();
        let (resp, kicks) = reconcile_orgs(
            c,
            &ReconcileRequest {
                orgs: vec![moved],
                touch_all_active: true,
            },
            &multi_cells,
            NOW + 60,
        )
        .unwrap();

        assert_eq!(resp.applied, 0);
        assert_eq!(resp.fenced_tenant_ids, vec!["t1"]);
        assert_eq!(resp.region_mismatch_tenant_ids, vec!["t1"]);
        assert_eq!(kicks.tenants, vec!["t1"]);

        let t = tenant(c, "t1");
        assert_eq!(t.home_region, "us-east-1", "C4: stored home_region must remain immutable");
        assert_eq!(t.access_epoch, 2);
        assert_eq!(t.storage_ceiling_bytes, 0);
        assert_eq!(t.storage_grant_expires_at, None);
        assert_eq!(t.authority_refreshed_at, None);
        assert_ne!(stamp(c, "u1"), "stamp-u1");
        let rt: String = devices::table.find(("dev-u1", "u1")).select(devices::refresh_token).first(c).unwrap();
        assert_ne!(rt, "rt-u1");

        // A subsequent empty heartbeat poll (touch_all_active=true) must NOT revive the C4-fenced tenant.
        let (hb, _) = reconcile_orgs(
            c,
            &ReconcileRequest {
                orgs: vec![],
                touch_all_active: true,
            },
            &multi_cells,
            NOW + 120,
        )
        .unwrap();
        assert_eq!(hb.applied, 0);
        assert_eq!(tenant(c, "t1").authority_refreshed_at, None);

        // Storage prepare/apply must also never grant storage to a C4-fenced tenant.
        let prep = storage_prepare(
            c,
            &PrepareRequest {
                want_bytes_default: 4096,
                limit: 10,
            },
            &multi_cells,
            NOW,
        )
        .unwrap();
        if let Some(rep) = prep.reports.iter().find(|r| r.org_id == "t1") {
            assert_eq!(rep.want_bytes, 0);
            storage_apply(
                c,
                &ApplyRequest {
                    sent_at: NOW + 125,
                    results: vec![ApplyItem {
                        org_id: "t1".into(),
                        result: "ok".into(),
                        report_seq: rep.seq,
                        seq: rep.seq,
                        ceiling_bytes: 99_999,
                        ttl_seconds: 600,
                        pool_bytes: 999_999,
                        org_used_bytes: 0,
                        over_since: None,
                    }],
                },
                &multi_cells,
                NOW + 125,
            )
            .unwrap();
        }
        let after = tenant(c, "t1");
        assert_eq!(after.storage_ceiling_bytes, 0);
        assert_eq!(after.storage_grant_expires_at, None);
    }

    #[test]
    fn erased_subject_cannot_be_provisioned_again() {
        use crate::db::models::{SignInUpdate, SsoUser, User, update_signed_in_user_tx};
        let c = &mut test_sqlite_conn();
        active_tenant(c, "t1");
        let provision = |c: &mut DbConnInner, tid: &str| {
            let mut user = User::new("new@example.com", None);
            user.tenant_id = Some(tid.to_owned());
            let link = SsoUser {
                user_uuid: user.uuid.clone(),
                identifier: format_oidc_identifier(ISS, "sub-new").into(),
                tenant_id: user.tenant_id.clone(),
            };
            TenantErasedSubject::provision_sso_user_inner(c, &user, &link, ISS, "sub-new", &cells(), NOW, 900)
        };
        let count = |c: &mut DbConnInner| {
            users::table.filter(users::email.eq("new@example.com")).count().get_result::<i64>(c).unwrap()
        };

        assert!(provision(c, "missing").is_err(), "unknown tenant");
        provision(c, "t1").unwrap();
        assert_eq!((count(c), sso_users::table.count().get_result::<i64>(c).unwrap()), (1, 1));
        let mut existing = users::table.filter(users::email.eq("new@example.com")).first::<User>(c).unwrap();
        existing.name = "finished key setup".to_owned();
        TenantErasedSubject::update_sso_user_inner(c, &existing, ISS, "sub-new").unwrap();

        // KyIdentity disables the account and rotates its stamp while a sign-in still holds the old row.
        let stale = users::table.find(&existing.uuid).first::<User>(c).unwrap();
        exec(c, "UPDATE users SET enabled = 0, security_stamp = 'revoked' WHERE email = 'new@example.com'");
        let mut stale_stub = stale;
        stale_stub.name = "stale".to_owned();
        assert!(TenantErasedSubject::update_sso_user_inner(c, &stale_stub, ISS, "sub-new").is_err());
        assert!(update_signed_in_user_tx(c, &stale_stub, &SignInUpdate::RecoveryCodeUsed).is_err());
        let (enabled, stamp, name): (bool, String, String) = users::table
            .find(&existing.uuid)
            .select((users::enabled, users::security_stamp, users::name))
            .first(c)
            .unwrap();
        assert_eq!((enabled, stamp.as_str(), name.as_str()), (false, "revoked", "finished key setup"));
        // Only a row matching what the sign-in loaded is written, and only its sign-in fields.
        exec(c, "UPDATE users SET enabled = 1 WHERE email = 'new@example.com'");
        let mut fresh = users::table.find(&existing.uuid).first::<User>(c).unwrap();
        fresh.totp_recover = Some("code".to_owned());
        exec(c, "UPDATE users SET totp_recover = 'code' WHERE email = 'new@example.com'");
        update_signed_in_user_tx(c, &fresh, &SignInUpdate::RecoveryCodeUsed).unwrap();
        let recover: Option<String> = users::table.find(&existing.uuid).select(users::totp_recover).first(c).unwrap();
        assert_eq!(recover, None);

        let req = EraseRequest {
            issuer: ISS.to_owned(),
            subject: "sub-new".to_owned(),
            tenant_id: Some("t1".to_owned()),
            revision: 1,
        };
        assert!(erase_user(c, &req, &cells(), NOW).unwrap().0.user_existed);
        assert_eq!(count(c), 0);

        let err = provision(c, "t1").unwrap_err();
        assert!(err.to_string().contains("permanently erased"), "{err}");
        // A stale save from a sign-in that loaded the user before erasure cannot restore it.
        let err = TenantErasedSubject::update_sso_user_inner(c, &existing, ISS, "sub-new").unwrap_err();
        assert!(err.to_string().contains("permanently erased"), "{err}");
        assert!(
            update_signed_in_user_tx(c, &fresh, &SignInUpdate::VerifiedStub).is_err(),
            "update-only never re-inserts"
        );
        assert_eq!(count(c), 0, "refused sign-ins left no user row");
    }

    #[test]
    fn failing_storage_reports_rotate_behind_other_tenants() {
        let c = &mut test_sqlite_conn();
        for t in ["t1", "t2", "t3"] {
            active_tenant(c, t);
        }
        let prepare = |c: &mut DbConnInner, now: i64| -> Vec<String> {
            let req = PrepareRequest {
                want_bytes_default: 1000,
                limit: 2,
            };
            storage_prepare(c, &req, &cells(), now).unwrap().reports.into_iter().map(|r| r.org_id).collect()
        };
        assert_eq!(prepare(c, NOW), ["t1", "t2"]);
        // Upstream never applies t1 and t2; their pending reports must not take every batch.
        assert_eq!(prepare(c, NOW + 1), ["t3", "t1"]);
        assert_eq!(prepare(c, NOW + 2), ["t2", "t1"]);
    }

    #[test]
    fn cleanup_cannot_finalize_a_tenant_before_its_rows_are_purged() {
        let c = &mut test_sqlite_conn();
        active_tenant(c, "t1");
        user(c, "u1", "t1", "sub1");
        exec(c, "UPDATE tenants SET status = 'purge_pending' WHERE id = 't1'"); // as reconciliation does
        exec(
            c,
            "INSERT INTO tenant_pending_deletions (id, tenant_id, storage_kind, object_key, attempts, created_at) \
             VALUES ('pd-old', 't1', 'attachment', 'cells/us-east-1/tenants/t1/attachments/c/a', 0, '2025-01-01 00:00:00')",
        );
        let complete = |c: &mut DbConnInner, ids: Vec<String>| {
            let req = CompleteRequest {
                completed_ids: ids,
                failed: vec![],
            };
            cleanup_complete(c, &req, &cells(), NOW).unwrap().finalized_tenant_ids
        };
        assert!(complete(c, vec!["pd-old".to_owned()]).is_empty());
        assert_eq!(tenant(c, "t1").status, STATUS_PURGE_PENDING);

        // The purge still runs, and only its cleanup finalizes the tenant.
        purge_begin(c, "t1", ISS, &cells(), NOW).unwrap();
        assert_eq!(users::table.filter(users::tenant_id.eq("t1")).count().get_result::<i64>(c).unwrap(), 0);
        let ids: Vec<String> =
            cleanup_pending(c, None, &cells(), NOW).unwrap().items.into_iter().map(|i| i.id).collect();
        assert_eq!(complete(c, ids), ["t1"]);
        assert_eq!(tenant(c, "t1").status, STATUS_DELETED);
    }

    #[test]
    fn inactive_tenant_reports_once_after_erasure_changes_its_usage() {
        let c = &mut test_sqlite_conn();
        active_tenant(c, "t1");
        user(c, "u1", "t1", "sub1");
        exec(c, "UPDATE tenants SET status = 'suspended', storage_last_applied_seq = 3 WHERE id = 't1'");
        let prepare = |c: &mut DbConnInner| -> Vec<(String, i64)> {
            let req = PrepareRequest {
                want_bytes_default: 1000,
                limit: 10,
            };
            storage_prepare(c, &req, &cells(), NOW)
                .unwrap()
                .reports
                .into_iter()
                .map(|r| (r.org_id, r.want_bytes))
                .collect()
        };
        assert!(prepare(c).is_empty(), "a settled suspended tenant does not report");

        let req = EraseRequest {
            issuer: ISS.to_owned(),
            subject: "sub1".to_owned(),
            tenant_id: Some("t1".to_owned()),
            revision: 1,
        };
        erase_user(c, &req, &cells(), NOW).unwrap();
        assert_eq!(prepare(c), [("t1".to_owned(), 0)]);
        assert!(!tenant(c, "t1").storage_dirty);
    }

    #[test]
    fn failing_cleanup_rotates_behind_newer_jobs() {
        let c = &mut test_sqlite_conn();
        active_tenant_in(c, "local", "us-east-1");
        for (id, at) in [("pd-1", "2025-01-01"), ("pd-2", "2025-01-02"), ("pd-3", "2025-01-03")] {
            exec(
                c,
                &format!(
                    "INSERT INTO tenant_pending_deletions (id, tenant_id, storage_kind, object_key, attempts, created_at) \
                     VALUES ('{id}', 'local', 'attachment', 'cells/us-east-1/tenants/local/attachments/c/{id}', 0, '{at} 00:00:00')"
                ),
            );
        }
        let ids = |c: &mut DbConnInner| -> Vec<String> {
            cleanup_pending(c, Some(2), &cells(), NOW).unwrap().items.into_iter().map(|i| i.id).collect()
        };
        assert_eq!(ids(c), ["pd-1", "pd-2"]);
        let fail = |id: &str| FailedItem {
            id: id.to_owned(),
            error: "object locked".to_owned(),
        };
        let req = CompleteRequest {
            completed_ids: vec![],
            failed: vec![fail("pd-1"), fail("pd-2")],
        };
        cleanup_complete(c, &req, &cells(), NOW).unwrap();
        assert_eq!(ids(c), ["pd-3", "pd-1"]);
    }

    #[test]
    fn c5_every_internal_op_refuses_unserved_cell_with_403() {
        let c = &mut test_sqlite_conn();
        active_tenant_in(c, "local", "us-east-1");
        active_tenant_in(c, "foreign", "eu-west-1");
        user(c, "u-foreign", "foreign", "sub-foreign");
        exec(
            c,
            "INSERT INTO tenant_pending_deletions (id, tenant_id, storage_kind, object_key, attempts, created_at) \
             VALUES ('pd-foreign', 'foreign', 'attachment', 'cells/eu-west-1/tenants/foreign/attachments/c/a', 0, '2025-01-01 00:00:00')",
        );

        let served = cells();

        // 1. reconcile_orgs rejects unknown foreign org with 403.
        let mut new_foreign = snap("new-foreign", "active", true, 1);
        new_foreign.home_region = "eu-west-1".to_owned();
        assert_eq!(
            reconcile_orgs(
                c,
                &ReconcileRequest {
                    orgs: vec![new_foreign],
                    touch_all_active: false,
                },
                &served,
                NOW,
            )
            .unwrap_err()
            .error_code(),
            403
        );

        // 2. logout_user rejects foreign tenant (by explicit tenant_id AND by subject lookup).
        assert_eq!(
            logout_user(
                c,
                &LogoutRequest {
                    issuer: ISS.to_owned(),
                    subject: "sub-foreign".to_owned(),
                    tenant_id: Some("foreign".to_owned()),
                },
                &served,
                NOW,
            )
            .unwrap_err()
            .error_code(),
            403
        );
        assert_eq!(
            logout_user(
                c,
                &LogoutRequest {
                    issuer: ISS.to_owned(),
                    subject: "sub-foreign".to_owned(),
                    tenant_id: None,
                },
                &served,
                NOW,
            )
            .unwrap_err()
            .error_code(),
            403
        );

        // 3. sync_user rejects foreign tenant.
        assert_eq!(
            sync_user(
                c,
                &SyncRequest {
                    event_type: "user.updated".to_owned(),
                    issuer: ISS.to_owned(),
                    subject: "sub-foreign".to_owned(),
                    tenant_id: Some("foreign".to_owned()),
                    display_name: Some("Bob".to_owned()),
                    active: true,
                },
                &served,
                NOW,
            )
            .unwrap_err()
            .error_code(),
            403
        );

        // 4. erase_user rejects foreign tenant.
        assert_eq!(
            erase_user(
                c,
                &EraseRequest {
                    issuer: ISS.to_owned(),
                    subject: "sub-foreign".to_owned(),
                    tenant_id: Some("foreign".to_owned()),
                    revision: 1,
                },
                &served,
                NOW,
            )
            .unwrap_err()
            .error_code(),
            403
        );

        // 5. purge_begin rejects foreign tenant.
        assert_eq!(purge_begin(c, "foreign", ISS, &served, NOW).unwrap_err().error_code(), 403);

        // 6. cleanup_pending hides foreign items; cleanup_complete rejects foreign item with 403.
        assert!(cleanup_pending(c, None, &served, NOW).unwrap().items.is_empty());
        assert_eq!(
            cleanup_complete(
                c,
                &CompleteRequest {
                    completed_ids: vec!["pd-foreign".to_owned()],
                    failed: vec![],
                },
                &served,
                NOW,
            )
            .unwrap_err()
            .error_code(),
            403
        );

        // 7. storage_prepare omits foreign tenant; storage_apply and storage_repair_seq reject with 403.
        let prep = storage_prepare(
            c,
            &PrepareRequest {
                want_bytes_default: 1000,
                limit: 500,
            },
            &served,
            NOW,
        )
        .unwrap();
        assert_eq!(prep.reports.iter().map(|r| r.org_id.as_str()).collect::<Vec<_>>(), vec!["local"]);

        assert_eq!(
            storage_apply(
                c,
                &ApplyRequest {
                    sent_at: NOW,
                    results: vec![ApplyItem {
                        org_id: "foreign".to_owned(),
                        result: "ok".to_owned(),
                        report_seq: 1,
                        seq: 1,
                        ceiling_bytes: 1000,
                        ttl_seconds: 600,
                        pool_bytes: 1000,
                        org_used_bytes: 0,
                        over_since: None,
                    }],
                },
                &served,
                NOW,
            )
            .unwrap_err()
            .error_code(),
            403
        );

        assert_eq!(
            storage_repair_seq(
                c,
                &RepairSeqRequest {
                    org_id: "foreign".to_owned(),
                    next_seq: 10,
                },
                &served,
            )
            .unwrap_err()
            .error_code(),
            403
        );
    }

    #[test]
    fn multi_cell_deployment_serves_multiple_cells_with_isolated_object_keys() {
        let c = &mut test_sqlite_conn();
        let multi = vec!["us-east-1".to_owned(), "us-east-2".to_owned()];

        let mut s2 = snap("t2", "active", true, 1);
        s2.home_region = "us-east-2".to_owned();
        let (r, _) = reconcile_orgs(
            c,
            &ReconcileRequest {
                orgs: vec![snap("t1", "active", true, 1), s2],
                touch_all_active: false,
            },
            &multi,
            NOW,
        )
        .unwrap();
        assert_eq!(r.applied, 2);

        user(c, "u1", "t1", "sub1");
        user(c, "u2", "t2", "sub2");
        cipher(c, "c1", Some("u1"), None, "t1");
        cipher(c, "c2", Some("u2"), None, "t2");
        attachment(c, "a1", "c1", "t1");
        attachment(c, "a2", "c2", "t2");

        purge_begin(c, "t1", ISS, &multi, NOW).unwrap();
        purge_begin(c, "t2", ISS, &multi, NOW).unwrap();

        let mut keys: Vec<String> =
            cleanup_pending(c, None, &multi, NOW).unwrap().items.into_iter().map(|i| i.object_key).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "cells/us-east-1/tenants/t1/",
                "cells/us-east-1/tenants/t1/attachments/c1/a1",
                "cells/us-east-2/tenants/t2/",
                "cells/us-east-2/tenants/t2/attachments/c2/a2",
            ]
        );
    }

    #[test]
    fn recovery_kit_enforces_storage_grant_and_replaces_old_ciphertext() {
        use crate::db::models::{TenantRecoveryBundle, UserId, committed_bytes};

        let c = &mut test_sqlite_conn();
        let served = cells();
        active_tenant(c, "t1");
        user(c, "u1", "t1", "sub1");
        diesel::update(tenants::table.find("t1"))
            .set((
                tenants::storage_ceiling_bytes.eq(30),
                tenants::storage_grant_expires_at.eq(Some(NOW + 600)),
                tenants::authority_refreshed_at.eq(Some(NOW)),
            ))
            .execute(c)
            .unwrap();

        let k1 = TenantRecoveryBundle::new_personal_kit(
            "t1".to_owned(),
            UserId::from("u1".to_owned()),
            1,
            "{}".to_owned(),
            "a".repeat(10),
            None,
            None,
        );
        TenantRecoveryBundle::upsert_personal_kit_inner(c, &k1, Some((&served, 900)), NOW).unwrap();
        assert_eq!(tenant_recovery_bundles::table.count().get_result::<i64>(c).unwrap(), 1);
        assert_eq!(committed_bytes(c, "t1").unwrap(), 10);

        // Rotate within grant: old bundle is deleted, not left uncounted.
        let k2 = TenantRecoveryBundle::new_personal_kit(
            "t1".to_owned(),
            UserId::from("u1".to_owned()),
            1,
            "{}".to_owned(),
            "b".repeat(20),
            None,
            None,
        );
        TenantRecoveryBundle::upsert_personal_kit_inner(c, &k2, Some((&served, 900)), NOW).unwrap();
        assert_eq!(tenant_recovery_bundles::table.count().get_result::<i64>(c).unwrap(), 1);
        assert_eq!(committed_bytes(c, "t1").unwrap(), 20);

        // Exhausted grant rejects larger upload without touching existing kit.
        let k_too_big = TenantRecoveryBundle::new_personal_kit(
            "t1".to_owned(),
            UserId::from("u1".to_owned()),
            1,
            "{}".to_owned(),
            "c".repeat(40),
            None,
            None,
        );
        assert!(TenantRecoveryBundle::upsert_personal_kit_inner(c, &k_too_big, Some((&served, 900)), NOW).is_err());

        // Expired grant rejects larger upload without inserting or revoking rows.
        diesel::update(tenants::table.find("t1"))
            .set((tenants::storage_ceiling_bytes.eq(1000), tenants::storage_grant_expires_at.eq(Some(NOW - 10))))
            .execute(c)
            .unwrap();
        let k3 = TenantRecoveryBundle::new_personal_kit(
            "t1".to_owned(),
            UserId::from("u1".to_owned()),
            1,
            "{}".to_owned(),
            "d".repeat(30),
            None,
            None,
        );
        assert!(TenantRecoveryBundle::upsert_personal_kit_inner(c, &k3, Some((&served, 900)), NOW).is_err());

        let remaining: Vec<TenantRecoveryBundle> = tenant_recovery_bundles::table.load(c).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].uuid, k2.uuid);
        assert_eq!(remaining[0].revoked_at, None);
    }

    #[test]
    fn staged_upload_cleanup_survives_insert_failure_and_respects_grace() {
        use crate::db::models::{Attachment, AttachmentId, CipherId, TenantPendingDeletion};
        use diesel::connection::SimpleConnection;

        let c = &mut test_sqlite_conn();
        let served = cells();
        #[allow(irrefutable_let_patterns)]
        if let DbConnInner::Sqlite(s) = c {
            s.batch_execute("PRAGMA foreign_keys = ON;").unwrap();
        }
        active_tenant(c, "t1");
        user(c, "u1", "t1", "sub1");
        diesel::update(tenants::table.find("t1")).set(tenants::storage_reserved_bytes.eq(128)).execute(c).unwrap();

        let staged = TenantPendingDeletion {
            id: "pd-staged".to_owned(),
            tenant_id: "t1".to_owned(),
            user_uuid: Some(UserId::from("u1".to_owned())),
            storage_kind: "attachment".to_owned(),
            object_key: "cells/us-east-1/tenants/t1/attachments/missing-cipher/att1".to_owned(),
            attempts: 0,
            last_error: Some(UPLOAD_IN_FLIGHT_MARKER.to_owned()),
            reserved_bytes: 0,
            created_at: naive(NOW),
        };
        diesel::insert_into(tenant_pending_deletions::table).values(&staged).execute(c).unwrap();

        // While upload is actively in flight, worker does not see it.
        assert!(cleanup_pending(c, None, &served, NOW).unwrap().items.is_empty());

        // Simulating a mid-upload cipher deletion causes attachment insert to fail its FK constraint.
        let att_fail = Attachment::new(
            AttachmentId("att1".to_owned()),
            CipherId::from("missing-cipher".to_owned()),
            "f".to_owned(),
            128,
            None,
        )
        .with_tenant_id(Some("t1".to_owned()));
        assert!(
            Tenant::save_attachment_releasing_inner(c, "t1", &att_fail, 128, Some(1), Some("pd-staged"), NOW).is_err()
        );

        // Rollback preserves both the staged cleanup row and reserved bytes.
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 128);
        assert!(tenant_pending_deletions::table.find("pd-staged").first::<TenantPendingDeletion>(c).is_ok());

        // After the staging grace expires (e.g. process crash), cleanup_pending exposes it automatically.
        assert_eq!(cleanup_pending(c, None, &served, NOW + UPLOAD_STAGING_GRACE_SECS + 1).unwrap().items.len(), 1);

        // Activating the row on failure exposes it immediately at NOW.
        diesel::update(tenant_pending_deletions::table.find("pd-staged"))
            .set(tenant_pending_deletions::last_error.eq(None::<String>))
            .execute(c)
            .unwrap();
        assert_eq!(cleanup_pending(c, None, &served, NOW).unwrap().items.len(), 1);

        // Happy path: with a real cipher, saving the attachment atomically clears the staged row.
        cipher(c, "c1", Some("u1"), None, "t1");
        let staged_ok = TenantPendingDeletion {
            id: "pd-ok".to_owned(),
            tenant_id: "t1".to_owned(),
            user_uuid: Some(UserId::from("u1".to_owned())),
            storage_kind: "attachment".to_owned(),
            object_key: "cells/us-east-1/tenants/t1/attachments/c1/att2".to_owned(),
            attempts: 0,
            last_error: Some(UPLOAD_IN_FLIGHT_MARKER.to_owned()),
            reserved_bytes: 0,
            created_at: naive(NOW),
        };
        diesel::insert_into(tenant_pending_deletions::table).values(&staged_ok).execute(c).unwrap();
        let att_ok = Attachment::new(
            AttachmentId("att2".to_owned()),
            CipherId::from("c1".to_owned()),
            "f".to_owned(),
            128,
            None,
        )
        .with_tenant_id(Some("t1".to_owned()));
        Tenant::save_attachment_releasing_inner(c, "t1", &att_ok, 128, Some(1), Some("pd-ok"), NOW).unwrap();
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 0);
        assert!(tenant_pending_deletions::table.find("pd-ok").first::<TenantPendingDeletion>(c).is_err());
    }

    #[test]
    fn cipher_save_enforces_storage_grant_and_preserves_stored_data() {
        use crate::db::models::{Cipher, committed_bytes};

        let c = &mut test_sqlite_conn();
        let served = cells();
        active_tenant(c, "t1");
        user(c, "u1", "t1", "sub1");

        let mut item = Cipher::new(1, "name".to_owned());
        item.user_uuid = Some(UserId::from("u1".to_owned()));
        item.tenant_id = Some("t1".to_owned());
        item.data = "0123456789".to_owned(); // 4 + 10 = 14 bytes

        // 1. Expired storage grant rejects creating a cipher without inserting anything.
        diesel::update(tenants::table.find("t1"))
            .set((tenants::storage_ceiling_bytes.eq(1000), tenants::storage_grant_expires_at.eq(Some(NOW - 1))))
            .execute(c)
            .unwrap();
        assert!(Tenant::save_cipher_enforcing_grant_inner(c, "t1", &item, &[], 900, &served, 10, NOW).is_err());
        assert_eq!(ciphers::table.filter(ciphers::tenant_id.eq("t1")).count().get_result::<i64>(c).unwrap(), 0);
        assert_eq!(committed_bytes(c, "t1").unwrap(), 0);

        // 2. Exhausted storage grant (ceiling smaller than cipher payload) rejects create.
        diesel::update(tenants::table.find("t1"))
            .set((tenants::storage_ceiling_bytes.eq(10), tenants::storage_grant_expires_at.eq(Some(NOW + 300))))
            .execute(c)
            .unwrap();
        assert!(Tenant::save_cipher_enforcing_grant_inner(c, "t1", &item, &[], 900, &served, 10, NOW).is_err());
        assert_eq!(ciphers::table.filter(ciphers::tenant_id.eq("t1")).count().get_result::<i64>(c).unwrap(), 0);

        // 3. Sufficient active grant allows creating the cipher and counts all encrypted fields.
        diesel::update(tenants::table.find("t1")).set(tenants::storage_ceiling_bytes.eq(20)).execute(c).unwrap();
        Tenant::save_cipher_enforcing_grant_inner(c, "t1", &item, &[], 900, &served, 10, NOW).unwrap();
        assert_eq!(committed_bytes(c, "t1").unwrap(), 14);

        // 4. Exhausted grant rejects enlarging data or notes without modifying stored data.
        let mut enlarged = ciphers::table.find(&item.uuid).first::<Cipher>(c).unwrap();
        enlarged.data = "01234567890123456789".to_owned(); // 4 + 20 = 24 > ceiling 20
        assert!(Tenant::save_cipher_enforcing_grant_inner(c, "t1", &enlarged, &[], 900, &served, 10, NOW).is_err());
        let stored = ciphers::table.find(&item.uuid).first::<Cipher>(c).unwrap();
        assert_eq!(stored.data, "0123456789");
        assert_eq!(committed_bytes(c, "t1").unwrap(), 14);

        let mut big_notes = stored;
        big_notes.notes = Some("1234567".to_owned()); // 14 + 7 = 21 > ceiling 20
        assert!(Tenant::save_cipher_enforcing_grant_inner(c, "t1", &big_notes, &[], 900, &served, 10, NOW).is_err());
        let stored = ciphers::table.find(&item.uuid).first::<Cipher>(c).unwrap();
        assert_eq!(stored.notes, None);

        // 5. Expired grant rejects even small growth without modifying stored data.
        diesel::update(tenants::table.find("t1"))
            .set((tenants::storage_ceiling_bytes.eq(1000), tenants::storage_grant_expires_at.eq(Some(NOW - 5))))
            .execute(c)
            .unwrap();
        let mut small_grow = stored;
        small_grow.data = "0123456789X".to_owned(); // +1 byte
        assert!(Tenant::save_cipher_enforcing_grant_inner(c, "t1", &small_grow, &[], 900, &served, 10, NOW).is_err());
        let stored = ciphers::table.find(&item.uuid).first::<Cipher>(c).unwrap();
        assert_eq!(stored.data, "0123456789");

        // 6. Shrinking / zero-delta updates (including soft-delete) succeed even with an expired grant.
        let mut shrunk = stored;
        shrunk.data = "01234".to_owned();
        shrunk.deleted_at = Some(naive(NOW));
        Tenant::save_cipher_enforcing_grant_inner(c, "t1", &shrunk, &[], 900, &served, 10, NOW).unwrap();
        let stored = ciphers::table.find(&item.uuid).first::<Cipher>(c).unwrap();
        assert_eq!(stored.data, "01234");
        assert!(stored.deleted_at.is_some());
        assert_eq!(committed_bytes(c, "t1").unwrap(), 9);

        // 7. Active cipher quota is enforced atomically under the tenant lock on create and restore.
        diesel::update(tenants::table.find("t1"))
            .set((tenants::storage_ceiling_bytes.eq(1000), tenants::storage_grant_expires_at.eq(Some(NOW + 300))))
            .execute(c)
            .unwrap();
        let mut second = Cipher::new(1, "second".to_owned());
        second.user_uuid = Some(UserId::from("u1".to_owned()));
        second.tenant_id = Some("t1".to_owned());
        second.data = "abc".to_owned();
        Tenant::save_cipher_enforcing_grant_inner(c, "t1", &second, &[], 900, &served, 1, NOW).unwrap();

        // Restoring the trashed first cipher would exceed max_ciphers = 1 -> rejected without mutating it.
        let mut restore = stored;
        restore.deleted_at = None;
        assert!(Tenant::save_cipher_enforcing_grant_inner(c, "t1", &restore, &[], 900, &served, 1, NOW).is_err());
        assert!(ciphers::table.find(&item.uuid).first::<Cipher>(c).unwrap().deleted_at.is_some());
    }

    #[test]
    fn v2_upload_concurrent_delete_retains_staged_cleanup_and_leaves_no_orphan() {
        use std::sync::{Arc, Barrier};

        use crate::db::{models::committed_bytes, test_sqlite_conn_at};

        struct TempDirGuard(std::path::PathBuf);
        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).ok();
            }
        }

        let dir = TempDirGuard(std::env::temp_dir().join(format!("kyvault-v2-race-{}", get_uuid())));
        std::fs::create_dir_all(&dir.0).unwrap();
        let db_path = dir.0.join("vault.sqlite3");
        let db_url = db_path.to_string_lossy().into_owned();
        let store_root = dir.0.join("objects");
        std::fs::create_dir_all(&store_root).unwrap();

        let served = cells();
        let mut setup = test_sqlite_conn_at(&db_url);
        active_tenant(&mut setup, "t1");
        user(&mut setup, "u1", "t1", "sub1");
        cipher(&mut setup, "c1", Some("u1"), None, "t1");
        // Pre-created v2 attachment row (100 declared bytes, actual uploaded blob will be 128 bytes).
        attachment(&mut setup, "att-v2", "c1", "t1");
        diesel::update(tenants::table.find("t1"))
            .set(tenants::storage_reserved_bytes.eq(28))
            .execute(&mut setup)
            .unwrap();

        let att = Attachment::new(
            AttachmentId("att-v2".to_owned()),
            CipherId::from("c1".to_owned()),
            "f".to_owned(),
            100,
            None,
        )
        .with_tenant_id(Some("t1".to_owned()));
        let object_key = att.get_file_path_in_cell(Some(REGION)).unwrap();
        let object_path = store_root.join(&object_key);
        let pending_id = "pd-v2-race";

        // Stage durable in-flight cleanup BEFORE starting the v2 object write.
        let staged = TenantPendingDeletion {
            id: pending_id.to_owned(),
            tenant_id: "t1".to_owned(),
            user_uuid: Some(UserId::from("u1".to_owned())),
            storage_kind: "attachment".to_owned(),
            object_key: object_key.clone(),
            attempts: 0,
            last_error: Some(UPLOAD_IN_FLIGHT_MARKER.to_owned()),
            reserved_bytes: 0,
            created_at: naive(NOW),
        };
        diesel::insert_into(tenant_pending_deletions::table).values(&staged).execute(&mut setup).unwrap();
        assert!(cleanup_pending(&mut setup, None, &served, NOW).unwrap().items.is_empty());

        // Run the v2 object write and concurrent attachment deletion across two threads synchronized
        // with barriers so deletion deterministically occurs mid-write.
        let write_started = Arc::new(Barrier::new(2));
        let delete_done = Arc::new(Barrier::new(2));

        let deleter_db = db_url;
        let deleter_path = object_path.clone();
        let b_start = Arc::clone(&write_started);
        let b_done = Arc::clone(&delete_done);
        let deleter = std::thread::spawn(move || {
            let mut del_conn = test_sqlite_conn_at(&deleter_db);
            b_start.wait();
            // Concurrent DELETE /ciphers/c1/attachment/att-v2: removes DB row and attempts
            // object delete before the in-flight upload finishes writing.
            let removed =
                diesel::delete(attachments::table.filter(attachments::id.eq("att-v2"))).execute(&mut del_conn).unwrap();
            assert_eq!(removed, 1);
            std::fs::remove_file(&deleter_path).ok();
            b_done.wait();
        });

        // Uploader thread: begins object write, pauses while deleter removes the DB row, then
        // completes writing the full 128-byte object to storage.
        std::fs::create_dir_all(object_path.parent().unwrap()).unwrap();
        write_started.wait();
        delete_done.wait();
        std::fs::write(&object_path, vec![0xABu8; 128]).unwrap();
        deleter.join().unwrap();

        // At this point the blob exists on disk, the attachment row is gone, and access_epoch is still 1.
        assert!(object_path.exists());
        assert_eq!(tenant(&mut setup, "t1").access_epoch, 1);

        // Finalizing the v2 upload MUST fail because the attachment row no longer exists,
        // and MUST leave the staged pending-deletion row intact for durable cleanup.
        assert!(
            Tenant::finalize_v2_attachment_upload_inner(
                &mut setup,
                "t1",
                &att,
                128,
                28,
                Some(1),
                Some(pending_id),
                NOW
            )
            .is_err()
        );
        assert!(tenant_pending_deletions::table.find(pending_id).first::<TenantPendingDeletion>(&mut setup).is_ok());
        assert_eq!(tenant(&mut setup, "t1").storage_reserved_bytes, 28);

        // Simulate best-effort object delete failure on the request path: activate the pending
        // deletion and release the reservation so the cleanup worker reclaims the orphan.
        diesel::update(tenant_pending_deletions::table.find(pending_id))
            .set(tenant_pending_deletions::last_error.eq(None::<String>))
            .execute(&mut setup)
            .unwrap();
        diesel::update(tenants::table.find("t1"))
            .set(tenants::storage_reserved_bytes.eq(0))
            .execute(&mut setup)
            .unwrap();

        let pending = cleanup_pending(&mut setup, None, &served, NOW).unwrap().items;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, pending_id);
        assert_eq!(pending[0].object_key, object_key);

        // Cleanup worker deletes the object and acknowledges completion.
        std::fs::remove_file(store_root.join(&pending[0].object_key)).unwrap();
        let done = cleanup_complete(
            &mut setup,
            &CompleteRequest {
                completed_ids: vec![pending[0].id.clone()],
                failed: vec![],
            },
            &served,
            NOW,
        )
        .unwrap();
        assert_eq!(done.deleted, 1);
        assert!(!object_path.exists());
        assert!(
            cleanup_pending(&mut setup, None, &served, NOW + UPLOAD_STAGING_GRACE_SECS + 1).unwrap().items.is_empty()
        );
        assert_eq!(attachments::table.count().get_result::<i64>(&mut setup).unwrap(), 0);
        assert_eq!(tenant(&mut setup, "t1").storage_reserved_bytes, 0);
        assert_eq!(committed_bytes(&mut setup, "t1").unwrap(), 11);

        // Also verify normal v2 finalization updates file_size, releases reservation, and clears staged cleanup;
        // and epoch fencing rejects v2 finalization while keeping staged cleanup intact.
        attachment(&mut setup, "att-ok", "c1", "t1");
        diesel::update(tenants::table.find("t1"))
            .set(tenants::storage_reserved_bytes.eq(28))
            .execute(&mut setup)
            .unwrap();
        let att_ok = Attachment::new(
            AttachmentId("att-ok".to_owned()),
            CipherId::from("c1".to_owned()),
            "f".to_owned(),
            100,
            None,
        )
        .with_tenant_id(Some("t1".to_owned()));
        let staged_ok = TenantPendingDeletion {
            id: "pd-v2-ok".to_owned(),
            tenant_id: "t1".to_owned(),
            user_uuid: Some(UserId::from("u1".to_owned())),
            storage_kind: "attachment".to_owned(),
            object_key: att_ok.get_file_path_in_cell(Some(REGION)).unwrap(),
            attempts: 0,
            last_error: Some(UPLOAD_IN_FLIGHT_MARKER.to_owned()),
            reserved_bytes: 0,
            created_at: naive(NOW),
        };
        diesel::insert_into(tenant_pending_deletions::table).values(&staged_ok).execute(&mut setup).unwrap();

        // Wrong epoch (fenced tenant) fails and preserves staged cleanup.
        assert!(
            Tenant::finalize_v2_attachment_upload_inner(
                &mut setup,
                "t1",
                &att_ok,
                128,
                28,
                Some(99),
                Some("pd-v2-ok"),
                NOW
            )
            .is_err()
        );
        assert!(tenant_pending_deletions::table.find("pd-v2-ok").first::<TenantPendingDeletion>(&mut setup).is_ok());

        // Matching epoch succeeds, updates file_size to 128, releases 28 reserved bytes, and clears pd-v2-ok.
        Tenant::finalize_v2_attachment_upload_inner(&mut setup, "t1", &att_ok, 128, 28, Some(1), Some("pd-v2-ok"), NOW)
            .unwrap();
        assert_eq!(attachments::table.find("att-ok").first::<Attachment>(&mut setup).unwrap().file_size, 128);
        assert_eq!(tenant(&mut setup, "t1").storage_reserved_bytes, 0);
        assert!(tenant_pending_deletions::table.find("pd-v2-ok").first::<TenantPendingDeletion>(&mut setup).is_err());
    }

    fn v2_att(aid: &str) -> Attachment {
        Attachment::new(AttachmentId(aid.to_owned()), CipherId::from("c1".to_owned()), "f".to_owned(), 100, None)
            .with_tenant_id(Some("t1".to_owned()))
    }

    /// Tenant t1 with one 100-byte attachment per id and a grant `headroom` bytes above committed.
    fn v2_setup(c: &mut DbConnInner, attachments: &[&str], headroom: i64) {
        active_tenant(c, "t1");
        user(c, "u1", "t1", "sub1");
        cipher(c, "c1", Some("u1"), None, "t1");
        for aid in attachments {
            attachment(c, aid, "c1", "t1");
        }
        let committed = committed_bytes(c, "t1").unwrap();
        diesel::update(tenants::table.find("t1"))
            .set((
                tenants::storage_ceiling_bytes.eq(committed + headroom),
                tenants::storage_grant_expires_at.eq(Some(NOW + 600)),
            ))
            .execute(c)
            .unwrap();
    }

    fn begin(c: &mut DbConnInner, aid: &str, size: i64) -> Result<V2UploadLease, Error> {
        Tenant::begin_v2_attachment_upload_inner(
            c,
            "t1",
            Some(UserId::from("u1".to_owned())),
            &v2_att(aid),
            size,
            900,
            &cells(),
            NOW,
        )
    }

    #[test]
    fn v2_uploads_to_one_attachment_are_serialized_and_sized_from_the_current_row() {
        let c = &mut test_sqlite_conn();
        v2_setup(c, &["att"], 2_000);

        let first = begin(c, "att", 1_100).unwrap();
        assert_eq!(first.reserved_bytes, 1_000);
        // A second upload while the first is in flight would be sized from the same stale row.
        assert!(begin(c, "att", 1_100).is_err());

        Tenant::finalize_v2_attachment_upload_inner(
            c,
            "t1",
            &v2_att("att"),
            1_100,
            first.reserved_bytes,
            Some(first.access_epoch),
            Some(&first.pending_cleanup_id),
            NOW,
        )
        .unwrap();
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 0);

        // The next upload's growth is measured against the stored 1_100 bytes, not the stale 100.
        let next = begin(c, "att", 1_200).unwrap();
        assert_eq!(next.reserved_bytes, 100);
    }

    #[test]
    fn v2_upload_admission_counts_other_in_flight_reservations() {
        let c = &mut test_sqlite_conn();
        v2_setup(c, &["a1", "a2"], 1_500);
        begin(c, "a1", 1_100).unwrap();
        // 1_000 already reserved; another 1_000 would pass the 1_500 headroom.
        assert!(begin(c, "a2", 1_100).is_err());
        assert!(
            committed_bytes(c, "t1").unwrap() + tenant(c, "t1").storage_reserved_bytes
                <= tenant(c, "t1").storage_ceiling_bytes
        );
    }

    #[test]
    fn v2_finalize_rejects_growth_its_reservation_does_not_cover() {
        let c = &mut test_sqlite_conn();
        v2_setup(c, &["att"], 2_000);
        let lease = begin(c, "att", 100).unwrap();
        assert_eq!(lease.reserved_bytes, 0);
        // The stored size changes after admission, so committing 100 bytes would be unreserved growth.
        diesel::update(attachments::table.find("att")).set(attachments::file_size.eq(50)).execute(c).unwrap();
        assert!(
            Tenant::finalize_v2_attachment_upload_inner(
                c,
                "t1",
                &v2_att("att"),
                100,
                lease.reserved_bytes,
                Some(lease.access_epoch),
                Some(&lease.pending_cleanup_id),
                NOW
            )
            .is_err()
        );
        assert_eq!(attachments::table.find("att").select(attachments::file_size).first::<i64>(c).unwrap(), 50);
    }

    #[test]
    fn abandoned_upload_returns_its_reservation_exactly_once() {
        let c = &mut test_sqlite_conn();
        v2_setup(c, &["crashed", "failed"], 5_000);
        diesel::update(tenants::table.find("t1")).set(tenants::storage_reserved_bytes.eq(500)).execute(c).unwrap();

        // Crash after admission: nothing releases on the request path.
        let crashed = begin(c, "crashed", 1_100).unwrap();
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 1_500);
        assert!(cleanup_pending(c, None, &cells(), NOW).unwrap().items.is_empty());
        let reclaim = cleanup_pending(c, None, &cells(), NOW + UPLOAD_STAGING_GRACE_SECS + 1).unwrap();
        assert_eq!(reclaim.items.len(), 1);
        let done = CompleteRequest {
            completed_ids: vec![crashed.pending_cleanup_id],
            failed: vec![],
        };
        cleanup_complete(c, &done, &cells(), NOW).unwrap();
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 500);

        // Failed finalization: the request path releases, and later reclaim must not release again.
        let failed = begin(c, "failed", 1_100).unwrap();
        c.transaction(|c| release_pending_reservations(c, &[failed.pending_cleanup_id.as_str()])).unwrap();
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 500);
        let done = CompleteRequest {
            completed_ids: vec![failed.pending_cleanup_id],
            failed: vec![],
        };
        cleanup_complete(c, &done, &cells(), NOW).unwrap();
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 500);
    }

    #[test]
    fn upload_handed_to_cleanup_cannot_commit_or_be_overwritten() {
        let c = &mut test_sqlite_conn();
        v2_setup(c, &["att"], 5_000);
        let late = NOW + UPLOAD_STAGING_GRACE_SECS + 1;

        // The upload outlives its grace and the worker picks up its cleanup row.
        let slow = begin(c, "att", 1_100).unwrap();
        let job = cleanup_pending(c, None, &cells(), late).unwrap();
        assert_eq!(job.items.len(), 1);

        // A retry would write the same object key the worker is about to delete.
        assert!(begin(c, "att", 1_100).is_err());
        // The slow upload must not commit a row pointing at an object being deleted.
        let fin = |c: &mut DbConnInner, lease: &V2UploadLease, now| {
            Tenant::finalize_v2_attachment_upload_inner(
                c,
                "t1",
                &v2_att("att"),
                1_100,
                lease.reserved_bytes,
                Some(lease.access_epoch),
                Some(&lease.pending_cleanup_id),
                now,
            )
        };
        assert!(fin(c, &slow, late).is_err());
        assert_eq!(attachments::table.find("att").select(attachments::file_size).first::<i64>(c).unwrap(), 100);

        // Once the worker reports the delete, the crashed upload's attachment row goes with its
        // object, so the key is never reused: a retry needs a new attachment.
        let done = CompleteRequest {
            completed_ids: vec![slow.pending_cleanup_id],
            failed: vec![],
        };
        cleanup_complete(c, &done, &cells(), late).unwrap();
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 0);
        assert_eq!(attachments::table.find("att").count().get_result::<i64>(c).unwrap(), 0);
        assert!(begin(c, "att", 1_100).is_err());
    }

    fn put(c: &mut DbConnInner, att: &Attachment) -> Result<(), Error> {
        Tenant::put_attachment_enforcing_grant_inner(c, "t1", att, 900, &cells(), NOW)
    }

    fn expire_grant(c: &mut DbConnInner) {
        diesel::update(tenants::table.find("t1"))
            .set(tenants::storage_grant_expires_at.eq(Some(NOW - 1)))
            .execute(c)
            .unwrap();
    }

    fn stored_name(c: &mut DbConnInner, aid: &str) -> String {
        attachments::table.find(aid).select(attachments::file_name).first(c).unwrap()
    }

    #[test]
    fn attachment_metadata_counts_toward_the_storage_grant() {
        let c = &mut test_sqlite_conn();
        v2_setup(c, &["att"], 50);
        // Fixture row: 100 payload bytes plus the 1-byte name "f".
        let before = committed_bytes(c, "t1").unwrap();

        // Creating: payload plus name plus key must fit the headroom.
        let mut new = v2_att("new");
        new.file_size = 0;
        new.file_name = "n".repeat(40);
        new.akey = Some("k".repeat(11));
        assert!(put(c, &new).is_err(), "51 metadata bytes exceed 50 bytes of headroom");
        new.akey = Some("k".repeat(10));
        put(c, &new).unwrap();
        assert_eq!(committed_bytes(c, "t1").unwrap(), before + 50);

        // Renaming with an expired grant: growth is refused and the stored record is untouched.
        expire_grant(c);
        let mut renamed = v2_att("att");
        renamed.file_name = "longer-name".to_owned();
        assert!(put(c, &renamed).is_err());
        assert_eq!(stored_name(c, "att"), "f");
        assert_eq!(committed_bytes(c, "t1").unwrap(), before + 50);

        // A rename that does not grow still works, and never rewrites the payload size.
        renamed.file_name = "g".to_owned();
        renamed.file_size = 999_999;
        put(c, &renamed).unwrap();
        assert_eq!(stored_name(c, "att"), "g");
        assert_eq!(attachments::table.find("att").select(attachments::file_size).first::<i64>(c).unwrap(), 100);

        // Oversized metadata is refused before any grant check.
        diesel::update(tenants::table.find("t1"))
            .set((
                tenants::storage_ceiling_bytes.eq(i64::MAX / 2),
                tenants::storage_grant_expires_at.eq(Some(NOW + 600)),
            ))
            .execute(c)
            .unwrap();
        let mut huge = v2_att("huge");
        huge.file_name = "n".repeat(crate::db::models::MAX_METADATA_LEN + 1);
        assert!(put(c, &huge).is_err());
        huge.file_name = "n".to_owned();
        huge.akey = Some("k".repeat(crate::db::models::MAX_METADATA_LEN + 1));
        assert!(put(c, &huge).is_err());
        assert_eq!(attachments::table.find("huge").count().get_result::<i64>(c).unwrap(), 0);

        // An attachment of another cipher cannot be rewritten through this path.
        let mut moved = v2_att("att");
        moved.cipher_uuid = CipherId::from("c2".to_owned());
        assert!(put(c, &moved).is_err());
    }

    #[test]
    fn legacy_upload_reserves_and_stages_in_one_transaction() {
        let c = &mut test_sqlite_conn();
        v2_setup(c, &[], 1_000);
        let begin_legacy = |c: &mut DbConnInner, att: &Attachment| {
            Tenant::begin_legacy_attachment_upload_inner(
                c,
                "t1",
                Some(UserId::from("u1".to_owned())),
                att,
                900,
                &cells(),
                NOW,
            )
        };
        let staged = |c: &mut DbConnInner| tenant_pending_deletions::table.count().get_result::<i64>(c).unwrap();

        // Refused admission leaves neither a reservation nor a cleanup row.
        let mut att = v2_att("legacy");
        att.file_size = 1_000;
        assert!(begin_legacy(c, &att).is_err(), "1,000 payload bytes plus the 1-byte name exceed the headroom");
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 0);
        assert_eq!(staged(c), 0);

        // Admission reserves payload plus metadata, and the staged row carries exactly that.
        att.file_size = 900;
        att.akey = Some("k".repeat(9));
        let lease = begin_legacy(c, &att).unwrap();
        assert_eq!(lease.reserved_bytes, 910);
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 910);
        let row_bytes: i64 = tenant_pending_deletions::table
            .find(&lease.pending_cleanup_id)
            .select(tenant_pending_deletions::reserved_bytes)
            .first(c)
            .unwrap();
        assert_eq!(row_bytes, 910);

        // A crash here is reclaimed through that row.
        let reclaim = cleanup_pending(c, None, &cells(), NOW + UPLOAD_STAGING_GRACE_SECS + 1).unwrap();
        assert_eq!(reclaim.items.len(), 1);
        let done = CompleteRequest {
            completed_ids: vec![lease.pending_cleanup_id],
            failed: vec![],
        };
        cleanup_complete(c, &done, &cells(), NOW).unwrap();
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 0);
    }

    #[test]
    fn crashed_v2_upload_loses_its_row_when_cleanup_reports() {
        let c = &mut test_sqlite_conn();
        v2_setup(c, &["done", "failed"], 5_000);
        let before = committed_bytes(c, "t1").unwrap();
        let late = NOW + UPLOAD_STAGING_GRACE_SECS + 1;

        // Both uploads crash after admission; the worker reclaims them after the grace.
        let done = begin(c, "done", 1_100).unwrap();
        let failed = begin(c, "failed", 1_100).unwrap();
        assert_eq!(cleanup_pending(c, None, &cells(), late).unwrap().items.len(), 2);
        let report = CompleteRequest {
            completed_ids: vec![done.pending_cleanup_id.clone()],
            failed: vec![FailedItem {
                id: failed.pending_cleanup_id.clone(),
                error: "storage unavailable".to_owned(),
            }],
        };
        cleanup_complete(c, &report, &cells(), late).unwrap();

        // Neither row advertises a file that is gone, nor keeps counting its declared payload.
        assert_eq!(attachments::table.count().get_result::<i64>(c).unwrap(), 0);
        assert_eq!(committed_bytes(c, "t1").unwrap(), before - 2 * 101);
        // The failed delete is retried, but no row is left for it to reconcile.
        assert_eq!(cleanup_pending(c, None, &cells(), late).unwrap().items.len(), 1);

        // A late write may land after the worker's delete, so its object is queued again; the
        // failed one is still pending, so it is left to that row. Neither can commit afterwards.
        let abandon = |c: &mut DbConnInner, l: &V2UploadLease, id: &str| {
            Tenant::abandon_upload_inner(c, "t1", &l.pending_cleanup_id, &v2_att(id), true, late).unwrap()
        };
        assert_eq!(abandon(c, &done, "done"), Abandoned::Requeued);
        assert_eq!(abandon(c, &failed, "failed"), Abandoned::LeftAlone);
        let key = v2_att("done").get_file_path_in_cell(Some(&tenant(c, "t1").home_region)).unwrap();
        let queued: Vec<String> =
            cleanup_pending(c, None, &cells(), late).unwrap().items.into_iter().map(|i| i.object_key).collect();
        assert!(queued.contains(&key), "{queued:?}");
        assert!(begin(c, "done", 1_100).is_err());
    }

    #[test]
    fn rotation_saves_cipher_and_attachment_keys_together() {
        use crate::db::models::Cipher;

        let c = &mut test_sqlite_conn();
        v2_setup(c, &["att"], 1);
        let stored = |c: &mut DbConnInner| {
            let k: Option<String> = ciphers::table.find("c1").select(ciphers::key).first(c).unwrap();
            let a: Option<String> = attachments::table.find("att").select(attachments::akey).first(c).unwrap();
            (k, a)
        };
        let before = stored(c);

        let mut rotated = ciphers::table.find("c1").first::<Cipher>(c).unwrap();
        rotated.key = Some("k".to_owned()); // 1 byte: fits the headroom alone
        let mut att = v2_att("att");
        att.akey = Some("new-attachment-key".to_owned());

        // The attachment key's growth exceeds the grant, so neither the cipher nor the key changes.
        assert!(Tenant::save_cipher_enforcing_grant_inner(c, "t1", &rotated, &[att], 900, &cells(), 10, NOW).is_err());
        assert_eq!(stored(c), before);

        // With room, both land together and the payload size is untouched.
        diesel::update(tenants::table.find("t1"))
            .set(tenants::storage_ceiling_bytes.eq(i64::MAX / 2))
            .execute(c)
            .unwrap();
        let mut att = v2_att("att");
        att.akey = Some("new-attachment-key".to_owned());
        att.file_size = 999_999;
        Tenant::save_cipher_enforcing_grant_inner(c, "t1", &rotated, &[att], 900, &cells(), 10, NOW).unwrap();
        assert_eq!(stored(c), (Some("k".to_owned()), Some("new-attachment-key".to_owned())));
        assert_eq!(attachments::table.find("att").select(attachments::file_size).first::<i64>(c).unwrap(), 100);

        // An attachment of another cipher is refused.
        let mut foreign = v2_att("att");
        foreign.cipher_uuid = CipherId::from("c2".to_owned());
        assert!(
            Tenant::save_cipher_enforcing_grant_inner(c, "t1", &rotated, &[foreign], 900, &cells(), 10, NOW).is_err()
        );
    }

    #[test]
    fn failing_upload_that_still_owns_its_row_hands_the_object_to_cleanup() {
        let c = &mut test_sqlite_conn();
        v2_setup(c, &["att"], 5_000);

        let lease = begin(c, "att", 1_100).unwrap();
        let abandon = |c: &mut DbConnInner| {
            Tenant::abandon_upload_inner(c, "t1", &lease.pending_cleanup_id, &v2_att("att"), true, NOW).unwrap()
        };
        assert_eq!(abandon(c), Abandoned::Owned);
        assert_eq!(attachments::table.find("att").count().get_result::<i64>(c).unwrap(), 0);
        assert_eq!(tenant(c, "t1").storage_reserved_bytes, 0);
        // Visible to the worker at once, not after the grace.
        assert_eq!(cleanup_pending(c, None, &cells(), NOW).unwrap().items.len(), 1);
        // A second abandon leaves the already queued row alone.
        assert_eq!(abandon(c), Abandoned::LeftAlone);
        assert_eq!(cleanup_pending(c, None, &cells(), NOW).unwrap().items.len(), 1);
    }

    #[test]
    fn deleting_an_attachment_queues_its_object_with_the_row_delete() {
        let c = &mut test_sqlite_conn();
        v2_setup(c, &["att"], 0);
        let key = v2_att("att").get_file_path_in_cell(Some(&tenant(c, "t1").home_region)).unwrap();

        Tenant::delete_attachment_queuing_cleanup_inner(c, "t1", &v2_att("att"), &key, NOW).unwrap();
        assert_eq!(attachments::table.find("att").count().get_result::<i64>(c).unwrap(), 0);
        let pending = cleanup_pending(c, None, &cells(), NOW).unwrap().items;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].object_key, key);

        // While the delete is queued, no upload may reuse the key.
        attachment(c, "att", "c1", "t1");
        assert!(begin(c, "att", 100).is_err());
    }
}
