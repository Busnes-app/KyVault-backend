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
            lock_tenant,
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
    tenancy::{canonical_issuer, format_oidc_identifier},
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

fn check_id(field: &str, value: &str, max: usize) -> OpResult<()> {
    if value.trim().is_empty() || value.len() > max {
        return Err(bad_request(&format!("Invalid {field}")));
    }
    Ok(())
}

/// Object key relative to the attachments root, identical to `Attachment::get_file_path`.
fn attachment_key(tenant_id: Option<&str>, cipher_uuid: &str, att_id: &str) -> String {
    match tenant_id {
        Some(tid) => format!("tenants/{tid}/attachments/{cipher_uuid}/{att_id}"),
        None => format!("{cipher_uuid}/{att_id}"),
    }
}

/// Object key relative to the sends root, identical to `Send::get_file_path`.
fn send_key(tenant_id: Option<&str>, send_uuid: &str, file_id: &str) -> String {
    match tenant_id {
        Some(tid) => format!("tenants/{tid}/sends/{send_uuid}/{file_id}"),
        None => format!("{send_uuid}/{file_id}"),
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
    home_region: &str,
    now: i64,
) -> OpResult<(ReconcileResponse, Kicks)> {
    if req.orgs.len() > MAX_BATCH {
        return Err(bad_request("Too many orgs"));
    }
    let mut quotas = Vec::with_capacity(req.orgs.len());
    for org in &req.orgs {
        check_id("org id", &org.id, MAX_ID_LEN)?;
        if !ORG_STATUSES.contains(&org.status.as_str()) {
            return Err(bad_request("Invalid org status"));
        }
        if org.home_region.len() > MAX_ID_LEN {
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
            if !home_region.is_empty() && !org.home_region.is_empty() && org.home_region != home_region {
                continue;
            }
            let existing = lock_tenant(conn, &org.id)?;
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
            let was_active = !created && t.is_active();

            if !org.home_region.is_empty() {
                t.home_region.clone_from(&org.home_region);
            }
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
            if non_active && (was_active || created) {
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
            let live = tenants::table.filter(tenants::status.ne_all(TOMBSTONED));
            let set = tenants::authority_refreshed_at.eq(Some(now));
            if home_region.is_empty() {
                diesel::update(live).set(set).execute(conn)?;
            } else {
                diesel::update(live.filter(tenants::home_region.eq(home_region).or(tenants::home_region.eq(""))))
                    .set(set)
                    .execute(conn)?;
            }
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

pub fn logout_user(conn: &mut DbConnInner, req: &LogoutRequest, now: i64) -> OpResult<(LogoutResponse, Kicks)> {
    check_subject(&req.issuer, &req.subject)?;
    conn.transaction(|conn| {
        let mut kicks = Kicks::default();
        let found = find_sso_user(conn, &req.issuer, &req.subject, req.tenant_id.as_deref())?;
        if let Some((uid, _)) = &found {
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

pub fn sync_user(conn: &mut DbConnInner, req: &SyncRequest, now: i64) -> OpResult<(UserStatusResponse, Kicks)> {
    if !["user.created", "user.updated", "user.deleted"].contains(&req.event_type.as_str()) {
        return Err(bad_request("Invalid event_type"));
    }
    check_subject(&req.issuer, &req.subject)?;
    if req.display_name.as_ref().is_some_and(|n| n.chars().count() > MAX_NAME_LEN) {
        return Err(bad_request("display_name too long"));
    }
    let now_dt = naive(now);
    conn.transaction(|conn| {
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
        let Some((uid, user_tenant)) = find_sso_user(conn, &req.issuer, &req.subject, req.tenant_id.as_deref())? else {
            return Ok((
                UserStatusResponse {
                    status: "not_found",
                    user_uuid: None,
                },
                kicks,
            ));
        };

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
            let tenant_active = match user_tenant.as_deref() {
                Some(tid) => lock_tenant(conn, tid)?.is_some_and(|t| t.is_active()),
                None => false,
            };
            if tenant_active {
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

pub fn erase_user(conn: &mut DbConnInner, req: &EraseRequest, now: i64) -> OpResult<(EraseResponse, Kicks)> {
    check_subject(&req.issuer, &req.subject)?;
    if let Some(tid) = req.tenant_id.as_deref().filter(|t| !t.is_empty()) {
        check_id("tenant_id", tid, MAX_ID_LEN)?;
    }
    let now_dt = naive(now);
    conn.transaction(|conn| {
        let mut kicks = Kicks::default();
        let req_tid = req.tenant_id.as_deref().filter(|t| !t.is_empty());
        let found = find_sso_user(conn, &req.issuer, &req.subject, req_tid)?;
        let user_tid = found.as_ref().and_then(|(_, t)| t.clone());
        let stone_tid = req_tid.map(str::to_owned).or_else(|| user_tid.clone()).unwrap_or_default();
        record_tombstone(conn, &tombstone(&req.issuer, &req.subject, &stone_tid, req.revision, now_dt))?;

        let mut queued = 0;
        if let Some((uid, _)) = &found {
            queued = erase_personal_data(conn, uid, user_tid.as_deref(), &stone_tid, now_dt)?;
            kicks.users.push(UserId::from(uid.clone()));
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
        let key = attachment_key(tid.as_deref().or(user_tid), &cipher, &id);
        rows.push(pending(pending_tid, Some(uid), KIND_ATTACHMENT, key, now));
    }
    for (send, data, tid) in file_sends {
        if let Some(file_id) = send_file_id(&data) {
            let key = send_key(tid.as_deref().or(user_tid), &send, &file_id);
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

fn has_tenant_rows(conn: &mut DbConnInner, tid: &str) -> QueryResult<bool> {
    let n = users::table.filter(users::tenant_id.eq(tid)).count().get_result::<i64>(conn)?
        + organizations::table.filter(organizations::tenant_id.eq(tid)).count().get_result::<i64>(conn)?
        + ciphers::table.filter(ciphers::tenant_id.eq(tid)).count().get_result::<i64>(conn)?
        + attachments::table.filter(attachments::tenant_id.eq(tid)).count().get_result::<i64>(conn)?
        + sends::table.filter(sends::tenant_id.eq(tid)).count().get_result::<i64>(conn)?;
    Ok(n > 0)
}

pub fn purge_begin(
    conn: &mut DbConnInner,
    tenant_id: &str,
    sso_authority: &str,
    now: i64,
) -> OpResult<(PurgeResponse, Kicks)> {
    check_id("tenant_id", tenant_id, MAX_ID_LEN)?;
    let now_dt = naive(now);
    conn.transaction(|conn| {
        let mut kicks = Kicks::default();
        let existing = lock_tenant(conn, tenant_id)?;
        let mut t = if let Some(t) = existing {
            t
        } else {
            let mut t = Tenant::new(tenant_id.to_owned(), String::new());
            t.created_at = now_dt;
            t.updated_at = now_dt;
            if !has_tenant_rows(conn, tenant_id)? {
                STATUS_DELETED.clone_into(&mut t.status);
                t.deleted_at = Some(now_dt);
                t.erased_at = Some(now_dt);
                diesel::insert_into(tenants::table).values(&t).execute(conn)?;
                return Ok((
                    PurgeResponse {
                        status: STATUS_DELETED,
                        pending_deletions: 0,
                    },
                    kicks,
                ));
            }
            // Orphaned rows without a tenant record still get purged.
            diesel::insert_into(tenants::table).values(&t).execute(conn)?;
            t
        };
        if t.status == STATUS_DELETED && t.erased_at.is_some() && pending_count(conn, tenant_id)? == 0 {
            return Ok((
                PurgeResponse {
                    status: STATUS_DELETED,
                    pending_deletions: 0,
                },
                kicks,
            ));
        }

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

        purge_tenant_rows(conn, tenant_id, sso_authority, now_dt)?;
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
fn purge_tenant_rows(conn: &mut DbConnInner, tid: &str, sso_authority: &str, now: NaiveDateTime) -> QueryResult<()> {
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
            attachment_key(Some(att_tid.as_deref().unwrap_or(tid)), &cipher, &id),
            now,
        ));
    }
    for (send, data, send_tid) in file_sends {
        if let Some(file_id) = send_file_id(&data) {
            rows.push(pending(
                tid,
                None,
                KIND_SEND,
                send_key(Some(send_tid.as_deref().unwrap_or(tid)), &send, &file_id),
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
        rows.push(pending(tid, None, KIND_TENANT_PREFIX, format!("tenants/{tid}/"), now));
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

#[derive(Debug, Serialize)]
pub struct PendingResponse {
    pub items: Vec<PendingItem>,
}

pub fn cleanup_pending(conn: &mut DbConnInner, limit: Option<i64>) -> OpResult<PendingResponse> {
    let limit = limit.unwrap_or(100).clamp(1, MAX_BATCH_SQL);
    let items = tenant_pending_deletions::table
        .order((tenant_pending_deletions::created_at.asc(), tenant_pending_deletions::id.asc()))
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

pub fn cleanup_complete(conn: &mut DbConnInner, req: &CompleteRequest, now: i64) -> OpResult<CompleteResponse> {
    if req.completed_ids.len() + req.failed.len() > MAX_BATCH {
        return Err(bad_request("Too many cleanup results"));
    }
    for id in req.completed_ids.iter().chain(req.failed.iter().map(|f| &f.id)) {
        check_id("id", id, MAX_ID_LEN)?;
    }
    conn.transaction(|conn| {
        let mut resp = CompleteResponse::default();
        let mut affected: Vec<String> = tenant_pending_deletions::table
            .filter(tenant_pending_deletions::id.eq_any(&req.completed_ids))
            .select(tenant_pending_deletions::tenant_id)
            .distinct()
            .load(conn)?;
        affected.sort();
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
            if (t.status == STATUS_PURGE_PENDING || t.status == STATUS_ERASING) && pending_count(conn, &tid)? == 0 {
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

pub fn storage_prepare(conn: &mut DbConnInner, req: &PrepareRequest, home_region: &str) -> OpResult<PrepareResponse> {
    let limit = usize::try_from(req.limit).unwrap_or(1).clamp(1, MAX_BATCH);
    let want_default = req.want_bytes_default.max(0);

    // Soonest-expiring (or missing) grants first so a capped batch rotates through tenants.
    let base = tenants::table
        .filter(tenants::status.ne_all(TOMBSTONED))
        .filter(tenants::storage_seq_stale.eq(false))
        .order((
            tenants::storage_grant_expires_at.is_not_null().asc(),
            tenants::storage_grant_expires_at.asc(),
            tenants::id.asc(),
        ))
        .select(tenants::id);
    let ids: Vec<String> = if home_region.is_empty() {
        base.load(conn)?
    } else {
        base.filter(tenants::home_region.eq(home_region).or(tenants::home_region.eq(""))).load(conn)?
    };

    let mut reports = Vec::new();
    for id in ids {
        if reports.len() >= limit {
            break;
        }
        let report = conn.transaction::<_, Error, _>(|conn| {
            let Some(t) = lock_tenant(conn, &id)? else {
                return Ok(None);
            };
            if is_tombstoned(&t.status) || t.storage_seq_stale {
                return Ok(None);
            }
            let want = if t.is_active() && t.storage_over_since.is_none() {
                want_default
            } else {
                0
            };
            if let (Some(seq), Some(used)) = (t.storage_pending_seq, t.storage_pending_used_bytes) {
                return Ok(Some(StorageReport {
                    org_id: t.id,
                    used_bytes: used,
                    seq,
                    want_bytes: want,
                }));
            }
            let needs = t.is_active()
                || t.storage_ceiling_bytes > 0
                || t.storage_grant_expires_at.is_some()
                || t.storage_last_applied_seq == 0;
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

pub fn storage_apply(conn: &mut DbConnInner, req: &ApplyRequest, now: i64) -> OpResult<ApplyResponse> {
    if req.results.len() > MAX_BATCH {
        return Err(bad_request("Too many results"));
    }
    for r in &req.results {
        check_id("org_id", &r.org_id, MAX_ID_LEN)?;
        if !["ok", "stale", "unknown_org"].contains(&r.result.as_str()) {
            return Err(bad_request("Invalid result"));
        }
    }
    // A skewed worker clock can never stretch a grant past now + TTL.
    let sent_at = req.sent_at.min(now);
    let mut resp = ApplyResponse::default();
    for r in &req.results {
        let applied = conn.transaction::<_, Error, _>(|conn| {
            let Some(t) = lock_tenant(conn, &r.org_id)? else {
                return Ok(false);
            };
            if is_tombstoned(&t.status) {
                return Ok(false);
            }
            let row = tenants::table.find(&r.org_id);
            match r.result.as_str() {
                "ok" => {
                    let out_of_order = r.seq <= 0
                        || r.seq > t.storage_report_seq
                        || r.seq < t.storage_last_applied_seq
                        || t.storage_pending_seq.is_some_and(|p| r.seq < p);
                    if out_of_order {
                        return Ok(false);
                    }
                    // A report sent before a fence can be answered after it: keep the
                    // bookkeeping, never reinstall a grant on a non-active tenant.
                    let (ceiling, expires) = if t.is_active() {
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

pub fn storage_repair_seq(conn: &mut DbConnInner, req: &RepairSeqRequest) -> OpResult<RepairSeqResponse> {
    check_id("org_id", &req.org_id, MAX_ID_LEN)?;
    conn.transaction(|conn| {
        let Some(t) = lock_tenant(conn, &req.org_id)? else {
            return Err(Error::new_msg("Tenant not found").with_code(404));
        };
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
        models::{Attachment, AttachmentId, CipherId},
        test_sqlite_conn,
    };

    const NOW: i64 = 1_750_000_000;
    const ISS: &str = "https://id.busnes.app";
    const REGION: &str = "us-east-1";

    fn exec(c: &mut DbConnInner, sql: &str) {
        diesel::sql_query(sql).execute(c).unwrap_or_else(|e| panic!("{sql}: {e}"));
    }

    fn tenant(c: &mut DbConnInner, id: &str) -> Tenant {
        lock_tenant(c, id).unwrap().unwrap_or_else(|| panic!("tenant {id} missing"))
    }

    fn active_tenant(c: &mut DbConnInner, id: &str) {
        let mut t = Tenant::new(id.to_owned(), REGION.to_owned());
        t.app_enabled = true;
        t.authority_refreshed_at = Some(NOW);
        diesel::insert_into(tenants::table).values(&t).execute(c).unwrap();
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
            REGION,
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
        assert_eq!(attachment_key(Some("t1"), "c1", "att"), att.get_file_path());
        assert_eq!(send_key(Some("t1"), "s1", "f1"), "tenants/t1/sends/s1/f1");
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

        // Other region skipped; new non-active tenant fenced.
        let mut far = snap("t2", "active", true, 1);
        far.home_region = "eu-west-1".to_owned();
        let r = reconcile(c, vec![far, snap("t3", "active", false, 1)], false, NOW);
        assert_eq!(r.applied, 1);
        assert_eq!(r.fenced_tenant_ids, vec!["t3"]);
        assert!(lock_tenant(c, "t2").unwrap().is_none());

        // Deleted: purge_pending, never back to active.
        let r = reconcile(c, vec![snap("t1", "deleted", false, 4)], false, NOW);
        assert_eq!(r.purge_required_tenant_ids, vec!["t1"]);
        assert_eq!(tenant(c, "t1").status, STATUS_PURGE_PENDING);
        let r = reconcile(c, vec![snap("t1", "active", true, 9)], false, NOW);
        assert_eq!((r.applied, r.purge_required_tenant_ids), (0, vec!["t1".to_owned()]));
        assert_eq!(tenant(c, "t1").status, STATUS_PURGE_PENDING);
    }

    #[test]
    fn reconcile_touch_all_refreshes_live_home_tenants_only() {
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
        for orgs in [
            vec![snap("t", "bogus", true, 1)],
            vec![snap("", "active", true, 1)],
            vec![bad_quotas],
            (0..=MAX_BATCH).map(|i| snap(&i.to_string(), "active", true, 1)).collect(),
        ] {
            let req = ReconcileRequest {
                orgs,
                touch_all_active: false,
            };
            assert!(reconcile_orgs(c, &req, REGION, NOW).is_err());
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
        user(c, "u1", "t1", "sub1");
        let req = |subject: &str, tenant_id: Option<&str>| LogoutRequest {
            issuer: format!("{ISS}/"),
            subject: subject.to_owned(),
            tenant_id: tenant_id.map(str::to_owned),
        };

        let (r, _) = logout_user(c, &req("sub1", Some("t2")), NOW).unwrap();
        assert!(!r.found);
        let (r, _) = logout_user(c, &req("sub", None), NOW).unwrap();
        assert!(!r.found);
        assert_eq!(stamp(c, "u1"), "stamp-u1");

        let (r, kicks) = logout_user(c, &req("sub1", Some("t1")), NOW).unwrap();
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

        assert!(sync_user(c, &req("user.bogus", "sub1", true), NOW).is_err());
        assert_eq!(sync_user(c, &req("user.updated", "nobody", true), NOW).unwrap().0.status, "not_found");

        let (r, kicks) = sync_user(c, &req("user.deleted", "sub1", true), NOW).unwrap();
        assert_eq!(r.status, "ok");
        assert_eq!(kicks.users.len(), 1);
        assert!(!enabled(c));
        assert_ne!(stamp(c, "u1"), "stamp-u1");

        sync_user(c, &req("user.updated", "sub1", true), NOW).unwrap();
        assert!(enabled(c));
        let name: String = users::table.find("u1").select(users::name).first(c).unwrap();
        assert_eq!(name, "Alice");

        // Inactive tenant: never re-enabled.
        sync_user(c, &req("user.updated", "sub1", false), NOW).unwrap();
        diesel::update(tenants::table.find("t1")).set(tenants::status.eq("suspended")).execute(c).unwrap();
        sync_user(c, &req("user.updated", "sub1", true), NOW).unwrap();
        assert!(!enabled(c));

        record_tombstone(c, &tombstone(ISS, "sub1", "t1", 1, naive(NOW))).unwrap();
        assert_eq!(sync_user(c, &req("user.created", "sub1", true), NOW).unwrap().0.status, "erased_tombstone");
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
        let (r, kicks) = erase_user(c, &req, NOW).unwrap();
        assert!(r.user_existed && r.tombstone_recorded);
        assert_eq!(r.pending_deletions_queued, 2);
        assert_eq!(kicks.users.len(), 1);

        let mut keys: Vec<String> =
            tenant_pending_deletions::table.select(tenant_pending_deletions::object_key).load(c).unwrap();
        keys.sort();
        assert_eq!(keys, vec!["tenants/t1/attachments/pc/pa", "tenants/t1/sends/s1/file1"]);

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
        let (r, _) = erase_user(c, &req, NOW).unwrap();
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

        let (r, kicks) = purge_begin(c, "ta", ISS, NOW).unwrap();
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
                ("attachment".to_owned(), "tenants/ta/attachments/oc-ua/att-ua".to_owned()),
                ("send".to_owned(), "tenants/ta/sends/s-ua/file1".to_owned()),
                ("tenant_prefix".to_owned(), "tenants/ta/".to_owned()),
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
        assert_eq!(purge_begin(c, "ta", ISS, NOW).unwrap().0.pending_deletions, 3);

        let items = cleanup_pending(c, Some(2)).unwrap().items;
        assert_eq!(items.len(), 2);
        let all: Vec<String> = cleanup_pending(c, None).unwrap().items.into_iter().map(|i| i.id).collect();
        let r = cleanup_complete(
            c,
            &CompleteRequest {
                completed_ids: all[..2].to_vec(),
                failed: vec![FailedItem {
                    id: all[2].clone(),
                    error: "x".repeat(900),
                }],
            },
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
            NOW + 5,
        )
        .unwrap();
        assert_eq!(r.finalized_tenant_ids, vec!["ta"]);
        let t = tenant(c, "ta");
        assert_eq!((t.status.as_str(), t.erased_at), (STATUS_DELETED, Some(naive(NOW + 5))));

        let r = purge_begin(c, "ta", ISS, NOW).unwrap().0;
        assert_eq!((r.status, r.pending_deletions), (STATUS_DELETED, 0));

        // Unknown tenant: bare tombstone, nothing queued.
        let r = purge_begin(c, "never-seen", ISS, NOW).unwrap().0;
        assert_eq!((r.status, r.pending_deletions), (STATUS_DELETED, 0));
        assert_eq!(tenant(c, "never-seen").status, STATUS_DELETED);

        assert!(
            cleanup_complete(
                c,
                &CompleteRequest {
                    completed_ids: (0..=MAX_BATCH).map(|i| i.to_string()).collect(),
                    failed: vec![],
                },
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
        attachment(c, "pa", "pc", "t1"); // 100 bytes
        diesel::update(tenants::table.find("t1")).set(tenants::storage_reserved_bytes.eq(5)).execute(c).unwrap();
        let prep = |c: &mut DbConnInner| {
            storage_prepare(
                c,
                &PrepareRequest {
                    want_bytes_default: 1000,
                    limit: 500,
                },
                REGION,
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
                        seq,
                        ceiling_bytes: 5000,
                        ttl_seconds: 3600,
                        pool_bytes: 9000,
                        org_used_bytes: 115,
                        over_since: None,
                    }],
                },
                NOW,
            )
            .unwrap()
        };
        let first = StorageReport {
            org_id: "t1".to_owned(),
            used_bytes: 115,
            seq: 1,
            want_bytes: 1000,
        };
        assert_eq!(prep(c), vec![first]);

        // Unapplied report replays the exact seq and bytes even after usage changed.
        attachment(c, "pb", "pc", "t1");
        assert_eq!(prep(c)[0].seq, 1);
        assert_eq!(prep(c)[0].used_bytes, 115);

        // Future-dated sent_at is clamped to now; TTL capped at 900 s.
        assert_eq!(apply(c, "ok", 1, NOW + 10_000).applied, 1);
        let t = tenant(c, "t1");
        assert_eq!(t.storage_grant_expires_at, Some(NOW + MAX_GRANT_TTL_SECS));
        assert_eq!((t.storage_ceiling_bytes, t.storage_last_applied_seq, t.storage_pending_seq), (5000, 1, None));

        let next = prep(c);
        assert_eq!((next[0].seq, next[0].used_bytes), (2, 215));
        // Out-of-order and never-issued sequences are ignored.
        assert_eq!(apply(c, "ok", 1, NOW).applied, 0);
        assert_eq!(apply(c, "ok", 99, NOW).applied, 0);
        assert_eq!(tenant(c, "t1").storage_pending_seq, Some(2));

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
            )
        };
        assert!(repair(c, 2).is_err());
        assert!(repair(c, 0).is_err());
        let r = repair(c, 42).unwrap();
        assert_eq!((r.storage_report_seq, r.storage_seq_stale), (41, false));
        assert_eq!(prep(c)[0].seq, 42);

        assert_eq!(apply(c, "unknown_org", 0, NOW).applied, 1);
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
        assert!(
            storage_repair_seq(
                c,
                &RepairSeqRequest {
                    org_id: "nope".to_owned(),
                    next_seq: 1
                }
            )
            .is_err()
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
}
