use bigdecimal::{BigDecimal, ToPrimitive};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::EmptyResult,
    db::{
        DbConn, DbConnInner,
        schema::{
            attachments, ciphers, sends, tenant_erased_subjects, tenant_pending_deletions, tenant_recovery_bundles,
            tenants,
        },
    },
    error::MapResult,
    util::get_uuid,
};

use super::{Attachment, Cipher, OrganizationId, UserId};

pub const TENANT_STATUS_ACTIVE: &str = "active";

/// Strict zero-knowledge personal Recovery Kit (client-wrapped offline recovery key,
/// readable only by the owning user — no server escrow and no admin key recovery).
pub const RECOVERY_BUNDLE_KIT: &str = "personal_kit";

/// Maximum authority validity window (15 minutes per Design §11 P3).
pub const MAX_AUTHORITY_AGE_SECS: i64 = 900;

/// Allowed difference between a v2 attachment's declared and uploaded size.
const V2_SIZE_LEEWAY: i64 = 1024 * 1024;

/// Lease acquired atomically under the tenant lock before a hosted v2 attachment upload writes to
/// object storage: carries the fencing `access_epoch`, the `reserved_bytes` computed against the
/// locked current `attachments.file_size`, and the staged `pending_cleanup_id` acting as both
/// crash-recovery cleanup and cross-replica per-attachment upload serialization lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2UploadLease {
    pub access_epoch: i64,
    pub reserved_bytes: i64,
    pub pending_cleanup_id: String,
}

#[derive(Clone, Debug, Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = tenants)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(id))]
pub struct Tenant {
    pub id: String,
    pub status: String,
    pub home_region: String,
    pub app_enabled: bool,
    pub revision: i64,
    pub quotas_json: String,
    pub storage_pool_bytes: i64,
    pub storage_ceiling_bytes: i64,
    pub storage_reserved_bytes: i64,
    pub storage_grant_expires_at: Option<i64>,
    pub storage_org_used_bytes: i64,
    pub storage_over_since: Option<i64>,
    pub storage_report_seq: i64,
    pub storage_last_applied_seq: i64,
    pub storage_pending_seq: Option<i64>,
    pub storage_pending_used_bytes: Option<i64>,
    pub storage_seq_stale: bool,
    pub authority_refreshed_at: Option<i64>,
    pub access_epoch: i64,
    pub primary_org_uuid: Option<OrganizationId>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub deleted_at: Option<NaiveDateTime>,
    pub erased_at: Option<NaiveDateTime>,
}

#[derive(Clone, Debug, Identifiable, Queryable, Insertable)]
#[diesel(table_name = tenant_erased_subjects)]
#[diesel(primary_key(issuer, subject))]
pub struct TenantErasedSubject {
    pub issuer: String,
    pub subject: String,
    pub tenant_id: String,
    pub revision: i64,
    pub erased_at: NaiveDateTime,
}

#[derive(Clone, Debug, Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = tenant_pending_deletions)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(id))]
pub struct TenantPendingDeletion {
    pub id: String,
    pub tenant_id: String,
    pub user_uuid: Option<UserId>,
    pub storage_kind: String,
    pub object_key: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub created_at: NaiveDateTime,
    /// Upload bytes reserved for this staged object; returned to the tenant when the row is
    /// reclaimed so an abandoned upload cannot leak its reservation.
    pub reserved_bytes: i64,
}

#[derive(Clone, Debug, Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = tenant_recovery_bundles)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct TenantRecoveryBundle {
    pub uuid: String,
    pub tenant_id: String,
    pub user_uuid: UserId,
    pub bundle_type: String,
    pub version: i32,
    pub kdf_params_json: String,
    pub wrapped_user_key: String,
    pub wrapped_private_key: Option<String>,
    pub recovery_key_hint: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
}

impl Tenant {
    pub fn new(id: String, home_region: String) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            id,
            status: TENANT_STATUS_ACTIVE.to_owned(),
            home_region,
            app_enabled: false,
            revision: 0,
            quotas_json: "{}".to_owned(),
            storage_pool_bytes: 0,
            storage_ceiling_bytes: 0,
            storage_reserved_bytes: 0,
            storage_grant_expires_at: None,
            storage_org_used_bytes: 0,
            storage_over_since: None,
            storage_report_seq: 0,
            storage_last_applied_seq: 0,
            storage_pending_seq: None,
            storage_pending_used_bytes: None,
            storage_seq_stale: false,
            authority_refreshed_at: None,
            access_epoch: 1,
            primary_org_uuid: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
            erased_at: None,
        }
    }

    /// True if the tenant is active, enabled, and not deleted/erased.
    pub fn is_active(&self) -> bool {
        self.app_enabled && self.status == TENANT_STATUS_ACTIVE && self.deleted_at.is_none() && self.erased_at.is_none()
    }

    /// True if the tenant's cached KyIdentity authority record is within the bounded freshness cap.
    pub fn has_fresh_authority(&self, now_ts: i64, max_age_secs: i64) -> bool {
        let cap = max_age_secs.clamp(60, MAX_AUTHORITY_AGE_SECS);
        match self.authority_refreshed_at {
            Some(refreshed) => now_ts.saturating_sub(refreshed) <= cap,
            None => false,
        }
    }

    /// True if the tenant currently holds an unexpired, non-over-pool storage growth grant.
    /// Per SUITE-DIRECTORY.md & Design §4.3, `storage_pool_bytes` is NEVER a spendable grant.
    pub fn has_valid_storage_grant(&self, now_ts: i64) -> bool {
        if self.storage_over_since.is_some() {
            return false;
        }
        match self.storage_grant_expires_at {
            Some(exp) => now_ts < exp && self.storage_ceiling_bytes > 0,
            None => false,
        }
    }

    /// Returns true if a write adding `additional_bytes` is permitted under the current
    /// reserved storage growth grant. Writes adding 0 bytes (or deletes/shrinks) always pass.
    pub fn can_grow_storage(&self, committed_bytes: i64, additional_bytes: i64, now_ts: i64) -> bool {
        if additional_bytes <= 0 {
            return true;
        }
        if !self.has_valid_storage_grant(now_ts) {
            return false;
        }
        let projected =
            committed_bytes.max(0).saturating_add(self.storage_reserved_bytes.max(0)).saturating_add(additional_bytes);
        projected <= self.storage_ceiling_bytes
    }

    pub fn parsed_quotas(&self) -> Value {
        serde_json::from_str(&self.quotas_json).unwrap_or_else(|_| json!({}))
    }

    pub fn max_ciphers_quota(&self) -> Option<i64> {
        self.parsed_quotas().get("max_ciphers").and_then(Value::as_i64).filter(|v| *v > 0)
    }

    pub async fn find_by_id(id: &str, conn: &DbConn) -> Option<Self> {
        let id = id.to_owned();
        conn.run(move |conn| tenants::table.filter(tenants::id.eq(id)).first::<Self>(conn).ok()).await
    }

    pub async fn list_all(conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| tenants::table.load::<Self>(conn).unwrap_or_default()).await
    }

    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();
        let row = self.clone();
        db_run! { conn:
            mysql {
                diesel::insert_into(tenants::table)
                    .values(&row)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(&row)
                    .execute(conn)
                    .map_res("Error saving tenant")
            }
            postgresql, sqlite {
                diesel::insert_into(tenants::table)
                    .values(&row)
                    .on_conflict(tenants::id)
                    .do_update()
                    .set(&row)
                    .execute(conn)
                    .map_res("Error saving tenant")
            }
        }
    }

    pub async fn cipher_count(tenant_id: &str, conn: &DbConn) -> i64 {
        let tid = tenant_id.to_owned();
        conn.run(move |conn| {
            ciphers::table
                .filter(ciphers::tenant_id.eq(tid))
                .filter(ciphers::deleted_at.is_null())
                .count()
                .first::<i64>(conn)
                .unwrap_or(0)
        })
        .await
    }

    /// Total committed storage bytes retained for this tenant (see [`committed_bytes`]).
    pub async fn committed_storage_bytes(tenant_id: &str, conn: &DbConn) -> i64 {
        let tid = tenant_id.to_owned();
        conn.run(move |conn| committed_bytes(conn, &tid).unwrap_or(0)).await
    }

    /// Transactionally locks the tenant, verifies active status and `expected_epoch`, saves `att`,
    /// releases `release` reserved bytes, and clears `clear_pending_id` (plus any stale upload
    /// cleanup rows for the same object key) from `tenant_pending_deletions`. If any check or the
    /// insert fails (for example on epoch fencing or a cipher foreign-key violation), the
    /// transaction rolls back so the pending cleanup row remains intact.
    pub fn save_attachment_releasing_inner(
        conn: &mut DbConnInner,
        tid: &str,
        att: &Attachment,
        release: i64,
        expected_epoch: Option<i64>,
        clear_pending_id: Option<&str>,
        now_ts: i64,
    ) -> EmptyResult {
        let release = release.max(0);
        conn.transaction::<(), crate::Error, _>(|conn| {
            let Some(tenant) = lock_tenant(conn, tid).map_res("Error locking tenant")? else {
                err_code!("Tenant not found", 403);
            };
            if !tenant.is_active()
                || tenant.authority_refreshed_at.is_none()
                || expected_epoch.is_some_and(|ep| tenant.access_epoch != ep)
            {
                err_code!("Tenant access was revoked during upload", 403);
            }
            if let Some(pid) = clear_pending_id {
                take_upload_row(conn, tid, pid, now_ts)?;
            }
            match conn {
                #[cfg(mysql)]
                DbConnInner::Mysql(c) => diesel::insert_into(attachments::table)
                    .values(att)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(att)
                    .execute(c),
                #[cfg(postgresql)]
                DbConnInner::Postgresql(c) => diesel::insert_into(attachments::table)
                    .values(att)
                    .on_conflict(attachments::id)
                    .do_update()
                    .set(att)
                    .execute(c),
                #[cfg(sqlite)]
                DbConnInner::Sqlite(c) => diesel::insert_into(attachments::table)
                    .values(att)
                    .on_conflict(attachments::id)
                    .do_update()
                    .set(att)
                    .execute(c),
            }
            .map(|_| ())
            .map_res("Error saving attachment")?;
            diesel::update(tenants::table.find(tid))
                .set(tenants::storage_reserved_bytes.eq(tenant.storage_reserved_bytes.saturating_sub(release).max(0)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error releasing storage reservation")?;
            Ok(())
        })
    }

    /// Saves an attachment row, verifies `expected_epoch`, releases `release` reserved bytes, and
    /// clears `clear_pending_id` in one transaction under the tenant lock, so a concurrent
    /// admission never counts those bytes twice and a failed save never drops its cleanup job.
    pub async fn save_attachment_releasing(
        tenant_id: &str,
        att: &Attachment,
        release: i64,
        expected_epoch: Option<i64>,
        clear_pending_id: Option<&str>,
        conn: &DbConn,
    ) -> EmptyResult {
        let tid = tenant_id.to_owned();
        let pid = clear_pending_id.map(str::to_owned);
        conn.run(move |conn| {
            if !is_postgresql(conn) {
                err_code!("Hosted multi-tenant storage requires PostgreSQL", 503);
            }
            Self::save_attachment_releasing_inner(
                conn,
                &tid,
                att,
                release,
                expected_epoch,
                pid.as_deref(),
                Utc::now().timestamp(),
            )
        })
        .await
    }

    /// Transactionally begins a hosted v2 attachment upload under the tenant lock:
    /// 1. Validates active status, served cell, and authority freshness.
    /// 2. Serializes concurrent uploads for the same attachment across all replicas by rejecting
    ///    while any cleanup row exists for its object key (in flight, or held by the worker).
    /// 3. Reads the locked current `attachments.file_size`, checks v2 leeway (1 MiB), computes
    ///    positive growth delta against that locked row, verifies and reserves storage bytes, and
    ///    stages the durable `upload_in_flight` cleanup row in the same transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_v2_attachment_upload_inner(
        conn: &mut DbConnInner,
        tid: &str,
        user_uuid: Option<UserId>,
        att: &Attachment,
        file_size: i64,
        max_authority_age_secs: i64,
        served_cells: &[String],
        now_ts: i64,
    ) -> Result<V2UploadLease, crate::Error> {
        if file_size < 0 {
            err_code!("Attachment size can't be negative", 400);
        }
        conn.transaction::<V2UploadLease, crate::Error, _>(|conn| {
            let Some(tenant) = lock_tenant(conn, tid).map_res("Error locking tenant")? else {
                err_code!("Tenant not found", 403);
            };
            validate_tenant_growth_tx(&tenant, served_cells, now_ts, max_authority_age_secs)?;
            let object_key = att.get_file_path_in_cell(Some(&tenant.home_region))?;

            let in_flight: bool = diesel::select(diesel::dsl::exists(
                tenant_pending_deletions::table
                    .filter(tenant_pending_deletions::tenant_id.eq(tid))
                    .filter(tenant_pending_deletions::storage_kind.eq("attachment"))
                    .filter(tenant_pending_deletions::object_key.eq(&object_key)),
            ))
            .get_result(conn)
            .map_res("Error checking in-flight attachment upload")?;
            if in_flight {
                // A pending row is an upload in flight or a delete the cleanup worker may hold;
                // a new write to the same key could be removed by that delete.
                err_code!("An upload or cleanup for this attachment is still pending", 409);
            }

            let Some(current_size): Option<i64> = attachments::table
                .filter(attachments::id.eq(&att.id))
                .filter(attachments::cipher_uuid.eq(&att.cipher_uuid))
                .filter(attachments::tenant_id.eq(tid))
                .select(attachments::file_size)
                .first(conn)
                .optional()
                .map_res("Error loading attachment")?
            else {
                err_code!("Attachment no longer exists", 404);
            };

            let Some(max_size) = current_size.checked_add(V2_SIZE_LEEWAY) else {
                err_code!("Invalid attachment size max", 400);
            };
            let Some(min_size) = current_size.checked_sub(V2_SIZE_LEEWAY) else {
                err_code!("Invalid attachment size min", 400);
            };
            if !(min_size <= file_size && file_size <= max_size) {
                err_code!(
                    format!("Attachment size mismatch (expected within [{min_size}, {max_size}], got {file_size})"),
                    400
                );
            }

            let delta_bytes = file_size.saturating_sub(current_size).max(0);
            reserve_and_stage_upload_tx(conn, &tenant, user_uuid, object_key, delta_bytes, now_ts)
        })
    }

    /// Begins a hosted v2 attachment upload atomically under the PostgreSQL tenant lock.
    pub async fn begin_v2_attachment_upload(
        tenant_id: &str,
        user_uuid: Option<UserId>,
        att: &Attachment,
        file_size: i64,
        max_authority_age_secs: i64,
        served_cells: &[String],
        conn: &DbConn,
    ) -> Result<V2UploadLease, crate::Error> {
        let tid = tenant_id.to_owned();
        let cells = served_cells.to_vec();
        conn.run(move |conn| {
            if !is_postgresql(conn) {
                err_code!("Hosted multi-tenant storage requires PostgreSQL", 503);
            }
            Self::begin_v2_attachment_upload_inner(
                conn,
                &tid,
                user_uuid,
                att,
                file_size,
                max_authority_age_secs,
                &cells,
                Utc::now().timestamp(),
            )
        })
        .await
    }

    /// Transactionally finalizes a v2 attachment upload under the tenant lock: verifies tenant
    /// active status, authority, and `expected_epoch`, loads the locked current attachment row,
    /// verifies that the upload's reserved bytes (`release`) still cover the actual growth
    /// (`file_size - current_size`), updates `file_size`, releases `release` reserved bytes, and
    /// clears `clear_pending_id` (plus any stale upload cleanup rows for the same object key).
    /// If the tenant was fenced, the attachment was deleted, or the attachment shrank concurrently
    /// so `release` no longer covers growth, the transaction rolls back and `clear_pending_id`
    /// stays queued.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_v2_attachment_upload_inner(
        conn: &mut DbConnInner,
        tid: &str,
        att: &Attachment,
        file_size: i64,
        release: i64,
        expected_epoch: Option<i64>,
        clear_pending_id: Option<&str>,
        now_ts: i64,
    ) -> EmptyResult {
        let release = release.max(0);
        conn.transaction::<(), crate::Error, _>(|conn| {
            let Some(tenant) = lock_tenant(conn, tid).map_res("Error locking tenant")? else {
                err_code!("Tenant not found", 403);
            };
            if !tenant.is_active()
                || tenant.authority_refreshed_at.is_none()
                || expected_epoch.is_some_and(|ep| tenant.access_epoch != ep)
            {
                err_code!("Tenant access was revoked during upload", 403);
            }
            if let Some(pid) = clear_pending_id {
                take_upload_row(conn, tid, pid, now_ts)?;
            }
            let Some(current_size): Option<i64> = attachments::table
                .filter(attachments::id.eq(&att.id))
                .filter(attachments::cipher_uuid.eq(&att.cipher_uuid))
                .filter(attachments::tenant_id.eq(tid))
                .select(attachments::file_size)
                .first(conn)
                .optional()
                .map_res("Error loading attachment")?
            else {
                err_code!("Attachment no longer exists", 404);
            };
            let actual_growth = file_size.saturating_sub(current_size).max(0);
            if actual_growth > release {
                err_code!("Attachment size changed during upload; storage reservation no longer covers growth", 409);
            }
            let updated: usize = diesel::update(
                attachments::table
                    .filter(attachments::id.eq(&att.id))
                    .filter(attachments::cipher_uuid.eq(&att.cipher_uuid))
                    .filter(attachments::tenant_id.eq(tid)),
            )
            .set(attachments::file_size.eq(file_size))
            .execute(conn)
            .map_res("Error finalizing attachment")?;
            if updated == 0 {
                err_code!("Attachment no longer exists", 404);
            }
            diesel::update(tenants::table.find(tid))
                .set(tenants::storage_reserved_bytes.eq(tenant.storage_reserved_bytes.saturating_sub(release).max(0)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error releasing storage reservation")?;
            Ok(())
        })
    }

    /// Finalizes a v2 attachment upload atomically under the PostgreSQL tenant lock.
    pub async fn finalize_v2_attachment_upload(
        tenant_id: &str,
        att: &Attachment,
        file_size: i64,
        release: i64,
        expected_epoch: Option<i64>,
        clear_pending_id: Option<&str>,
        conn: &DbConn,
    ) -> EmptyResult {
        let tid = tenant_id.to_owned();
        let pid = clear_pending_id.map(str::to_owned);
        conn.run(move |conn| {
            if !is_postgresql(conn) {
                err_code!("Hosted multi-tenant storage requires PostgreSQL", 503);
            }
            Self::finalize_v2_attachment_upload_inner(
                conn,
                &tid,
                att,
                file_size,
                release,
                expected_epoch,
                pid.as_deref(),
                Utc::now().timestamp(),
            )
        })
        .await
    }

    /// Begins a hosted legacy attachment upload: in one transaction under the tenant lock, checks
    /// the tenant, reserves the payload and metadata bytes, and stages the in-flight cleanup row,
    /// so a crash at any point leaves a row through which the reservation is reclaimed.
    pub fn begin_legacy_attachment_upload_inner(
        conn: &mut DbConnInner,
        tid: &str,
        user_uuid: Option<UserId>,
        att: &Attachment,
        max_authority_age_secs: i64,
        served_cells: &[String],
        now_ts: i64,
    ) -> Result<V2UploadLease, crate::Error> {
        if att.file_size < 0 {
            err_code!("Attachment size can't be negative", 400);
        }
        att.check_metadata_limits()?;
        conn.transaction::<V2UploadLease, crate::Error, _>(|conn| {
            let Some(tenant) = lock_tenant(conn, tid).map_res("Error locking tenant")? else {
                err_code!("Tenant not found", 403);
            };
            validate_tenant_growth_tx(&tenant, served_cells, now_ts, max_authority_age_secs)?;
            let object_key = att.get_file_path_in_cell(Some(&tenant.home_region))?;
            let bytes = att.file_size.saturating_add(att.metadata_bytes());
            reserve_and_stage_upload_tx(conn, &tenant, user_uuid, object_key, bytes, now_ts)
        })
    }

    /// Begins a hosted legacy attachment upload under the PostgreSQL tenant lock.
    pub async fn begin_legacy_attachment_upload(
        tenant_id: &str,
        user_uuid: Option<UserId>,
        att: &Attachment,
        max_authority_age_secs: i64,
        served_cells: &[String],
        conn: &DbConn,
    ) -> Result<V2UploadLease, crate::Error> {
        let tid = tenant_id.to_owned();
        let cells = served_cells.to_vec();
        conn.run(move |conn| {
            if !is_postgresql(conn) {
                err_code!("Hosted multi-tenant storage requires PostgreSQL", 503);
            }
            Self::begin_legacy_attachment_upload_inner(
                conn,
                &tid,
                user_uuid,
                att,
                max_authority_age_secs,
                &cells,
                Utc::now().timestamp(),
            )
        })
        .await
    }

    /// Creates an attachment row, or updates an existing row's file name and key, under the tenant
    /// lock. Growth (the new row's size plus metadata, or the metadata delta of an update) is
    /// checked against the storage grant in the same transaction; a rejected write changes nothing.
    pub fn put_attachment_enforcing_grant_inner(
        conn: &mut DbConnInner,
        tid: &str,
        att: &Attachment,
        max_authority_age_secs: i64,
        served_cells: &[String],
        now_ts: i64,
    ) -> EmptyResult {
        conn.transaction::<(), crate::Error, _>(|conn| {
            let Some(tenant) = lock_tenant(conn, tid).map_res("Error locking tenant")? else {
                err_code!("Tenant not found", 403);
            };
            validate_tenant_growth_tx(&tenant, served_cells, now_ts, max_authority_age_secs)?;
            let (growth, exists) = attachment_growth_tx(conn, tid, att)?;
            if growth > 0 {
                let committed = committed_bytes(conn, tid).map_res("Error checking tenant storage")?;
                if !tenant.can_grow_storage(committed, growth, now_ts) {
                    err_code!("Organization storage quota exceeded or grant expired", 403);
                }
            }
            write_attachment_tx(conn, att, exists)
        })
    }

    /// Creates or renames an attachment under the PostgreSQL tenant lock, enforcing the grant.
    pub async fn put_attachment_enforcing_grant(
        tenant_id: &str,
        att: &Attachment,
        max_authority_age_secs: i64,
        served_cells: &[String],
        conn: &DbConn,
    ) -> EmptyResult {
        let tid = tenant_id.to_owned();
        let cells = served_cells.to_vec();
        conn.run(move |conn| {
            if !is_postgresql(conn) {
                err_code!("Hosted multi-tenant storage requires PostgreSQL", 503);
            }
            Self::put_attachment_enforcing_grant_inner(
                conn,
                &tid,
                att,
                max_authority_age_secs,
                &cells,
                Utc::now().timestamp(),
            )
        })
        .await
    }

    /// Abandons a failed upload, but only while it still owns its in-flight cleanup row: returns
    /// the row's reservation, hands the object to the cleanup worker, and deletes `v2_att`'s row.
    /// Once the worker has taken the row over, a retry may own the object key and attachment row,
    /// so nothing is touched. Returns whether the upload was still the owner.
    pub fn abandon_upload_inner(
        conn: &mut DbConnInner,
        tid: &str,
        pending_id: &str,
        v2_att: Option<&Attachment>,
    ) -> QueryResult<bool> {
        conn.transaction(|conn| {
            lock_tenant(conn, tid)?;
            let owned = diesel::update(
                tenant_pending_deletions::table
                    .filter(tenant_pending_deletions::id.eq(pending_id))
                    .filter(tenant_pending_deletions::tenant_id.eq(tid))
                    .filter(
                        tenant_pending_deletions::last_error.eq(Some(crate::tenancy::ops::UPLOAD_IN_FLIGHT_MARKER)),
                    ),
            )
            .set(tenant_pending_deletions::last_error.eq(None::<String>))
            .execute(conn)?
                > 0;
            if !owned {
                return Ok(false);
            }
            release_pending_reservations(conn, &[pending_id])?;
            if let Some(att) = v2_att {
                diesel::delete(
                    attachments::table
                        .filter(attachments::id.eq(&att.id))
                        .filter(attachments::cipher_uuid.eq(&att.cipher_uuid))
                        .filter(attachments::tenant_id.eq(tid)),
                )
                .execute(conn)?;
            }
            Ok(true)
        })
    }

    /// Abandons a failed hosted upload; see [`Self::abandon_upload_inner`].
    pub async fn abandon_upload(tenant_id: &str, pending_id: &str, v2_att: Option<&Attachment>, conn: &DbConn) {
        let tid = tenant_id.to_owned();
        let pid = pending_id.to_owned();
        match conn.run(move |conn| Self::abandon_upload_inner(conn, &tid, &pid, v2_att)).await {
            Ok(true) => {}
            Ok(false) => warn!("Upload {pending_id} was already handed to cleanup; leaving its object alone"),
            Err(e) => error!("Failed to abandon upload {pending_id}: {e}"),
        }
    }

    /// Deletes an attachment row and queues its object for the cleanup worker in one transaction.
    pub fn delete_attachment_queuing_cleanup_inner(
        conn: &mut DbConnInner,
        tid: &str,
        att: &Attachment,
        object_key: &str,
        now_ts: i64,
    ) -> EmptyResult {
        let row = TenantPendingDeletion {
            id: get_uuid(),
            tenant_id: tid.to_owned(),
            user_uuid: None,
            storage_kind: "attachment".to_owned(),
            object_key: object_key.to_owned(),
            attempts: 0,
            last_error: None,
            reserved_bytes: 0,
            created_at: naive_ts(now_ts),
        };
        conn.transaction::<(), crate::Error, _>(|conn| {
            diesel::insert_into(tenant_pending_deletions::table)
                .values(&row)
                .execute(conn)
                .map(drop)
                .map_res("Error queuing attachment cleanup")?;
            diesel::delete(attachments::table.filter(attachments::id.eq(&att.id)))
                .execute(conn)
                .map(drop)
                .map_res("Error deleting attachment")?;
            Ok(())
        })
    }

    /// Deletes a hosted attachment row; the cleanup worker removes the object.
    pub async fn delete_attachment_queuing_cleanup(
        tenant_id: &str,
        att: &Attachment,
        object_key: &str,
        conn: &DbConn,
    ) -> EmptyResult {
        let tid = tenant_id.to_owned();
        let key = object_key.to_owned();
        conn.run(move |conn| {
            Self::delete_attachment_queuing_cleanup_inner(conn, &tid, att, &key, Utc::now().timestamp())
        })
        .await
    }

    /// Transactionally locks the tenant, validates active status/region/authority freshness,
    /// enforces active cipher count quota on create/restore, checks positive byte deltas against
    /// the tenant's active storage growth grant, and persists `cipher` together with the file name
    /// and key changes in `attachments` (key rotation), so a rotation lands whole or not at all. Rejects growth without
    /// modifying stored data if the grant is expired or exhausted.
    #[allow(clippy::too_many_arguments)]
    pub fn save_cipher_enforcing_grant_inner(
        conn: &mut DbConnInner,
        tid: &str,
        cipher: &Cipher,
        attachments: &[Attachment],
        max_authority_age_secs: i64,
        served_cells: &[String],
        default_max_ciphers: i64,
        now_ts: i64,
    ) -> EmptyResult {
        if cipher.tenant_id.as_deref() != Some(tid) {
            err_code!("Cross-tenant cipher write denied", 403);
        }
        conn.transaction::<(), crate::Error, _>(|conn| {
            let Some(tenant) = lock_tenant(conn, tid).map_res("Error locking tenant")? else {
                err_code!("Tenant not found", 403);
            };
            validate_tenant_growth_tx(&tenant, served_cells, now_ts, max_authority_age_secs)?;

            let existing: Option<Cipher> = ciphers::table
                .find(&cipher.uuid)
                .first::<Cipher>(conn)
                .optional()
                .map_res("Error loading existing cipher")?;
            if let Some(ref old) = existing
                && old.tenant_id.as_deref() != Some(tid)
            {
                err_code!("Cross-tenant cipher write denied", 403);
            }

            let activates_cipher =
                cipher.deleted_at.is_none() && existing.as_ref().is_none_or(|old| old.deleted_at.is_some());
            if activates_cipher {
                let max_ciphers = tenant.max_ciphers_quota().unwrap_or(default_max_ciphers);
                if max_ciphers > 0 {
                    let active_count: i64 = ciphers::table
                        .filter(ciphers::tenant_id.eq(tid))
                        .filter(ciphers::deleted_at.is_null())
                        .count()
                        .first::<i64>(conn)
                        .map_res("Error counting tenant ciphers")?;
                    if active_count >= max_ciphers {
                        err_code!(format!("Organization cipher quota exceeded (limit: {max_ciphers})"), 403);
                    }
                }
            }

            let old_bytes = existing.as_ref().map_or(0, Cipher::storage_bytes);
            let mut delta_bytes = cipher.storage_bytes().saturating_sub(old_bytes);
            let mut att_exists = Vec::with_capacity(attachments.len());
            for att in attachments {
                if att.cipher_uuid != cipher.uuid {
                    err_code!("Attachment is not owned by the cipher", 400);
                }
                let (growth, exists) = attachment_growth_tx(conn, tid, att)?;
                delta_bytes = delta_bytes.saturating_add(growth);
                att_exists.push(exists);
            }
            if delta_bytes > 0 {
                let committed = committed_bytes(conn, tid).map_res("Error checking tenant storage")?;
                if !tenant.can_grow_storage(committed, delta_bytes, now_ts) {
                    err_code!("Organization storage quota exceeded or grant expired", 403);
                }
            }

            match conn {
                #[cfg(mysql)]
                DbConnInner::Mysql(c) => diesel::insert_into(ciphers::table)
                    .values(cipher)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(cipher)
                    .execute(c),
                #[cfg(postgresql)]
                DbConnInner::Postgresql(c) => diesel::insert_into(ciphers::table)
                    .values(cipher)
                    .on_conflict(ciphers::uuid)
                    .do_update()
                    .set(cipher)
                    .execute(c),
                #[cfg(sqlite)]
                DbConnInner::Sqlite(c) => diesel::insert_into(ciphers::table)
                    .values(cipher)
                    .on_conflict(ciphers::uuid)
                    .do_update()
                    .set(cipher)
                    .execute(c),
            }
            .map(|_| ())
            .map_res("Error saving cipher")?;
            for (att, exists) in attachments.iter().zip(att_exists) {
                write_attachment_tx(conn, att, exists)?;
            }
            Ok(())
        })
    }

    /// Persists a cipher in hosted multi-tenant mode under the PostgreSQL tenant lock, enforcing
    /// both active cipher quota and storage grant admission atomically.
    pub async fn save_cipher_enforcing_grant(
        tenant_id: &str,
        cipher: &Cipher,
        attachments: &[Attachment],
        max_authority_age_secs: i64,
        served_cells: &[String],
        default_max_ciphers: i64,
        conn: &DbConn,
    ) -> EmptyResult {
        let tid = tenant_id.to_owned();
        let cells = served_cells.to_vec();
        conn.run(move |conn| {
            if !is_postgresql(conn) {
                err_code!("Hosted multi-tenant storage requires PostgreSQL", 503);
            }
            Self::save_cipher_enforcing_grant_inner(
                conn,
                &tid,
                cipher,
                attachments,
                max_authority_age_secs,
                &cells,
                default_max_ciphers,
                Utc::now().timestamp(),
            )
        })
        .await
    }
}

fn sum_to_i64(sum: Option<BigDecimal>) -> i64 {
    match sum.map(|v| v.to_i64()) {
        Some(Some(v)) => v.max(0),
        Some(None) => i64::MAX,
        None => 0,
    }
}

pub fn is_postgresql(conn: &DbConnInner) -> bool {
    match conn {
        #[cfg(postgresql)]
        DbConnInner::Postgresql(_) => true,
        #[allow(unreachable_patterns, reason = "only reachable when another backend is compiled in")]
        _ => false,
    }
}

/// Loads a tenant row, holding a `FOR UPDATE` row lock on PostgreSQL (the hosted backend).
/// Call inside a transaction.
/// Deletes the upload's own cleanup row, which must still be in flight and inside the grace
/// window. Past either, the cleanup worker may hold the row and delete the object, so the
/// upload must not commit a row pointing at it.
fn take_upload_row(conn: &mut DbConnInner, tid: &str, pid: &str, now_ts: i64) -> EmptyResult {
    let cutoff = chrono::DateTime::from_timestamp(now_ts - crate::tenancy::ops::UPLOAD_STAGING_GRACE_SECS, 0)
        .map_or_else(|| Utc::now().naive_utc(), |dt| dt.naive_utc());
    let taken: usize = diesel::delete(
        tenant_pending_deletions::table
            .filter(tenant_pending_deletions::id.eq(pid))
            .filter(tenant_pending_deletions::tenant_id.eq(tid))
            .filter(tenant_pending_deletions::last_error.eq(Some(crate::tenancy::ops::UPLOAD_IN_FLIGHT_MARKER)))
            .filter(tenant_pending_deletions::created_at.gt(cutoff)),
    )
    .execute(conn)
    .map_res("Error claiming staged upload")?;
    if taken == 0 {
        err_code!("Upload took too long and was handed to cleanup; retry it", 409);
    }
    Ok(())
}

/// Validates an attachment write and returns its byte growth and whether the row exists: the
/// new row's payload plus metadata, or an existing row's metadata delta. Call under the tenant lock.
fn attachment_growth_tx(conn: &mut DbConnInner, tid: &str, att: &Attachment) -> Result<(i64, bool), crate::Error> {
    if att.tenant_id.as_deref() != Some(tid) {
        err_code!("Cross-tenant attachment write denied", 403);
    }
    if att.file_size < 0 {
        err_code!("Attachment size can't be negative", 400);
    }
    att.check_metadata_limits()?;
    let existing: Option<Attachment> =
        attachments::table.find(&att.id).first::<Attachment>(conn).optional().map_res("Error loading attachment")?;
    match existing {
        Some(old) if old.tenant_id.as_deref() != Some(tid) || old.cipher_uuid != att.cipher_uuid => {
            err_code!("Cross-tenant attachment write denied", 403);
        }
        Some(old) => Ok((att.metadata_bytes().saturating_sub(old.metadata_bytes()), true)),
        None => Ok((att.file_size.saturating_add(att.metadata_bytes()), false)),
    }
}

/// Inserts `att`, or updates only its file name and key: file_size belongs to the upload path.
fn write_attachment_tx(conn: &mut DbConnInner, att: &Attachment, exists: bool) -> EmptyResult {
    if exists {
        diesel::update(attachments::table.find(&att.id))
            .set((attachments::file_name.eq(&att.file_name), attachments::akey.eq(&att.akey)))
            .execute(conn)
            .map(drop)
            .map_res("Error saving attachment")
    } else {
        diesel::insert_into(attachments::table).values(att).execute(conn).map(drop).map_res("Error saving attachment")
    }
}

fn naive_ts(now_ts: i64) -> NaiveDateTime {
    chrono::DateTime::from_timestamp(now_ts, 0).map_or_else(|| Utc::now().naive_utc(), |dt| dt.naive_utc())
}

/// Reserves `bytes` against the locked `tenant`'s grant and stages the upload's in-flight cleanup
/// row carrying that reservation. Call inside the transaction that locked `tenant`.
fn reserve_and_stage_upload_tx(
    conn: &mut DbConnInner,
    tenant: &Tenant,
    user_uuid: Option<UserId>,
    object_key: String,
    bytes: i64,
    now_ts: i64,
) -> Result<V2UploadLease, crate::Error> {
    let bytes = bytes.max(0);
    let now_dt = naive_ts(now_ts);
    if bytes > 0 {
        let committed = committed_bytes(conn, &tenant.id).map_res("Error checking tenant storage")?;
        if !tenant.can_grow_storage(committed, bytes, now_ts) {
            err_code!("Organization storage quota exceeded or grant expired", 403);
        }
        diesel::update(tenants::table.find(&tenant.id))
            .set((
                tenants::storage_reserved_bytes.eq(tenant.storage_reserved_bytes.max(0).saturating_add(bytes)),
                tenants::updated_at.eq(now_dt),
            ))
            .execute(conn)
            .map(drop)
            .map_res("Error reserving tenant storage bytes")?;
    }
    let staged = TenantPendingDeletion {
        id: get_uuid(),
        tenant_id: tenant.id.clone(),
        user_uuid,
        storage_kind: "attachment".to_owned(),
        object_key,
        attempts: 0,
        last_error: Some(crate::tenancy::ops::UPLOAD_IN_FLIGHT_MARKER.to_owned()),
        reserved_bytes: bytes,
        created_at: now_dt,
    };
    diesel::insert_into(tenant_pending_deletions::table)
        .values(&staged)
        .execute(conn)
        .map(drop)
        .map_res("Error staging attachment cleanup")?;
    Ok(V2UploadLease {
        access_epoch: tenant.access_epoch,
        reserved_bytes: bytes,
        pending_cleanup_id: staged.id,
    })
}

/// Returns the bytes reserved by cleanup rows `ids` to their tenants and zeroes the rows, so a
/// reclaimed or abandoned upload releases its reservation exactly once. Tenants are locked
/// before the rows are read, so concurrent callers cannot both release the same row.
/// Call inside a transaction.
pub fn release_pending_reservations(conn: &mut DbConnInner, ids: &[&str]) -> QueryResult<()> {
    let mut tenant_ids: Vec<String> = tenant_pending_deletions::table
        .filter(tenant_pending_deletions::id.eq_any(ids))
        .select(tenant_pending_deletions::tenant_id)
        .distinct()
        .load(conn)?;
    // Sorted for a stable lock order across concurrent callers.
    tenant_ids.sort();
    for tid in tenant_ids {
        let Some(t) = lock_tenant(conn, &tid)? else {
            continue;
        };
        let bytes: Vec<i64> = tenant_pending_deletions::table
            .filter(tenant_pending_deletions::id.eq_any(ids))
            .filter(tenant_pending_deletions::tenant_id.eq(&tid))
            .filter(tenant_pending_deletions::reserved_bytes.gt(0))
            .select(tenant_pending_deletions::reserved_bytes)
            .load(conn)?;
        let total = bytes.into_iter().fold(0i64, i64::saturating_add);
        if total > 0 {
            diesel::update(tenants::table.find(&tid))
                .set(tenants::storage_reserved_bytes.eq(t.storage_reserved_bytes.saturating_sub(total).max(0)))
                .execute(conn)?;
        }
        diesel::update(
            tenant_pending_deletions::table
                .filter(tenant_pending_deletions::id.eq_any(ids))
                .filter(tenant_pending_deletions::tenant_id.eq(&tid)),
        )
        .set(tenant_pending_deletions::reserved_bytes.eq(0))
        .execute(conn)?;
    }
    Ok(())
}

pub fn lock_tenant(conn: &mut DbConnInner, id: &str) -> QueryResult<Option<Tenant>> {
    match conn {
        #[cfg(postgresql)]
        DbConnInner::Postgresql(pg) => tenants::table.find(id).for_update().first::<Tenant>(pg).optional(),
        #[allow(unreachable_patterns, reason = "only reachable when another backend is compiled in")]
        _ => tenants::table.find(id).first::<Tenant>(conn).optional(),
    }
}

/// `SUM` of the byte lengths of `cols`, as a non-null BIGINT, in the active backend's dialect.
fn octet_sum_sql(conn: &DbConnInner, cols: &[&str]) -> String {
    let len = |col: &str| match conn {
        #[cfg(postgresql)]
        DbConnInner::Postgresql(_) => format!("COALESCE(OCTET_LENGTH({col}), 0)"),
        #[cfg(mysql)]
        DbConnInner::Mysql(_) => format!("COALESCE(LENGTH({col}), 0)"),
        #[cfg(sqlite)]
        DbConnInner::Sqlite(_) => format!("COALESCE(LENGTH(CAST({col} AS BLOB)), 0)"),
    };
    let sum = format!("COALESCE(SUM({}), 0)", cols.iter().map(|c| len(c)).collect::<Vec<_>>().join(" + "));
    match conn {
        #[cfg(mysql)]
        DbConnInner::Mysql(_) => format!("CAST({sum} AS SIGNED)"),
        #[allow(unreachable_patterns, reason = "only reachable when another backend is compiled in")]
        _ => sum,
    }
}

/// Committed tenant storage per Design §11 P3: attachment payloads with their encrypted file name
/// and key, file Send payloads, encrypted cipher data (trash included) and active recovery-kit
/// envelopes. Pending upload reservations live in `tenants.storage_reserved_bytes` and are added
/// by callers.
pub fn committed_bytes(conn: &mut DbConnInner, tenant_id: &str) -> QueryResult<i64> {
    use diesel::{dsl::sql, sql_types::BigInt};

    let att: Option<BigDecimal> = attachments::table
        .filter(attachments::tenant_id.eq(tenant_id))
        .select(diesel::dsl::sum(attachments::file_size))
        .first(conn)?;

    let att_meta_sql = octet_sum_sql(conn, &["file_name", "akey"]);
    let att_meta: i64 = attachments::table
        .filter(attachments::tenant_id.eq(tenant_id))
        .select(sql::<BigInt>(&att_meta_sql))
        .first(conn)?;

    let cipher_sql = octet_sum_sql(conn, &["name", "notes", "fields", "data", "password_history", "key"]);
    let records: i64 =
        ciphers::table.filter(ciphers::tenant_id.eq(tenant_id)).select(sql::<BigInt>(&cipher_sql)).first(conn)?;

    let bundle_sql = octet_sum_sql(conn, &["wrapped_user_key", "wrapped_private_key"]);
    let bundles: i64 = tenant_recovery_bundles::table
        .filter(tenant_recovery_bundles::tenant_id.eq(tenant_id))
        .select(sql::<BigInt>(&bundle_sql))
        .first(conn)?;

    let send_data: Vec<String> = sends::table
        .filter(sends::tenant_id.eq(tenant_id))
        .filter(sends::atype.eq(1))
        .select(sends::data)
        .load(conn)?;
    let send_bytes = send_data
        .iter()
        .filter_map(|d| serde_json::from_str::<Value>(d).ok())
        .filter_map(|v| v.get("size").or_else(|| v.get("Size")).and_then(Value::as_i64))
        .fold(0i64, |acc, sz| acc.saturating_add(sz.max(0)));

    Ok(sum_to_i64(att)
        .saturating_add(att_meta.max(0))
        .saturating_add(records.max(0))
        .saturating_add(bundles.max(0))
        .saturating_add(send_bytes))
}

fn validate_tenant_growth_tx(
    tenant: &Tenant,
    served_cells: &[String],
    now_ts: i64,
    max_authority_age_secs: i64,
) -> EmptyResult {
    crate::tenancy::check_tenant_active_for_cells(tenant, served_cells, now_ts, max_authority_age_secs)
}

impl TenantErasedSubject {
    pub async fn record(issuer: &str, subject: &str, tenant_id: &str, revision: i64, conn: &DbConn) -> EmptyResult {
        let row = Self {
            issuer: crate::tenancy::canonical_issuer(issuer).to_owned(),
            subject: subject.trim().to_owned(),
            tenant_id: tenant_id.to_owned(),
            revision,
            erased_at: Utc::now().naive_utc(),
        };
        db_run! { conn:
            mysql {
                diesel::insert_or_ignore_into(tenant_erased_subjects::table)
                    .values(&row)
                    .execute(conn)
                    .map_res("Error recording erased subject tombstone")
            }
            postgresql, sqlite {
                diesel::insert_into(tenant_erased_subjects::table)
                    .values(&row)
                    .on_conflict((tenant_erased_subjects::issuer, tenant_erased_subjects::subject))
                    .do_nothing()
                    .execute(conn)
                    .map_res("Error recording erased subject tombstone")
            }
        }
    }

    pub async fn is_erased(issuer: &str, subject: &str, conn: &DbConn) -> bool {
        let iss = crate::tenancy::canonical_issuer(issuer).to_owned();
        let sub = subject.trim().to_owned();
        conn.run(move |conn| {
            tenant_erased_subjects::table
                .filter(tenant_erased_subjects::issuer.eq(iss))
                .filter(tenant_erased_subjects::subject.eq(sub))
                .count()
                .first::<i64>(conn)
                .unwrap_or(0)
                > 0
        })
        .await
    }
}

impl TenantRecoveryBundle {
    pub fn new_personal_kit(
        tenant_id: String,
        user_uuid: UserId,
        version: i32,
        kdf_params_json: String,
        wrapped_user_key: String,
        wrapped_private_key: Option<String>,
        recovery_key_hint: Option<String>,
    ) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            uuid: get_uuid(),
            tenant_id,
            user_uuid,
            bundle_type: RECOVERY_BUNDLE_KIT.to_owned(),
            version,
            kdf_params_json,
            wrapped_user_key,
            wrapped_private_key,
            recovery_key_hint,
            created_at: now,
            updated_at: now,
            revoked_at: None,
        }
    }

    pub fn byte_len(&self) -> i64 {
        let total = self.wrapped_user_key.len().saturating_add(self.wrapped_private_key.as_deref().map_or(0, str::len));
        i64::try_from(total).unwrap_or(i64::MAX)
    }

    pub async fn find_active_personal_kit(tenant_id: &str, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        let tid = tenant_id.to_owned();
        let uid = user_uuid.clone();
        conn.run(move |conn| {
            tenant_recovery_bundles::table
                .filter(tenant_recovery_bundles::tenant_id.eq(tid))
                .filter(tenant_recovery_bundles::user_uuid.eq(uid))
                .filter(tenant_recovery_bundles::bundle_type.eq(RECOVERY_BUNDLE_KIT))
                .filter(tenant_recovery_bundles::revoked_at.is_null())
                .order(tenant_recovery_bundles::updated_at.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// Transactionally enforces storage admission (when `check_grant` is `Some`), deletes any
    /// prior personal kit rows for this user so superseded ciphertext is never retained
    /// unaccounted, and inserts `row`.
    pub fn upsert_personal_kit_inner(
        conn: &mut DbConnInner,
        row: &Self,
        check_grant: Option<(&[String], i64)>,
        now: i64,
    ) -> EmptyResult {
        use diesel::{dsl::sql, sql_types::BigInt};

        conn.transaction::<_, crate::Error, _>(|conn| {
            if let Some((served_cells, max_authority_age_secs)) = check_grant {
                let Some(tenant) = lock_tenant(conn, &row.tenant_id)? else {
                    err_code!("Tenant not found", 403);
                };
                validate_tenant_growth_tx(&tenant, served_cells, now, max_authority_age_secs)?;

                let bundle_sql = octet_sum_sql(conn, &["wrapped_user_key", "wrapped_private_key"]);
                let existing_bytes: i64 = tenant_recovery_bundles::table
                    .filter(tenant_recovery_bundles::tenant_id.eq(&row.tenant_id))
                    .filter(tenant_recovery_bundles::user_uuid.eq(&row.user_uuid))
                    .filter(tenant_recovery_bundles::bundle_type.eq(RECOVERY_BUNDLE_KIT))
                    .select(sql::<BigInt>(&bundle_sql))
                    .first::<i64>(conn)
                    .map_res("Error measuring existing recovery bundle")?
                    .max(0);
                let delta = row.byte_len().saturating_sub(existing_bytes).max(0);
                if delta > 0 {
                    let committed = committed_bytes(conn, &row.tenant_id).map_res("Error checking tenant storage")?;
                    if !tenant.can_grow_storage(committed, delta, now) {
                        err_code!("Organization storage quota exceeded or grant expired", 403);
                    }
                }
            }

            diesel::delete(
                tenant_recovery_bundles::table
                    .filter(tenant_recovery_bundles::tenant_id.eq(&row.tenant_id))
                    .filter(tenant_recovery_bundles::user_uuid.eq(&row.user_uuid))
                    .filter(tenant_recovery_bundles::bundle_type.eq(RECOVERY_BUNDLE_KIT)),
            )
            .execute(conn)
            .map(drop)
            .map_res("Error replacing previous recovery bundle")?;

            diesel::insert_into(tenant_recovery_bundles::table)
                .values(row)
                .execute(conn)
                .map(drop)
                .map_res("Error inserting recovery bundle")?;

            Ok(())
        })
    }

    /// Atomically replaces any prior personal kit for this user (single-tenant mode).
    pub async fn upsert_personal_kit(&self, conn: &DbConn) -> EmptyResult {
        let row = self.clone();
        conn.run(move |conn| Self::upsert_personal_kit_inner(conn, &row, None, Utc::now().timestamp())).await
    }

    /// Atomically checks tenant storage grant admission under the tenant lock and replaces any
    /// prior personal kit for this user (hosted multi-tenant mode).
    pub async fn upsert_personal_kit_enforcing_grant(
        &self,
        served_cells: &[String],
        max_authority_age_secs: i64,
        conn: &DbConn,
    ) -> EmptyResult {
        let row = self.clone();
        let cells = served_cells.to_vec();
        conn.run(move |conn| {
            if !is_postgresql(conn) {
                err_code!("Hosted multi-tenant storage requires PostgreSQL", 503);
            }
            Self::upsert_personal_kit_inner(conn, &row, Some((&cells, max_authority_age_secs)), Utc::now().timestamp())
        })
        .await
    }

    /// Deletes the user's personal recovery kit rows so revoked ciphertext is not retained.
    pub async fn revoke_personal_kit(tenant_id: &str, user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        let tid = tenant_id.to_owned();
        let uid = user_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(
                tenant_recovery_bundles::table
                    .filter(tenant_recovery_bundles::tenant_id.eq(tid))
                    .filter(tenant_recovery_bundles::user_uuid.eq(uid))
                    .filter(tenant_recovery_bundles::bundle_type.eq(RECOVERY_BUNDLE_KIT)),
            )
            .execute(conn)
            .map_res("Error revoking recovery bundle")
        })
        .await
    }
}
