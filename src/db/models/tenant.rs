use bigdecimal::{BigDecimal, ToPrimitive};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        schema::{
            attachments, ciphers, sends, tenant_erased_subjects, tenant_pending_deletions, tenant_recovery_bundles,
            tenants,
        },
    },
    error::MapResult,
    util::get_uuid,
};

use super::{OrganizationId, UserId};

pub const TENANT_STATUS_ACTIVE: &str = "active";

/// Strict zero-knowledge personal Recovery Kit (client-wrapped offline recovery key,
/// readable only by the owning user — no server escrow and no admin key recovery).
pub const RECOVERY_BUNDLE_KIT: &str = "personal_kit";

/// Maximum authority validity window (15 minutes per Design §11 P3).
pub const MAX_AUTHORITY_AGE_SECS: i64 = 900;

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

    pub async fn attachment_bytes(tenant_id: &str, conn: &DbConn) -> i64 {
        let tid = tenant_id.to_owned();
        conn.run(move |conn| {
            let sum: Option<BigDecimal> = attachments::table
                .filter(attachments::tenant_id.eq(tid))
                .select(diesel::dsl::sum(attachments::file_size))
                .first(conn)
                .unwrap_or(None);
            sum_to_i64(sum)
        })
        .await
    }

    pub async fn send_file_bytes(tenant_id: &str, conn: &DbConn) -> i64 {
        let tid = tenant_id.to_owned();
        conn.run(move |conn| {
            let rows: Vec<String> = sends::table
                .filter(sends::tenant_id.eq(tid))
                .filter(sends::atype.eq(1))
                .select(sends::data)
                .load::<String>(conn)
                .unwrap_or_default();
            let mut total: i64 = 0;
            for data in rows {
                if let Ok(val) = serde_json::from_str::<Value>(&data)
                    && let Some(sz) = val.get("size").or_else(|| val.get("Size")).and_then(Value::as_i64)
                {
                    total = total.saturating_add(sz.max(0));
                }
            }
            total
        })
        .await
    }

    /// Counts retained encrypted record bytes (personal + shared ciphers including trashed
    /// revisions, plus active recovery kit envelopes) per Design §11 P3.
    pub async fn record_payload_bytes(tenant_id: &str, conn: &DbConn) -> i64 {
        let tid = tenant_id.to_owned();
        conn.run(move |conn| {
            let cipher_data: Vec<String> = ciphers::table
                .filter(ciphers::tenant_id.eq(&tid))
                .select(ciphers::data)
                .load::<String>(conn)
                .unwrap_or_default();
            let mut total: i64 = 0;
            for d in cipher_data {
                total = total.saturating_add(len_i64(&d));
            }

            let bundles: Vec<(String, Option<String>)> = tenant_recovery_bundles::table
                .filter(tenant_recovery_bundles::tenant_id.eq(&tid))
                .filter(tenant_recovery_bundles::revoked_at.is_null())
                .select((tenant_recovery_bundles::wrapped_user_key, tenant_recovery_bundles::wrapped_private_key))
                .load(conn)
                .unwrap_or_default();
            for (wk, wpk) in bundles {
                total = total.saturating_add(len_i64(&wk));
                if let Some(pk) = wpk {
                    total = total.saturating_add(len_i64(&pk));
                }
            }
            total
        })
        .await
    }

    /// Total committed storage bytes retained for this tenant across attachments, sends,
    /// encrypted ciphers (including trash), and key envelopes.
    pub async fn committed_storage_bytes(tenant_id: &str, conn: &DbConn) -> i64 {
        let att = Self::attachment_bytes(tenant_id, conn).await;
        let snd = Self::send_file_bytes(tenant_id, conn).await;
        let rec = Self::record_payload_bytes(tenant_id, conn).await;
        att.saturating_add(snd).saturating_add(rec)
    }

    /// Locks the tenant row, checks status, authority freshness and the storage grant against
    /// committed + reserved bytes, reserves `additional_bytes`, and returns `access_epoch` so a
    /// late upload can be fenced. Hosted mode is PostgreSQL-only; other backends fail closed.
    pub async fn reserve_storage_grant(
        tenant_id: &str,
        additional_bytes: i64,
        max_authority_age_secs: i64,
        home_region: &str,
        conn: &DbConn,
    ) -> Result<i64, crate::Error> {
        let tid = tenant_id.to_owned();
        let region = home_region.to_owned();
        let add = additional_bytes.max(0);
        db_run! { conn:
            postgresql {
                conn.transaction::<i64, crate::Error, _>(|conn| {
                    let now = Utc::now();
                    let tenant: Tenant = tenants::table
                        .filter(tenants::id.eq(&tid))
                        .for_update()
                        .first::<Tenant>(conn)
                        .map_err(|_| crate::Error::new("Tenant not found", "Tenant not found").with_code(403))?;
                    validate_tenant_growth_tx(&tenant, &region, now.timestamp(), max_authority_age_secs)?;
                    if add > 0 {
                        let att: Option<BigDecimal> = attachments::table
                            .filter(attachments::tenant_id.eq(&tid))
                            .select(diesel::dsl::sum(attachments::file_size))
                            .first(conn)
                            .map_res("Error summing tenant attachments")?;
                        let records: Option<i64> = ciphers::table
                            .filter(ciphers::tenant_id.eq(&tid))
                            .select(diesel::dsl::sql::<diesel::sql_types::Nullable<diesel::sql_types::BigInt>>(
                                "SUM(OCTET_LENGTH(data))::BIGINT",
                            ))
                            .first(conn)
                            .map_res("Error summing tenant records")?;
                        let committed = sum_to_i64(att).saturating_add(records.unwrap_or(0).max(0));
                        if !tenant.can_grow_storage(committed, add, now.timestamp()) {
                            err_code!("Organization storage quota exceeded or grant expired", 403);
                        }
                        diesel::update(tenants::table.filter(tenants::id.eq(&tid)))
                            .set((
                                tenants::storage_reserved_bytes.eq(tenant.storage_reserved_bytes.max(0).saturating_add(add)),
                                tenants::updated_at.eq(now.naive_utc()),
                            ))
                            .execute(conn)
                            .map(drop)
                            .map_res("Error reserving tenant storage bytes")?;
                    }
                    Ok(tenant.access_epoch)
                })
            }
            sqlite, mysql {
                let _ = conn;
                drop((tid, region, add, max_authority_age_secs));
                err_code!("Hosted multi-tenant storage requires PostgreSQL", 503)
            }
        }
    }

    /// Releases previously reserved bytes (clamped at 0).
    pub async fn release_storage_reservation(tenant_id: &str, bytes: i64, conn: &DbConn) {
        if bytes <= 0 {
            return;
        }
        let tid = tenant_id.to_owned();
        let now_dt = Utc::now().naive_utc();
        let res = db_run! { conn:
            postgresql {
                conn.transaction::<(), diesel::result::Error, _>(|conn| {
                    if let Ok(tenant) = tenants::table.filter(tenants::id.eq(&tid)).for_update().first::<Tenant>(conn) {
                        let next = tenant.storage_reserved_bytes.saturating_sub(bytes).max(0);
                        diesel::update(tenants::table.filter(tenants::id.eq(&tid)))
                            .set((tenants::storage_reserved_bytes.eq(next), tenants::updated_at.eq(now_dt)))
                            .execute(conn)?;
                    }
                    Ok(())
                })
            }
            sqlite, mysql {
                conn.transaction::<(), diesel::result::Error, _>(|conn| {
                    if let Ok(tenant) = tenants::table.filter(tenants::id.eq(&tid)).first::<Tenant>(conn) {
                        let next = tenant.storage_reserved_bytes.saturating_sub(bytes).max(0);
                        diesel::update(tenants::table.filter(tenants::id.eq(&tid)))
                            .set((tenants::storage_reserved_bytes.eq(next), tenants::updated_at.eq(now_dt)))
                            .execute(conn)?;
                    }
                    Ok(())
                })
            }
        };
        if let Err(e) = res {
            error!("Failed to release {bytes} reserved bytes for tenant {tenant_id}: {e}");
        }
    }

    /// Verifies that the tenant is still active and `access_epoch` has not advanced since upload began.
    pub async fn verify_access_epoch(tenant_id: &str, expected_epoch: i64, conn: &DbConn) -> EmptyResult {
        let Some(tenant) = Self::find_by_id(tenant_id, conn).await else {
            err_code!("Tenant not found", 403);
        };
        if !tenant.is_active() || tenant.access_epoch != expected_epoch {
            err_code!("Tenant access was revoked while request was in flight", 403);
        }
        Ok(())
    }
}

fn len_i64(s: &str) -> i64 {
    i64::try_from(s.len()).unwrap_or(i64::MAX)
}

fn sum_to_i64(sum: Option<BigDecimal>) -> i64 {
    match sum.map(|v| v.to_i64()) {
        Some(Some(v)) => v.max(0),
        Some(None) => i64::MAX,
        None => 0,
    }
}

#[cfg(postgresql)]
fn validate_tenant_growth_tx(
    tenant: &Tenant,
    home_region: &str,
    now_ts: i64,
    max_authority_age_secs: i64,
) -> EmptyResult {
    if !home_region.trim().is_empty() && !tenant.home_region.trim().is_empty() && tenant.home_region != home_region {
        err_code!("Tenant belongs to a different region", 403);
    }
    if !tenant.is_active() {
        err_code!(format!("Tenant is not active (status: {})", tenant.status), 403);
    }
    if !tenant.has_fresh_authority(now_ts, max_authority_age_secs) {
        err_code!("Tenant authority cache is stale; failing closed", 503);
    }
    Ok(())
}

impl TenantErasedSubject {
    pub async fn record(issuer: &str, subject: &str, tenant_id: &str, revision: i64, conn: &DbConn) -> EmptyResult {
        let row = Self {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
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
        let iss = issuer.to_owned();
        let sub = subject.to_owned();
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

    /// Atomically revokes any prior active personal kit for this user and inserts the new bundle.
    pub async fn upsert_personal_kit(&self, conn: &DbConn) -> EmptyResult {
        let row = self.clone();
        let now = Utc::now().naive_utc();
        db_run! { conn:
            postgresql, sqlite, mysql {
                conn.transaction::<_, crate::Error, _>(|conn| {
                    diesel::update(
                        tenant_recovery_bundles::table
                            .filter(tenant_recovery_bundles::tenant_id.eq(&row.tenant_id))
                            .filter(tenant_recovery_bundles::user_uuid.eq(&row.user_uuid))
                            .filter(tenant_recovery_bundles::bundle_type.eq(RECOVERY_BUNDLE_KIT))
                            .filter(tenant_recovery_bundles::revoked_at.is_null()),
                    )
                    .set((
                        tenant_recovery_bundles::revoked_at.eq(Some(now)),
                        tenant_recovery_bundles::updated_at.eq(now),
                    ))
                    .execute(conn)
                    .map(drop)
                    .map_res("Error revoking previous recovery bundle")?;

                    diesel::insert_into(tenant_recovery_bundles::table)
                        .values(&row)
                        .execute(conn)
                        .map(drop)
                        .map_res("Error inserting recovery bundle")?;

                    Ok(())
                })
            }
        }
    }

    pub async fn revoke_personal_kit(tenant_id: &str, user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        let tid = tenant_id.to_owned();
        let uid = user_uuid.clone();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(
                tenant_recovery_bundles::table
                    .filter(tenant_recovery_bundles::tenant_id.eq(tid))
                    .filter(tenant_recovery_bundles::user_uuid.eq(uid))
                    .filter(tenant_recovery_bundles::bundle_type.eq(RECOVERY_BUNDLE_KIT))
                    .filter(tenant_recovery_bundles::revoked_at.is_null()),
            )
            .set((tenant_recovery_bundles::revoked_at.eq(Some(now)), tenant_recovery_bundles::updated_at.eq(now)))
            .execute(conn)
            .map_res("Error revoking recovery bundle")
        })
        .await
    }
}
