use bigdecimal::{BigDecimal, ToPrimitive};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        schema::{
            attachments, ciphers, sends, tenant_processed_events, tenant_recovery_bundles, tenants,
        },
    },
    error::MapResult,
    util::get_uuid,
};

use super::{OrganizationId, UserId};

pub const TENANT_STATUS_ACTIVE: &str = "active";
#[allow(dead_code)]
pub const TENANT_STATUS_SUSPENDED: &str = "suspended";
pub const TENANT_STATUS_ERASING: &str = "erasing";
#[allow(dead_code)]
pub const TENANT_STATUS_DELETED: &str = "deleted";

pub const RECOVERY_BUNDLE_KIT: &str = "personal_kit";
pub const RECOVERY_BUNDLE_ORG_ESCROW: &str = "org_escrow";

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
    pub storage_over_since: Option<i64>,
    pub primary_org_uuid: Option<OrganizationId>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub deleted_at: Option<NaiveDateTime>,
    pub erased_at: Option<NaiveDateTime>,
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
    pub escrow_org_uuid: Option<OrganizationId>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
}

#[derive(Clone, Debug, Identifiable, Queryable, Insertable)]
#[diesel(table_name = tenant_processed_events)]
#[diesel(primary_key(event_id))]
pub struct TenantProcessedEvent {
    pub event_id: String,
    pub event_type: String,
    pub expires_at: i64,
    pub processed_at: NaiveDateTime,
}

impl Tenant {
    pub fn new(id: String, home_region: String) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            id,
            status: TENANT_STATUS_ACTIVE.to_owned(),
            home_region,
            app_enabled: true,
            revision: 0,
            quotas_json: "{}".to_owned(),
            storage_pool_bytes: 0,
            storage_over_since: None,
            primary_org_uuid: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
            erased_at: None,
        }
    }

    /// True if the tenant is active, enabled, and not deleted/erased.
    pub fn is_active(&self) -> bool {
        self.app_enabled
            && self.status == TENANT_STATUS_ACTIVE
            && self.deleted_at.is_none()
            && self.erased_at.is_none()
    }

    /// True if a user with an `export_only` session may read/export vault data.
    /// Blocked once the tenant is deleted or erased, or if disabled/suspended.
    pub fn is_export_readable(&self) -> bool {
        self.app_enabled
            && matches!(self.status.as_str(), TENANT_STATUS_ACTIVE | TENANT_STATUS_ERASING)
            && self.deleted_at.is_none()
            && self.erased_at.is_none()
    }

    pub fn parsed_quotas(&self) -> Value {
        serde_json::from_str(&self.quotas_json).unwrap_or_else(|_| json!({}))
    }

    pub fn max_ciphers_quota(&self) -> Option<i64> {
        self.parsed_quotas()
            .get("max_ciphers")
            .and_then(Value::as_i64)
            .filter(|v| *v > 0)
    }

    pub fn max_storage_bytes(&self) -> Option<i64> {
        if self.storage_pool_bytes > 0 {
            return Some(self.storage_pool_bytes);
        }
        self.parsed_quotas()
            .get("max_storage_bytes")
            .and_then(Value::as_i64)
            .filter(|v| *v > 0)
    }

    pub fn is_storage_over_quota(&self, current_used_bytes: i64, additional_bytes: i64) -> bool {
        if self.storage_over_since.is_some() {
            return true;
        }
        if let Some(limit) = self.max_storage_bytes() {
            return current_used_bytes.saturating_add(additional_bytes) > limit;
        }
        false
    }

    pub async fn find_by_id(id: &str, conn: &DbConn) -> Option<Self> {
        let id = id.to_owned();
        conn.run(move |conn| tenants::table.filter(tenants::id.eq(id)).first::<Self>(conn).ok()).await
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
            let result: Option<BigDecimal> = attachments::table
                .filter(attachments::tenant_id.eq(tid))
                .select(diesel::dsl::sum(attachments::file_size))
                .first(conn)
                .unwrap_or(None);
            match result.map(|r| r.to_i64()) {
                Some(Some(v)) => v,
                Some(None) => i64::MAX,
                None => 0,
            }
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

    pub async fn storage_used_bytes(tenant_id: &str, conn: &DbConn) -> i64 {
        let att = Self::attachment_bytes(tenant_id, conn).await;
        let snd = Self::send_file_bytes(tenant_id, conn).await;
        att.saturating_add(snd)
    }
}

impl TenantRecoveryBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: String,
        user_uuid: UserId,
        bundle_type: String,
        version: i32,
        kdf_params_json: String,
        wrapped_user_key: String,
        wrapped_private_key: Option<String>,
        recovery_key_hint: Option<String>,
        escrow_org_uuid: Option<OrganizationId>,
    ) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            uuid: get_uuid(),
            tenant_id,
            user_uuid,
            bundle_type,
            version,
            kdf_params_json,
            wrapped_user_key,
            wrapped_private_key,
            recovery_key_hint,
            escrow_org_uuid,
            created_at: now,
            updated_at: now,
            revoked_at: None,
        }
    }

    pub async fn find_active(
        tenant_id: &str,
        user_uuid: &UserId,
        bundle_type: &str,
        conn: &DbConn,
    ) -> Option<Self> {
        let tid = tenant_id.to_owned();
        let uid = user_uuid.clone();
        let btype = bundle_type.to_owned();
        conn.run(move |conn| {
            tenant_recovery_bundles::table
                .filter(tenant_recovery_bundles::tenant_id.eq(tid))
                .filter(tenant_recovery_bundles::user_uuid.eq(uid))
                .filter(tenant_recovery_bundles::bundle_type.eq(btype))
                .filter(tenant_recovery_bundles::revoked_at.is_null())
                .order(tenant_recovery_bundles::updated_at.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_active_escrow(
        tenant_id: &str,
        user_uuid: &UserId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Option<Self> {
        let tid = tenant_id.to_owned();
        let uid = user_uuid.clone();
        let oid = org_uuid.clone();
        conn.run(move |conn| {
            tenant_recovery_bundles::table
                .filter(tenant_recovery_bundles::tenant_id.eq(tid))
                .filter(tenant_recovery_bundles::user_uuid.eq(uid))
                .filter(tenant_recovery_bundles::bundle_type.eq("org_escrow"))
                .filter(tenant_recovery_bundles::escrow_org_uuid.eq(Some(oid)))
                .filter(tenant_recovery_bundles::revoked_at.is_null())
                .order(tenant_recovery_bundles::updated_at.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn list_active_for_user(tenant_id: &str, user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        let tid = tenant_id.to_owned();
        let uid = user_uuid.clone();
        conn.run(move |conn| {
            tenant_recovery_bundles::table
                .filter(tenant_recovery_bundles::tenant_id.eq(tid))
                .filter(tenant_recovery_bundles::user_uuid.eq(uid))
                .filter(tenant_recovery_bundles::revoked_at.is_null())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn list_active_for_org(tenant_id: &str, org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        let tid = tenant_id.to_owned();
        let oid = org_uuid.clone();
        conn.run(move |conn| {
            tenant_recovery_bundles::table
                .filter(tenant_recovery_bundles::tenant_id.eq(tid))
                .filter(tenant_recovery_bundles::bundle_type.eq("org_escrow"))
                .filter(tenant_recovery_bundles::escrow_org_uuid.eq(Some(oid)))
                .filter(tenant_recovery_bundles::revoked_at.is_null())
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// Atomically revokes any prior active bundle of the same type (and org for `org_escrow`)
    /// and inserts this bundle.
    pub async fn upsert_active(&self, conn: &DbConn) -> EmptyResult {
        let now = Utc::now().naive_utc();
        let row = self.clone();
        conn.run(move |conn| {
            conn.transaction::<_, diesel::result::Error, _>(|conn| {
                if let Some(ref oid) = row.escrow_org_uuid {
                    diesel::update(
                        tenant_recovery_bundles::table
                            .filter(tenant_recovery_bundles::tenant_id.eq(&row.tenant_id))
                            .filter(tenant_recovery_bundles::user_uuid.eq(&row.user_uuid))
                            .filter(tenant_recovery_bundles::bundle_type.eq(&row.bundle_type))
                            .filter(tenant_recovery_bundles::escrow_org_uuid.eq(Some(oid)))
                            .filter(tenant_recovery_bundles::revoked_at.is_null()),
                    )
                    .set((
                        tenant_recovery_bundles::revoked_at.eq(Some(now)),
                        tenant_recovery_bundles::updated_at.eq(now),
                    ))
                    .execute(conn)?;
                } else {
                    diesel::update(
                        tenant_recovery_bundles::table
                            .filter(tenant_recovery_bundles::tenant_id.eq(&row.tenant_id))
                            .filter(tenant_recovery_bundles::user_uuid.eq(&row.user_uuid))
                            .filter(tenant_recovery_bundles::bundle_type.eq(&row.bundle_type))
                            .filter(tenant_recovery_bundles::escrow_org_uuid.is_null())
                            .filter(tenant_recovery_bundles::revoked_at.is_null()),
                    )
                    .set((
                        tenant_recovery_bundles::revoked_at.eq(Some(now)),
                        tenant_recovery_bundles::updated_at.eq(now),
                    ))
                    .execute(conn)?;
                }

                diesel::insert_into(tenant_recovery_bundles::table).values(&row).execute(conn)?;
                Ok(())
            })
            .map_res("Error saving tenant recovery bundle")
        })
        .await
    }

    pub async fn revoke_active(
        tenant_id: &str,
        user_uuid: &UserId,
        bundle_type: &str,
        conn: &DbConn,
    ) -> EmptyResult {
        let now = Utc::now().naive_utc();
        let tid = tenant_id.to_owned();
        let uid = user_uuid.clone();
        let btype = bundle_type.to_owned();
        conn.run(move |conn| {
            diesel::update(
                tenant_recovery_bundles::table
                    .filter(tenant_recovery_bundles::tenant_id.eq(tid))
                    .filter(tenant_recovery_bundles::user_uuid.eq(uid))
                    .filter(tenant_recovery_bundles::bundle_type.eq(btype))
                    .filter(tenant_recovery_bundles::revoked_at.is_null()),
            )
            .set((
                tenant_recovery_bundles::revoked_at.eq(Some(now)),
                tenant_recovery_bundles::updated_at.eq(now),
            ))
            .execute(conn)
            .map(|_| ())
            .map_res("Error revoking tenant recovery bundle")
        })
        .await
    }

    pub async fn revoke_active_escrow(
        tenant_id: &str,
        user_uuid: &UserId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> EmptyResult {
        let now = Utc::now().naive_utc();
        let tid = tenant_id.to_owned();
        let uid = user_uuid.clone();
        let oid = org_uuid.clone();
        conn.run(move |conn| {
            diesel::update(
                tenant_recovery_bundles::table
                    .filter(tenant_recovery_bundles::tenant_id.eq(tid))
                    .filter(tenant_recovery_bundles::user_uuid.eq(uid))
                    .filter(tenant_recovery_bundles::bundle_type.eq("org_escrow"))
                    .filter(tenant_recovery_bundles::escrow_org_uuid.eq(Some(oid)))
                    .filter(tenant_recovery_bundles::revoked_at.is_null()),
            )
            .set((
                tenant_recovery_bundles::revoked_at.eq(Some(now)),
                tenant_recovery_bundles::updated_at.eq(now),
            ))
            .execute(conn)
            .map(|_| ())
            .map_res("Error revoking org escrow recovery bundle")
        })
        .await
    }
}

impl TenantProcessedEvent {
    /// Returns `Ok(true)` if the event was newly inserted, `Ok(false)` if already seen (replay).
    pub async fn claim(event_id: &str, event_type: &str, expires_at: i64, conn: &DbConn) -> Result<bool, crate::Error> {
        let row = Self {
            event_id: event_id.to_owned(),
            event_type: event_type.to_owned(),
            expires_at,
            processed_at: Utc::now().naive_utc(),
        };
        let inserted: Result<usize, crate::Error> = db_run! { conn:
            mysql {
                diesel::insert_or_ignore_into(tenant_processed_events::table)
                    .values(&row)
                    .execute(conn)
                    .map_res("Error claiming tenant event")
            }
            postgresql, sqlite {
                diesel::insert_into(tenant_processed_events::table)
                    .values(&row)
                    .on_conflict(tenant_processed_events::event_id)
                    .do_nothing()
                    .execute(conn)
                    .map_res("Error claiming tenant event")
            }
        };
        Ok(inserted? > 0)
    }
}
