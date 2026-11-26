use std::time::Duration;

use bigdecimal::{BigDecimal, ToPrimitive};
use derive_more::{AsRef, Deref, Display};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    CONFIG,
    api::EmptyResult,
    auth::{encode_jwt, generate_file_download_claims},
    config::PathType,
    db::{
        DbConn, DbConnInner,
        schema::{attachments, ciphers},
    },
    error::MapResult,
};
use macros::IdFromParam;

use super::{CipherId, OrganizationId, UserId};

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = attachments)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(id))]
pub struct Attachment {
    pub id: AttachmentId,
    pub cipher_uuid: CipherId,
    pub file_name: String, // encrypted
    pub file_size: i64,
    pub akey: Option<String>,
    pub tenant_id: Option<String>,
}

/// Upper bound on an encrypted attachment file name or key in hosted mode.
pub const MAX_METADATA_LEN: usize = 4096;

/// Local methods
impl Attachment {
    pub const fn new(
        id: AttachmentId,
        cipher_uuid: CipherId,
        file_name: String,
        file_size: i64,
        akey: Option<String>,
    ) -> Self {
        Self {
            id,
            cipher_uuid,
            file_name,
            file_size,
            akey,
            tenant_id: None,
        }
    }

    pub fn with_tenant_id(mut self, tenant_id: Option<String>) -> Self {
        self.tenant_id = tenant_id;
        self
    }

    /// Bytes of the encrypted file name and key, which hosted storage grants count.
    pub fn metadata_bytes(&self) -> i64 {
        let len = self.file_name.len().saturating_add(self.akey.as_ref().map_or(0, String::len));
        i64::try_from(len).unwrap_or(i64::MAX)
    }

    /// Hosted mode bounds the encrypted file name and key.
    pub fn check_metadata_limits(&self) -> EmptyResult {
        if self.file_name.len() > MAX_METADATA_LEN || self.akey.as_ref().is_some_and(|k| k.len() > MAX_METADATA_LEN) {
            err_code!("Attachment file name or key is too long", 400);
        }
        Ok(())
    }

    /// Computes the attachment's object key relative to the attachments root.
    /// Multi-tenant attachments (`tenant_id.is_some()`) require a valid cell slug and are
    /// scoped under `cells/<cell>/tenants/<tid>/attachments/<cipher>/<id>`.
    pub fn get_file_path_in_cell(&self, cell: Option<&str>) -> Result<String, crate::Error> {
        if let Some(ref tid) = self.tenant_id {
            let Some(cell) = cell.filter(|c| crate::tenancy::is_valid_cell_slug(c)) else {
                err_code!("Tenant cell is missing or invalid", 500);
            };
            Ok(crate::tenancy::attachment_object_key(cell, tid, &self.cipher_uuid, &self.id))
        } else {
            Ok(format!("{}/{}", self.cipher_uuid, self.id))
        }
    }

    /// Resolves the attachment's object key by looking up its tenant's immutable cell slug when
    /// `tenant_id` is set, or returning the single-tenant relative key otherwise.
    pub async fn resolve_file_path(&self, conn: &DbConn) -> Result<String, crate::Error> {
        // A tenant's home_region never changes (C4), so one lookup per tenant serves every sync.
        static CELLS: std::sync::LazyLock<dashmap::DashMap<String, String>> =
            std::sync::LazyLock::new(dashmap::DashMap::new);
        if let Some(ref tid) = self.tenant_id {
            if let Some(cell) = CELLS.get(tid) {
                return self.get_file_path_in_cell(Some(&cell));
            }
            let Some(tenant) = super::Tenant::find_by_id(tid, conn).await else {
                err_code!("Tenant not found for attachment path", 403);
            };
            CELLS.insert(tid.clone(), tenant.home_region.clone());
            self.get_file_path_in_cell(Some(&tenant.home_region))
        } else {
            self.get_file_path_in_cell(None)
        }
    }

    pub async fn get_url(&self, host: &str, conn: &DbConn) -> Result<String, crate::Error> {
        let operator = CONFIG.opendal_operator_for_path_type(&PathType::Attachments)?;

        if crate::storage::is_fs_operator(&operator) {
            let token = encode_jwt(&generate_file_download_claims(self.cipher_uuid.clone(), self.id.clone()));
            Ok(format!("{host}/attachments/{}/{}?token={token}", self.cipher_uuid, self.id))
        } else {
            let path = self.resolve_file_path(conn).await?;
            Ok(operator.presign_read(&path, Duration::from_mins(1)).await?.uri().to_string())
        }
    }

    pub async fn to_json(&self, host: &str, conn: &DbConn) -> Result<Value, crate::Error> {
        Ok(json!({
            "id": self.id,
            "url": self.get_url(host, conn).await?,
            "fileName": self.file_name,
            "size": self.file_size.to_string(),
            "sizeName": crate::util::get_display_size(self.file_size),
            "key": self.akey,
            "object": "attachment"
        }))
    }
}

/// Database methods
impl Attachment {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| self.upsert_on_conn(conn)).await
    }

    pub(super) fn upsert_on_conn(&self, conn: &mut DbConnInner) -> EmptyResult {
        match conn {
            #[cfg(mysql)]
            DbConnInner::Mysql(conn) => diesel::insert_into(attachments::table)
                .values(self)
                .on_conflict(diesel::dsl::DuplicatedKeys)
                .do_update()
                .set(self)
                .execute(conn),
            #[cfg(postgresql)]
            DbConnInner::Postgresql(conn) => diesel::insert_into(attachments::table)
                .values(self)
                .on_conflict(attachments::id)
                .do_update()
                .set(self)
                .execute(conn),
            #[cfg(sqlite)]
            DbConnInner::Sqlite(conn) => diesel::insert_into(attachments::table)
                .values(self)
                .on_conflict(attachments::id)
                .do_update()
                .set(self)
                .execute(conn),
        }
        .map(drop)
        .map_res("Error saving attachment")
    }

    /// Updates `file_size` only if the attachment still exists for its cipher.
    pub async fn update_file_size_if_exists(&self, file_size: i64, conn: &DbConn) -> EmptyResult {
        let updated: usize = conn
            .run(move |conn| {
                diesel::update(
                    attachments::table
                        .filter(attachments::id.eq(&self.id))
                        .filter(attachments::cipher_uuid.eq(&self.cipher_uuid)),
                )
                .set(attachments::file_size.eq(file_size))
                .execute(conn)
                .map_res("Error finalizing attachment")
            })
            .await?;
        if updated == 0 {
            err_code!("Attachment no longer exists", 404);
        }
        Ok(())
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        let file_path = self.resolve_file_path(conn).await?;

        // Hosted: queue the object for the cleanup worker in the same transaction that drops the
        // row, so a crash or storage error can never orphan it.
        if CONFIG.is_multi_tenant()
            && let Some(ref tid) = self.tenant_id
        {
            return super::Tenant::delete_attachment_queuing_cleanup(tid, self, &file_path, conn).await;
        }

        conn.run(move |conn| {
            crate::util::retry(
                || diesel::delete(attachments::table.filter(attachments::id.eq(&self.id))).execute(conn),
                10,
            )
            .map(|_| ())
            .map_res("Error deleting attachment")
        })
        .await?;

        let operator = CONFIG.opendal_operator_for_path_type(&PathType::Attachments)?;

        if let Err(e) = operator.delete(&file_path).await {
            if e.kind() == opendal::ErrorKind::NotFound {
                debug!("File '{file_path}' already deleted.");
            } else {
                return Err(e.into());
            }
        }

        Ok(())
    }

    pub async fn delete_all_by_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> EmptyResult {
        for attachment in Attachment::find_by_cipher(cipher_uuid, conn).await {
            attachment.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn find_by_id(id: &AttachmentId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| attachments::table.filter(attachments::id.eq(id.to_lowercase())).first::<Self>(conn).ok())
            .await
    }

    pub async fn find_by_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            attachments::table
                .filter(attachments::cipher_uuid.eq(cipher_uuid))
                .load::<Self>(conn)
                .expect("Error loading attachments")
        })
        .await
    }

    pub async fn size_by_user(user_uuid: &UserId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            let result: Option<BigDecimal> = attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::user_uuid.eq(user_uuid))
                .select(diesel::dsl::sum(attachments::file_size))
                .first(conn)
                .expect("Error loading user attachment total size");

            match result.map(|r| r.to_i64()) {
                Some(Some(r)) => r,
                Some(None) => i64::MAX,
                None => 0,
            }
        })
        .await
    }

    pub async fn count_by_user(user_uuid: &UserId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::user_uuid.eq(user_uuid))
                .count()
                .first(conn)
                .unwrap_or(0)
        })
        .await
    }

    pub async fn size_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            let result: Option<BigDecimal> = attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .select(diesel::dsl::sum(attachments::file_size))
                .first(conn)
                .expect("Error loading user attachment total size");

            match result.map(|r| r.to_i64()) {
                Some(Some(r)) => r,
                Some(None) => i64::MAX,
                None => 0,
            }
        })
        .await
    }

    pub async fn count_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .count()
                .first(conn)
                .unwrap_or(0)
        })
        .await
    }

    // This will return all attachments linked to the user or org
    // There is no filtering done here if the user actually has access!
    // It is used to speed up the sync process, and the matching is done in a different part.
    pub async fn find_all_by_user_and_orgs(
        user_uuid: &UserId,
        org_uuids: &Vec<OrganizationId>,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::user_uuid.eq(user_uuid))
                .or_filter(ciphers::organization_uuid.eq_any(org_uuids))
                .select(attachments::all_columns)
                .load::<Self>(conn)
                .expect("Error loading attachments")
        })
        .await
    }
}

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    IdFromParam,
)]
pub struct AttachmentId(pub String);
