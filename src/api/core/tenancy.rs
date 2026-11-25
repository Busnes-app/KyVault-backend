//! Multi-tenant status, storage grant/quota visibility (P3), and strict zero-knowledge
//! user-owned Personal Recovery Kit endpoints (P2).
//!
//! All recovery blobs stored here are opaque client-encrypted ciphertexts; the server never
//! sees plaintext recovery keys or user keys, and there is no server-held or admin escrow.

use rocket::{
    Route,
    serde::json::{Json, Value},
};

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::Headers,
    db::{
        DbConn,
        models::{Tenant, TenantRecoveryBundle, User},
    },
};

const MAX_WRAPPED_KEY_LEN: usize = 65_536; // 64 KiB upper bound per wrapped blob
const MAX_KDF_PARAMS_LEN: usize = 4_096;
const MAX_HINT_LEN: usize = 256;

pub fn routes() -> Vec<Route> {
    routes![get_tenancy_status, put_personal_recovery, get_personal_recovery, delete_personal_recovery,]
}

fn effective_tenant_id(user: &User) -> Result<String, crate::Error> {
    if CONFIG.is_multi_tenant() {
        Ok(crate::tenancy::require_user_tenant(user)?.to_owned())
    } else {
        Ok(user.tenant_id.clone().unwrap_or_else(|| "default".to_owned()))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersonalRecoveryPayload {
    #[serde(default = "default_version")]
    version: i32,
    kdf_params: Value,
    wrapped_user_key: String,
    wrapped_private_key: Option<String>,
    recovery_key_hint: Option<String>,
}

const fn default_version() -> i32 {
    1
}

fn validate_recovery_blobs(
    version: i32,
    kdf_params_json: &str,
    wrapped_user_key: &str,
    wrapped_private_key: Option<&str>,
    hint: Option<&str>,
) -> EmptyResult {
    if !(1..=100).contains(&version) {
        err_code!("Invalid recovery bundle version", 400);
    }
    if kdf_params_json.len() > MAX_KDF_PARAMS_LEN {
        err_code!("Recovery KDF parameters exceed maximum size", 400);
    }
    if wrapped_user_key.trim().is_empty() || wrapped_user_key.len() > MAX_WRAPPED_KEY_LEN {
        err_code!("Invalid wrappedUserKey payload", 400);
    }
    if let Some(pk) = wrapped_private_key
        && pk.len() > MAX_WRAPPED_KEY_LEN
    {
        err_code!("wrappedPrivateKey exceeds maximum size", 400);
    }
    if let Some(h) = hint
        && h.len() > MAX_HINT_LEN
    {
        err_code!("recoveryKeyHint exceeds maximum size", 400);
    }
    Ok(())
}

fn bundle_to_json(bundle: &TenantRecoveryBundle) -> Value {
    let kdf_params: Value = serde_json::from_str(&bundle.kdf_params_json).unwrap_or(json!({}));
    json!({
        "id": bundle.uuid,
        "tenantId": bundle.tenant_id,
        "userId": bundle.user_uuid,
        "bundleType": bundle.bundle_type,
        "version": bundle.version,
        "kdfParams": kdf_params,
        "wrappedUserKey": bundle.wrapped_user_key,
        "wrappedPrivateKey": bundle.wrapped_private_key,
        "recoveryKeyHint": bundle.recovery_key_hint,
        "createdAt": bundle.created_at.and_utc().to_rfc3339(),
        "updatedAt": bundle.updated_at.and_utc().to_rfc3339(),
    })
}

/// Returns tenant isolation status, reserved storage grant state, cipher quota consumption,
/// and personal recovery kit presence.
#[get("/tenancy/status")]
async fn get_tenancy_status(headers: Headers, conn: DbConn) -> JsonResult {
    let tid = effective_tenant_id(&headers.user)?;
    let tenant = Tenant::find_by_id(&tid, &conn).await;

    let (storage_used, cipher_count) = if CONFIG.is_multi_tenant() {
        (Tenant::committed_storage_bytes(&tid, &conn).await, Tenant::cipher_count(&tid, &conn).await)
    } else {
        (0, 0)
    };

    let has_personal_kit =
        TenantRecoveryBundle::find_active_personal_kit(&tid, &headers.user.uuid, &conn).await.is_some();

    Ok(Json(json!({
        "multiTenant": CONFIG.is_multi_tenant(),
        "tenantId": tid,
        "homeRegion": tenant.as_ref().map_or("", |t| t.home_region.as_str()),
        "cells": CONFIG.served_cells(),
        "status": tenant.as_ref().map_or("active", |t| t.status.as_str()),
        "appEnabled": tenant.as_ref().is_none_or(|t| t.app_enabled),
        "storagePoolBytes": tenant.as_ref().map(|t| t.storage_pool_bytes),
        "storageCeilingBytes": tenant.as_ref().map(|t| t.storage_ceiling_bytes),
        "storageReservedBytes": tenant.as_ref().map(|t| t.storage_reserved_bytes),
        "storageGrantExpiresAt": tenant
            .as_ref()
            .and_then(|t| t.storage_grant_expires_at)
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .map(|d| d.to_rfc3339()),
        "storageOrgUsedBytes": tenant.as_ref().map(|t| t.storage_org_used_bytes),
        "storageUsedBytes": storage_used,
        "storageOverSince": tenant
            .as_ref()
            .and_then(|t| t.storage_over_since)
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .map(|d| d.to_rfc3339()),
        "cipherCount": cipher_count,
        // The limit creation and restore enforce: the tenant's override, else the deployment default.
        "maxCiphersPerTenant": tenant
            .as_ref()
            .and_then(Tenant::max_ciphers_quota)
            .unwrap_or_else(|| CONFIG.tenancy_max_ciphers_per_tenant()),
        "maxImportCiphers": CONFIG.tenancy_max_import_ciphers(),
        "maxImportFolders": CONFIG.tenancy_max_import_folders(),
        "allowSends": CONFIG.is_sends_allowed(),
        "allowEmergencyAccess": CONFIG.is_emergency_access_allowed(),
        "recovery": {
            "hasPersonalRecoveryKit": has_personal_kit,
        }
    })))
}

/// Uploads or rotates the authenticated user's client-encrypted Personal Recovery Kit bundle.
#[put("/tenancy/recovery/personal", data = "<data>")]
async fn put_personal_recovery(data: Json<PersonalRecoveryPayload>, headers: Headers, conn: DbConn) -> JsonResult {
    let tid = effective_tenant_id(&headers.user)?;
    let data = data.into_inner();
    let kdf_params_json = serde_json::to_string(&data.kdf_params)?;

    validate_recovery_blobs(
        data.version,
        &kdf_params_json,
        &data.wrapped_user_key,
        data.wrapped_private_key.as_deref(),
        data.recovery_key_hint.as_deref(),
    )?;

    let bundle = TenantRecoveryBundle::new_personal_kit(
        tid.clone(),
        headers.user.uuid.clone(),
        data.version,
        kdf_params_json,
        data.wrapped_user_key,
        data.wrapped_private_key,
        data.recovery_key_hint,
    );
    if CONFIG.is_multi_tenant() {
        bundle
            .upsert_personal_kit_enforcing_grant(&CONFIG.served_cells(), CONFIG.tenancy_authority_max_age_secs(), &conn)
            .await?;
    } else {
        bundle.upsert_personal_kit(&conn).await?;
    }

    info!("AUDIT: User {} updated personal_kit recovery bundle {} (tenant {})", headers.user.uuid, bundle.uuid, tid);

    Ok(Json(bundle_to_json(&bundle)))
}

/// Retrieves the authenticated user's active Personal Recovery Kit bundle.
#[get("/tenancy/recovery/personal")]
async fn get_personal_recovery(headers: Headers, conn: DbConn) -> JsonResult {
    let tid = effective_tenant_id(&headers.user)?;
    let Some(bundle) = TenantRecoveryBundle::find_active_personal_kit(&tid, &headers.user.uuid, &conn).await else {
        err_code!("Personal recovery kit not found", 404);
    };
    Ok(Json(bundle_to_json(&bundle)))
}

/// Revokes the authenticated user's Personal Recovery Kit bundle.
#[delete("/tenancy/recovery/personal")]
async fn delete_personal_recovery(headers: Headers, conn: DbConn) -> EmptyResult {
    let tid = effective_tenant_id(&headers.user)?;
    TenantRecoveryBundle::revoke_personal_kit(&tid, &headers.user.uuid, &conn).await
}
