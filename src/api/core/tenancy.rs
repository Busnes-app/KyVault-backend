//! Multi-tenant status, quota visibility (P3), and zero-knowledge Recovery Kit +
//! Organization Admin Escrow endpoints (P2).
//!
//! All recovery blobs stored here are opaque client-encrypted ciphertexts; the
//! server never sees plaintext recovery keys, user keys, or org escrow private keys.

use rocket::{Route, serde::json::Json, serde::json::Value};

use crate::{
    CONFIG,
    api::{
        EmptyResult, JsonResult,
        core::log_event,
    },
    auth::{AdminHeaders, ClientHeaders, Headers},
    db::{
        DbConn,
        models::{
            EventType, Membership, MembershipStatus, MembershipType, Organization, OrganizationId, RECOVERY_BUNDLE_KIT,
            RECOVERY_BUNDLE_ORG_ESCROW, Tenant, TenantRecoveryBundle, User, UserId,
        },
    },
};

const MAX_WRAPPED_KEY_LEN: usize = 65_536; // 64 KiB upper bound per wrapped blob
const MAX_KDF_PARAMS_LEN: usize = 4_096;
const MAX_HINT_LEN: usize = 256;

pub fn routes() -> Vec<Route> {
    routes![
        get_tenancy_status,
        put_personal_recovery,
        get_personal_recovery,
        delete_personal_recovery,
        put_org_escrow,
        list_org_escrow,
        get_org_escrow_member,
        delete_org_escrow_member,
    ]
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgEscrowPayload {
    #[serde(default = "default_version")]
    version: i32,
    #[serde(default)]
    kdf_params: Option<Value>,
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
        "escrowOrgId": bundle.escrow_org_uuid,
        "createdAt": bundle.created_at.and_utc().to_rfc3339(),
        "updatedAt": bundle.updated_at.and_utc().to_rfc3339(),
    })
}

/// Returns tenant isolation status, storage/cipher quota consumption, and recovery bundle state.
#[get("/tenancy/status")]
async fn get_tenancy_status(headers: Headers, conn: DbConn) -> JsonResult {
    let tid = effective_tenant_id(&headers.user)?;
    let tenant = Tenant::find_by_id(&tid, &conn).await;

    let (storage_used, cipher_count) = if CONFIG.is_multi_tenant() {
        (
            Tenant::storage_used_bytes(&tid, &conn).await,
            Tenant::cipher_count(&tid, &conn).await,
        )
    } else {
        (0, 0)
    };

    let bundles = TenantRecoveryBundle::list_active_for_user(&tid, &headers.user.uuid, &conn).await;
    let has_personal_kit = bundles.iter().any(|b| b.bundle_type == RECOVERY_BUNDLE_KIT);
    let escrowed_org_ids: Vec<String> = bundles
        .iter()
        .filter(|b| b.bundle_type == RECOVERY_BUNDLE_ORG_ESCROW)
        .filter_map(|b| b.escrow_org_uuid.as_ref().map(|o| o.to_string()))
        .collect();

    Ok(Json(json!({
        "multiTenant": CONFIG.is_multi_tenant(),
        "tenantId": tid,
        "homeRegion": CONFIG.home_region(),
        "status": tenant.as_ref().map_or("active", |t| t.status.as_str()),
        "storagePoolBytes": tenant.as_ref().map(|t| t.storage_pool_bytes),
        "storageUsedBytes": storage_used,
        "storageOverSince": tenant
            .as_ref()
            .and_then(|t| t.storage_over_since)
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .map(|d| d.to_rfc3339()),
        "cipherCount": cipher_count,
        "maxCiphersPerTenant": CONFIG.tenancy_max_ciphers_per_tenant(),
        "maxImportCiphers": CONFIG.tenancy_max_import_ciphers(),
        "maxImportFolders": CONFIG.tenancy_max_import_folders(),
        "allowSends": CONFIG.tenancy_allow_sends(),
        "allowEmergencyAccess": CONFIG.tenancy_allow_emergency_access(),
        "recovery": {
            "hasPersonalRecoveryKit": has_personal_kit,
            "escrowedOrgIds": escrowed_org_ids,
        }
    })))
}

/// Uploads or rotates the authenticated user's client-encrypted Personal Recovery Kit bundle.
#[put("/tenancy/recovery/personal", data = "<data>")]
async fn put_personal_recovery(
    data: Json<PersonalRecoveryPayload>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
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

    let bundle = TenantRecoveryBundle::new(
        tid.clone(),
        headers.user.uuid.clone(),
        RECOVERY_BUNDLE_KIT.to_owned(),
        data.version,
        kdf_params_json,
        data.wrapped_user_key,
        data.wrapped_private_key,
        data.recovery_key_hint,
        None,
    );
    bundle.upsert_active(&conn).await?;

    info!(
        "AUDIT: User {} updated personal_kit recovery bundle {} (tenant {})",
        headers.user.uuid, bundle.uuid, tid
    );

    Ok(Json(bundle_to_json(&bundle)))
}

/// Retrieves the authenticated user's active Personal Recovery Kit bundle.
#[get("/tenancy/recovery/personal")]
async fn get_personal_recovery(headers: Headers, conn: DbConn) -> JsonResult {
    let tid = effective_tenant_id(&headers.user)?;
    let Some(bundle) = TenantRecoveryBundle::find_active(&tid, &headers.user.uuid, RECOVERY_BUNDLE_KIT, &conn).await else {
        err_code!("Personal recovery kit not found", 404);
    };
    Ok(Json(bundle_to_json(&bundle)))
}

/// Revokes the authenticated user's Personal Recovery Kit bundle.
#[delete("/tenancy/recovery/personal")]
async fn delete_personal_recovery(headers: Headers, conn: DbConn) -> EmptyResult {
    let tid = effective_tenant_id(&headers.user)?;
    TenantRecoveryBundle::revoke_active(&tid, &headers.user.uuid, RECOVERY_BUNDLE_KIT, &conn).await
}

/// Allows a confirmed organization member to upload their user key wrapped under the
/// organization's escrow public key (zero-knowledge admin escrow).
#[put("/tenancy/recovery/escrow/<org_id>", data = "<data>")]
async fn put_org_escrow(
    org_id: OrganizationId,
    data: Json<OrgEscrowPayload>,
    headers: Headers,
    client_header: ClientHeaders,
    conn: DbConn,
) -> JsonResult {
    let tid = effective_tenant_id(&headers.user)?;

    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err_code!("Organization not found", 404);
    };
    if CONFIG.is_multi_tenant() {
        crate::tenancy::ensure_same_tenant(Some(&tid), org.tenant_id.as_deref(), "put_org_escrow")?;
    }

    let Some(membership) = Membership::find_by_user_and_org(&headers.user.uuid, &org_id, &conn).await else {
        err_code!("User is not a member of this organization", 403);
    };
    if membership.status != MembershipStatus::Confirmed as i32 {
        err_code!("Organization membership must be confirmed to enroll in escrow", 403);
    }

    let data = data.into_inner();
    let kdf_params_json = serde_json::to_string(&data.kdf_params.unwrap_or_else(|| json!({"scheme": "org_rsa_oaep"})))?;
    validate_recovery_blobs(
        data.version,
        &kdf_params_json,
        &data.wrapped_user_key,
        data.wrapped_private_key.as_deref(),
        data.recovery_key_hint.as_deref(),
    )?;

    let bundle = TenantRecoveryBundle::new(
        tid,
        headers.user.uuid.clone(),
        RECOVERY_BUNDLE_ORG_ESCROW.to_owned(),
        data.version,
        kdf_params_json,
        data.wrapped_user_key,
        data.wrapped_private_key,
        data.recovery_key_hint,
        Some(org_id.clone()),
    );
    bundle.upsert_active(&conn).await?;

    log_event(
        EventType::OrganizationUserResetPasswordEnroll,
        &membership.uuid,
        &org_id,
        &headers.user.uuid,
        client_header.device_type,
        &client_header.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(bundle_to_json(&bundle)))
}

/// Lists escrow enrollment metadata (no ciphertext) for an organization (Admin/Owner only).
#[get("/tenancy/recovery/escrow/<org_id>")]
async fn list_org_escrow(org_id: OrganizationId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err_code!("Organization ID mismatch", 403);
    }
    let tid = effective_tenant_id(&headers.user)?;
    let bundles = TenantRecoveryBundle::list_active_for_org(&tid, &org_id, &conn).await;
    let items: Vec<Value> = bundles
        .into_iter()
        .map(|b| {
            json!({
                "id": b.uuid,
                "userId": b.user_uuid,
                "version": b.version,
                "recoveryKeyHint": b.recovery_key_hint,
                "createdAt": b.created_at.and_utc().to_rfc3339(),
                "updatedAt": b.updated_at.and_utc().to_rfc3339(),
            })
        })
        .collect();

    Ok(Json(json!({
        "organizationId": org_id,
        "data": items,
    })))
}

/// Retrieves a member's active org-escrow bundle (Admin/Owner in same tenant only, audit logged).
#[get("/tenancy/recovery/escrow/<org_id>/<target_user_id>")]
async fn get_org_escrow_member(
    org_id: OrganizationId,
    target_user_id: UserId,
    headers: AdminHeaders,
    client_header: ClientHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err_code!("Organization ID mismatch", 403);
    }
    let tid = effective_tenant_id(&headers.user)?;

    let Some(target_user) = User::find_by_uuid(&target_user_id, &conn).await else {
        err_code!("Target user not found", 404);
    };
    if CONFIG.is_multi_tenant() {
        crate::tenancy::ensure_same_tenant(Some(&tid), target_user.tenant_id.as_deref(), "get_org_escrow_member")?;
    }

    let Some(target_membership) = Membership::find_by_user_and_org(&target_user_id, &org_id, &conn).await else {
        err_code!("Target user is not a member of this organization", 404);
    };

    let Some(bundle) = TenantRecoveryBundle::find_active_escrow(&tid, &target_user_id, &org_id, &conn).await else {
        err_code!("Escrow recovery bundle not found for member", 404);
    };

    warn!(
        "AUDIT: Org admin {} retrieved org_escrow recovery bundle {} for user {} in org {} (tenant {})",
        headers.user.uuid, bundle.uuid, target_user_id, org_id, tid
    );

    log_event(
        EventType::OrganizationUserUpdated,
        &target_membership.uuid,
        &org_id,
        &headers.user.uuid,
        client_header.device_type,
        &client_header.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(bundle_to_json(&bundle)))
}

/// Revokes a member's org-escrow bundle. Allowed for the member themselves or an Org Admin/Owner.
#[delete("/tenancy/recovery/escrow/<org_id>/<target_user_id>")]
async fn delete_org_escrow_member(
    org_id: OrganizationId,
    target_user_id: UserId,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    let tid = effective_tenant_id(&headers.user)?;

    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err_code!("Organization not found", 404);
    };
    if CONFIG.is_multi_tenant() {
        crate::tenancy::ensure_same_tenant(Some(&tid), org.tenant_id.as_deref(), "delete_org_escrow_member")?;
    }

    if headers.user.uuid != target_user_id {
        let Some(caller_membership) = Membership::find_by_user_and_org(&headers.user.uuid, &org_id, &conn).await else {
            err_code!("Not authorized to revoke another user's escrow bundle", 403);
        };
        if caller_membership.status != MembershipStatus::Confirmed as i32
            || caller_membership.atype > MembershipType::Admin as i32
        {
            err_code!("Admin or Owner role required to revoke member escrow bundle", 403);
        }
    }

    TenantRecoveryBundle::revoke_active_escrow(&tid, &target_user_id, &org_id, &conn).await
}
