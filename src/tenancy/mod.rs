pub mod pubsub;

use chrono::Utc;

use crate::{
    CONFIG,
    api::EmptyResult,
    db::{
        DbConn,
        models::{Tenant, User},
    },
};

/// Canonicalizes an OIDC issuer URL by trimming any trailing slash so
/// `TenantErasedSubject` and `SsoUser` lookups stay consistent across Rust and worker calls.
pub fn canonical_issuer(issuer: &str) -> &str {
    issuer.trim().trim_end_matches('/')
}

/// Formats an OIDC `(issuer, subject)` pair identically to `sso::OIDCIdentifier`.
pub fn format_oidc_identifier(issuer: &str, subject: &str) -> String {
    format!("{}/{}", canonical_issuer(issuer), subject.trim())
}

/// Returns the user's bound tenant_id or fails closed with 403 in multi-tenant mode.
pub fn require_user_tenant(user: &User) -> Result<&str, crate::Error> {
    user.tenant_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| crate::Error::new("User is not bound to a tenant", "Tenant isolation violation").with_code(403))
}

/// Ensures two optional tenant IDs belong to the same tenant when running in multi-tenant mode.
/// In single-tenant mode this is a no-op.
pub fn ensure_same_tenant(a: Option<&str>, b: Option<&str>, context: &str) -> EmptyResult {
    if !CONFIG.is_multi_tenant() {
        return Ok(());
    }
    match (a.filter(|s| !s.is_empty()), b.filter(|s| !s.is_empty())) {
        (Some(ta), Some(tb)) if ta == tb => Ok(()),
        _ => {
            warn!("Cross-tenant access denied ({context}): lhs={a:?}, rhs={b:?}");
            err_code!("Cross-tenant access denied", 403);
        }
    }
}

/// Verifies that a tenant exists, belongs to this deployment's HOME_REGION,
/// is active and app-enabled, and has fresh KyIdentity authority (<= 15 min cap).
///
/// Ordinary vault access never accepts `export_only` sessions (Design §4.1 & §11 P3).
pub async fn check_tenant_active(tenant_id: &str, conn: &DbConn) -> Result<Tenant, crate::Error> {
    let Some(tenant) = Tenant::find_by_id(tenant_id, conn).await else {
        err_code!("Tenant not found or not provisioned in this region", 403);
    };

    let home_region = CONFIG.home_region();
    if !home_region.trim().is_empty() && !tenant.home_region.trim().is_empty() && tenant.home_region != home_region {
        warn!("Tenant {tenant_id} belongs to region '{}', rejected by region '{home_region}'", tenant.home_region);
        err_code!("Tenant belongs to a different region", 403);
    }

    if !tenant.app_enabled {
        err_code!("Password manager is disabled for this organization", 403);
    }

    if !tenant.is_active() {
        err_code!(format!("Tenant is not active (status: {})", tenant.status), 403);
    }

    let now_ts = Utc::now().timestamp();
    if !tenant.has_fresh_authority(now_ts, CONFIG.tenancy_authority_max_age_secs()) {
        warn!("Tenant {tenant_id} authority cache is stale or missing; failing closed");
        err_code!("Tenant authority cache is stale", 503);
    }

    Ok(tenant)
}

/// Transactionally checks tenant active status, authority freshness, and reserved storage growth
/// grant, reserving `additional_bytes` into `tenants.storage_reserved_bytes`.
///
/// Returns `Ok(Some(access_epoch))` in multi-tenant mode so callers can fence late upload
/// finalization and release reserved bytes on completion or error.
pub async fn reserve_storage_grant(
    user: &User,
    additional_bytes: i64,
    conn: &DbConn,
) -> Result<Option<i64>, crate::Error> {
    if !CONFIG.is_multi_tenant() {
        return Ok(None);
    }
    let tenant_id = require_user_tenant(user)?;
    let epoch = Tenant::reserve_storage_grant(
        tenant_id,
        additional_bytes,
        CONFIG.tenancy_authority_max_age_secs(),
        &CONFIG.home_region(),
        conn,
    )
    .await?;
    Ok(Some(epoch))
}

/// Releases previously reserved upload bytes in multi-tenant mode.
pub async fn release_storage_reservation(user: &User, bytes: i64, conn: &DbConn) {
    if !CONFIG.is_multi_tenant() || bytes <= 0 {
        return;
    }
    if let Ok(tenant_id) = require_user_tenant(user) {
        Tenant::release_storage_reservation(tenant_id, bytes, conn).await;
    }
}

/// Verifies that the tenant is still active and `access_epoch` has not changed since reservation.
pub async fn verify_access_epoch(user: &User, expected_epoch: Option<i64>, conn: &DbConn) -> EmptyResult {
    if !CONFIG.is_multi_tenant() {
        return Ok(());
    }
    let Some(epoch) = expected_epoch else {
        return Ok(());
    };
    let tenant_id = require_user_tenant(user)?;
    Tenant::verify_access_epoch(tenant_id, epoch, conn).await
}

/// Enforces tenant-level active cipher quota in multi-tenant mode.
pub async fn check_cipher_quota(user: &User, additional_ciphers: i64, conn: &DbConn) -> EmptyResult {
    if !CONFIG.is_multi_tenant() {
        return Ok(());
    }
    let tenant_id = require_user_tenant(user)?;
    let tenant = check_tenant_active(tenant_id, conn).await?;
    let max_ciphers = tenant.max_ciphers_quota().unwrap_or_else(|| CONFIG.tenancy_max_ciphers_per_tenant());
    if max_ciphers <= 0 {
        return Ok(());
    }
    let current = Tenant::cipher_count(tenant_id, conn).await;
    if current.saturating_add(additional_ciphers.max(0)) > max_ciphers {
        err_code!(format!("Organization cipher quota exceeded (limit: {max_ciphers})"), 403);
    }
    Ok(())
}

/// Enforces batch import guardrails (P3) per single request.
pub fn check_import_limits(cipher_count: usize, folder_count: usize) -> EmptyResult {
    if !CONFIG.is_multi_tenant() {
        return Ok(());
    }
    let max_ciphers = CONFIG.tenancy_max_import_ciphers();
    if cipher_count > max_ciphers {
        err_code!(format!("Import batch exceeds maximum of {max_ciphers} ciphers per request"), 400);
    }
    let max_folders = CONFIG.tenancy_max_import_folders();
    if folder_count > max_folders {
        err_code!(format!("Import batch exceeds maximum of {max_folders} folders per request"), 400);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::{
        Attachment, AttachmentId, CipherId, Send as SendModel, SendType, TENANT_STATUS_ACTIVE, Tenant,
    };

    #[test]
    fn canonical_oidc_identifier_formatting() {
        assert_eq!(format_oidc_identifier("https://id.busnes.app/", "usr_123"), "https://id.busnes.app/usr_123");
        assert_eq!(format_oidc_identifier("https://id.busnes.app", "usr_123"), "https://id.busnes.app/usr_123");
    }

    #[test]
    fn tenant_status_authority_and_reserved_grant_rules() {
        let now = 1_750_000_000i64;
        let mut t = Tenant::new("org-test".to_owned(), "us-east-1".to_owned());
        // New tenant starts app_enabled=false and without authority_refreshed_at (fail-closed)
        assert!(!t.is_active());
        assert!(!t.has_fresh_authority(now, 900));
        assert!(!t.has_valid_storage_grant(now));
        // Pool bytes alone is NOT a spendable grant!
        t.storage_pool_bytes = 100_000_000;
        assert!(!t.can_grow_storage(0, 1024, now));
        // 0-byte writes / shrinks / deletes are always permitted
        assert!(t.can_grow_storage(0, 0, now));
        assert!(t.can_grow_storage(50_000, -100, now));

        // Enable + fresh authority
        t.app_enabled = true;
        t.authority_refreshed_at = Some(now - 120);
        assert!(t.is_active());
        assert!(t.has_fresh_authority(now, 900));
        assert!(!t.has_fresh_authority(now + 901, 900));

        // Grant with ceiling & TTL
        t.storage_ceiling_bytes = 10_000;
        t.storage_grant_expires_at = Some(now + 600);
        t.storage_reserved_bytes = 1_000;
        assert!(t.has_valid_storage_grant(now));
        assert!(t.can_grow_storage(5_000, 4_000, now));
        assert!(!t.can_grow_storage(5_000, 4_001, now));
        // Expired grant denies growth
        assert!(!t.can_grow_storage(0, 1, now + 600));
        // Over-since denies growth even inside ceiling
        t.storage_over_since = Some(now - 10);
        assert!(!t.can_grow_storage(0, 1, now));

        // Lifecycle denials
        t.status = "suspended".to_owned();
        assert!(!t.is_active());
        t.status = "erasing".to_owned();
        assert!(!t.is_active());
        t.status = "deleted".to_owned();
        assert!(!t.is_active());
        t.status = TENANT_STATUS_ACTIVE.to_owned();
        t.app_enabled = false;
        assert!(!t.is_active());

        t.quotas_json = r#"{"max_ciphers": 2500}"#.to_owned();
        assert_eq!(t.max_ciphers_quota(), Some(2500));
    }

    #[test]
    fn tenant_prefixed_attachment_and_send_paths() {
        let cipher_id = CipherId::from("11111111-2222-3333-4444-555555555555".to_owned());
        let mut att = Attachment::new(AttachmentId("att-id-1".to_owned()), cipher_id, "doc.pdf".to_owned(), 1024, None);
        let legacy_path = att.get_file_path();
        assert!(!legacy_path.contains("tenants/"));

        att.tenant_id = Some("org-alpha".to_owned());
        let tenant_path = att.get_file_path();
        assert!(
            tenant_path.ends_with("tenants/org-alpha/attachments/11111111-2222-3333-4444-555555555555/att-id-1"),
            "unexpected tenant attachment path: {tenant_path}"
        );

        let mut send = SendModel::new(
            SendType::File as i32,
            "n".to_owned(),
            "d".to_owned(),
            "k".to_owned(),
            Utc::now().naive_utc(),
        );
        send.tenant_id = Some("org-alpha".to_owned());
        let send_path = send.get_file_path("file-1");
        assert!(send_path.contains("tenants/org-alpha/sends/"), "unexpected tenant send path: {send_path}");
    }

    #[test]
    fn pg_pubsub_rejects_unsafe_channel_identifiers() {
        assert!(pubsub::is_safe_pg_ident("kyvault_notify"));
        assert!(pubsub::is_safe_pg_ident("tenant_chan_01"));
        assert!(!pubsub::is_safe_pg_ident(""));
        assert!(!pubsub::is_safe_pg_ident("kyvault; DROP TABLE users;--"));
        assert!(!pubsub::is_safe_pg_ident("bad-hyphen"));
    }
}
