pub mod pubsub;

use rocket::http::Method;

use crate::{
    CONFIG,
    api::EmptyResult,
    db::{
        DbConn,
        models::{Tenant, User},
    },
};

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
/// and is active (or export-readable when `export_only` is true).
pub async fn check_tenant_active(
    tenant_id: &str,
    export_only: bool,
    conn: &DbConn,
) -> Result<Tenant, crate::Error> {
    let Some(tenant) = Tenant::find_by_id(tenant_id, conn).await else {
        err_code!("Tenant not found or not provisioned in this region", 403);
    };

    let home_region = CONFIG.home_region();
    if !home_region.trim().is_empty()
        && !tenant.home_region.trim().is_empty()
        && tenant.home_region != home_region
    {
        warn!(
            "Tenant {tenant_id} belongs to region '{}', rejected by region '{home_region}'",
            tenant.home_region
        );
        err_code!("Tenant belongs to a different region", 403);
    }

    if !tenant.app_enabled {
        err_code!("Password manager is disabled for this organization", 403);
    }

    if export_only {
        if !tenant.is_export_readable() {
            err_code!("Tenant export window is closed", 403);
        }
    } else if !tenant.is_active() {
        err_code!(format!("Tenant is not active (status: {})", tenant.status), 403);
    }

    Ok(tenant)
}

/// Allowlist of read/export endpoints permitted during an `export_only` session
/// (e.g., member export grace window after account-holder deletion).
pub fn is_export_only_route_allowed(method: Method, path: &str) -> bool {
    if method != Method::Get {
        return false;
    }
    let basepath = CONFIG.domain_path();
    let stripped = path.strip_prefix(&basepath).unwrap_or(path);
    matches!(
        stripped,
        "/api/sync"
            | "/api/ciphers"
            | "/api/accounts/profile"
            | "/api/accounts/revision-date"
            | "/api/tenancy/status"
            | "/api/tenancy/recovery/status"
            | "/api/tenancy/recovery/kit"
            | "/api/tenancy/recovery/personal"
    ) || stripped.starts_with("/api/ciphers/")
        || stripped.starts_with("/attachments/")
        || (stripped.starts_with("/api/organizations/") && stripped.ends_with("/export"))
}

/// Enforces tenant-level storage quota (attachments + send files) in multi-tenant mode.
pub async fn check_storage_quota(user: &User, additional_bytes: i64, conn: &DbConn) -> EmptyResult {
    if !CONFIG.is_multi_tenant() {
        return Ok(());
    }
    let tenant_id = require_user_tenant(user)?;
    let tenant = check_tenant_active(tenant_id, false, conn).await?;
    let used = Tenant::storage_used_bytes(tenant_id, conn).await;
    if tenant.is_storage_over_quota(used, additional_bytes.max(0)) {
        err_code!(
            "Organization storage quota exceeded. Free up space or upgrade storage pool to upload more files.",
            403
        );
    }
    Ok(())
}

/// Enforces tenant-level active cipher quota in multi-tenant mode.
pub async fn check_cipher_quota(user: &User, additional_ciphers: i64, conn: &DbConn) -> EmptyResult {
    if !CONFIG.is_multi_tenant() {
        return Ok(());
    }
    let tenant_id = require_user_tenant(user)?;
    let tenant = check_tenant_active(tenant_id, false, conn).await?;
    let max_ciphers = tenant
        .max_ciphers_quota()
        .unwrap_or_else(|| CONFIG.tenancy_max_ciphers_per_tenant());
    if max_ciphers <= 0 {
        return Ok(());
    }
    let current = Tenant::cipher_count(tenant_id, conn).await;
    if current.saturating_add(additional_ciphers.max(0)) > max_ciphers {
        err_code!(
            format!("Organization cipher quota exceeded (limit: {max_ciphers})"),
            403
        );
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
        err_code!(
            format!("Import batch exceeds maximum of {max_ciphers} ciphers per request"),
            400
        );
    }
    let max_folders = CONFIG.tenancy_max_import_folders();
    if folder_count > max_folders {
        err_code!(
            format!("Import batch exceeds maximum of {max_folders} folders per request"),
            400
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::{
        Attachment, AttachmentId, CipherId, Send as SendModel, SendType, Tenant, TENANT_STATUS_ACTIVE,
        TENANT_STATUS_DELETED, TENANT_STATUS_ERASING, TENANT_STATUS_SUSPENDED,
    };

    #[test]
    fn export_only_route_allowlist_blocks_mutations() {
        assert!(is_export_only_route_allowed(Method::Get, "/api/sync"));
        assert!(is_export_only_route_allowed(Method::Get, "/api/ciphers/abc/attachment/def"));
        assert!(is_export_only_route_allowed(Method::Get, "/api/organizations/123/export"));
        assert!(is_export_only_route_allowed(Method::Get, "/api/tenancy/status"));
        assert!(is_export_only_route_allowed(Method::Get, "/api/tenancy/recovery/personal"));
        assert!(is_export_only_route_allowed(Method::Get, "/attachments/abc/def"));
        assert!(!is_export_only_route_allowed(Method::Post, "/api/ciphers"));
        assert!(!is_export_only_route_allowed(Method::Put, "/api/ciphers/abc"));
        assert!(!is_export_only_route_allowed(Method::Delete, "/api/ciphers/abc"));
        assert!(!is_export_only_route_allowed(Method::Post, "/api/ciphers/import"));
        assert!(!is_export_only_route_allowed(Method::Post, "/api/sends"));
        assert!(!is_export_only_route_allowed(Method::Post, "/api/organizations"));
        assert!(!is_export_only_route_allowed(Method::Put, "/api/tenancy/recovery/personal"));
    }

    #[test]
    fn tenant_status_and_quota_helpers() {
        let mut t = Tenant::new("org-test".to_owned(), "us-east-1".to_owned());
        assert!(t.is_active());
        assert!(!t.is_storage_over_quota(0, 1024));
        assert_eq!(t.max_ciphers_quota(), None);

        t.status = TENANT_STATUS_SUSPENDED.to_owned();
        assert!(!t.is_active());
        t.status = TENANT_STATUS_ERASING.to_owned();
        assert!(!t.is_active());
        t.status = TENANT_STATUS_DELETED.to_owned();
        assert!(!t.is_active());

        t.status = TENANT_STATUS_ACTIVE.to_owned();
        t.app_enabled = false;
        assert!(!t.is_active());

        t.app_enabled = true;
        t.storage_pool_bytes = 10_000;
        assert!(!t.is_storage_over_quota(5_000, 4_000));
        assert!(t.is_storage_over_quota(5_000, 5_001));
        t.storage_over_since = Some(1_700_000_000);
        assert!(t.is_storage_over_quota(0, 1));

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
            chrono::Utc::now().naive_utc(),
        );
        send.tenant_id = Some("org-alpha".to_owned());
        let send_path = send.get_file_path("file-1");
        assert!(
            send_path.contains("tenants/org-alpha/sends/"),
            "unexpected tenant send path: {send_path}"
        );
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
