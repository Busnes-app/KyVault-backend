pub mod ops;
pub mod pubsub;

use std::collections::BTreeSet;

use chrono::Utc;

use crate::{
    CONFIG,
    api::EmptyResult,
    db::{
        DbConn,
        models::{Attachment, SsoUser, Tenant, TenantErasedSubject, User},
    },
};

/// Maximum number of cells one app deployment may serve (tenancy design C2 / 32-cell cap).
pub const MAX_SERVED_CELLS: usize = 32;

/// Validates a cell / home_region slug (`^[a-z][a-z0-9-]{1,31}$`).
pub fn is_valid_cell_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    if !(2..=32).contains(&bytes.len()) {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..].iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Parses and validates a comma-separated `KY_CELLS` configuration value.
/// Returns a sorted, deduplicated list of 1..=32 valid cell slugs.
pub fn parse_ky_cells(raw: &str) -> Result<Vec<String>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("`KY_CELLS` must list at least one cell slug when `TENANCY_MODE=multi`".to_owned());
    }
    let mut seen = BTreeSet::new();
    for part in trimmed.split(',') {
        let slug = part.trim();
        if slug.is_empty() {
            return Err("`KY_CELLS` contains an empty entry".to_owned());
        }
        if !is_valid_cell_slug(slug) {
            return Err(format!(
                "`KY_CELLS` contains invalid cell slug '{slug}' (must match ^[a-z][a-z0-9-]{{1,31}}$)"
            ));
        }
        if !seen.insert(slug.to_owned()) {
            return Err(format!("`KY_CELLS` contains duplicate cell slug '{slug}'"));
        }
        if seen.len() > MAX_SERVED_CELLS {
            return Err(format!("`KY_CELLS` exceeds maximum of {MAX_SERVED_CELLS} cells"));
        }
    }
    Ok(seen.into_iter().collect())
}

/// Returns true iff `cell` is a valid slug present in `served_cells`.
/// Always returns false when `cell` or `served_cells` is empty (fail closed).
pub fn is_cell_served(served_cells: &[String], cell: &str) -> bool {
    !cell.is_empty() && is_valid_cell_slug(cell) && served_cells.iter().any(|c| c == cell)
}

/// Cell-scoped attachment object key relative to the attachments root.
pub fn attachment_object_key(cell: &str, tenant_id: &str, cipher_uuid: &str, att_id: &str) -> String {
    format!("cells/{cell}/tenants/{tenant_id}/attachments/{cipher_uuid}/{att_id}")
}

/// Cell-scoped send object key relative to the sends root.
pub fn send_object_key(cell: &str, tenant_id: &str, send_uuid: &str, file_id: &str) -> String {
    format!("cells/{cell}/tenants/{tenant_id}/sends/{send_uuid}/{file_id}")
}

/// Cell-scoped tenant prefix used for whole-tenant sweeps.
pub fn tenant_prefix_object_key(cell: &str, tenant_id: &str) -> String {
    format!("cells/{cell}/tenants/{tenant_id}/")
}

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

/// Pure C5 + active + authority-freshness check for a loaded tenant against a deployment's
/// configured `served_cells`. Always fails closed on empty/unknown/unserved `home_region`.
pub fn check_tenant_active_for_cells(
    tenant: &Tenant,
    served_cells: &[String],
    now_ts: i64,
    max_authority_age_secs: i64,
) -> EmptyResult {
    if !is_cell_served(served_cells, &tenant.home_region) {
        warn!(
            "Tenant {} belongs to cell '{}', refused by deployment serving {:?}",
            tenant.id, tenant.home_region, served_cells
        );
        err_code!("Tenant belongs to a cell not served by this deployment", 403);
    }

    if !tenant.app_enabled {
        err_code!("Password manager is disabled for this organization", 403);
    }

    if !tenant.is_active() {
        err_code!(format!("Tenant is not active (status: {})", tenant.status), 403);
    }

    if !tenant.has_fresh_authority(now_ts, max_authority_age_secs) {
        warn!("Tenant {} authority cache is stale or missing; failing closed", tenant.id);
        err_code!("Tenant authority cache is stale", 503);
    }

    Ok(())
}

/// Verifies that a tenant exists, belongs to one of this deployment's `KY_CELLS`,
/// is active and app-enabled, and has fresh KyIdentity authority (<= 15 min cap).
///
/// Ordinary vault access never accepts `export_only` sessions (Design §4.1 & §11 P3).
pub async fn check_tenant_active(tenant_id: &str, conn: &DbConn) -> Result<Tenant, crate::Error> {
    let Some(tenant) = Tenant::find_by_id(tenant_id, conn).await else {
        err_code!("Tenant not found or not provisioned in this cell", 403);
    };

    let served_cells = CONFIG.served_cells();
    check_tenant_active_for_cells(
        &tenant,
        &served_cells,
        Utc::now().timestamp(),
        CONFIG.tenancy_authority_max_age_secs(),
    )?;
    Ok(tenant)
}

/// Creates a hosted SSO user and its subject link atomically; refused once the subject is erased.
pub async fn provision_sso_user(
    user: User,
    link: SsoUser,
    issuer: &str,
    subject: &str,
    conn: &DbConn,
) -> Result<(User, SsoUser), crate::Error> {
    if !crate::util::is_valid_email(&user.email) {
        err!(format!("User email {} is not a valid email address", user.email.escape_debug()))
    }
    let (issuer, subject) = (issuer.to_owned(), subject.to_owned());
    conn.run(move |conn| {
        TenantErasedSubject::provision_sso_user_inner(
            conn,
            &user,
            &link,
            &issuer,
            &subject,
            &CONFIG.served_cells(),
            Utc::now().timestamp(),
            CONFIG.tenancy_authority_max_age_secs(),
        )?;
        Ok((user, link))
    })
    .await
}

/// Convenience wrapper verifying a user is tenant-bound and their tenant is active in a served cell.
pub async fn require_user_tenant_active(user: &User, conn: &DbConn) -> Result<Tenant, crate::Error> {
    let tid = require_user_tenant(user)?;
    check_tenant_active(tid, conn).await
}

/// Begins a hosted legacy upload: reserves the payload and metadata bytes and stages the
/// in-flight cleanup row in one transaction. Returns `Ok(None)` in single-tenant mode.
pub async fn begin_legacy_attachment_upload(
    user: &User,
    att: &Attachment,
    conn: &DbConn,
) -> Result<Option<crate::db::models::V2UploadLease>, crate::Error> {
    if !CONFIG.is_multi_tenant() {
        return Ok(None);
    }
    let lease = Tenant::begin_legacy_attachment_upload(
        require_user_tenant(user)?,
        Some(user.uuid.clone()),
        att,
        CONFIG.tenancy_authority_max_age_secs(),
        &CONFIG.served_cells(),
        conn,
    )
    .await?;
    Ok(Some(lease))
}

/// Creates an attachment row or updates its file name and key; in multi-tenant mode the growth,
/// metadata included, is checked against the storage grant in the same transaction.
pub async fn put_attachment(user: &User, att: &Attachment, conn: &DbConn) -> EmptyResult {
    if !CONFIG.is_multi_tenant() {
        return att.save(conn).await;
    }
    Tenant::put_attachment_enforcing_grant(
        require_user_tenant(user)?,
        att,
        CONFIG.tenancy_authority_max_age_secs(),
        &CONFIG.served_cells(),
        conn,
    )
    .await
}

/// Abandons a failed hosted upload if it still owns its cleanup row; the cleanup worker deletes
/// the object. A no-op once the worker has taken the upload over.
pub async fn abandon_upload(user: &User, pending_id: &str, v2_att: Option<&Attachment>, conn: &DbConn) {
    if let Ok(tid) = require_user_tenant(user) {
        Tenant::abandon_upload(tid, pending_id, v2_att, conn).await;
    }
}

/// Saves an attachment row; in multi-tenant mode it also verifies `expected_epoch`, releases
/// `reserved` upload bytes, and deletes `clear_pending_id` (if any) in the same transaction.
/// On error nothing is released and any staged cleanup row stays pending.
pub async fn save_attachment_releasing(
    user: &User,
    att: &Attachment,
    reserved: i64,
    expected_epoch: Option<i64>,
    clear_pending_id: Option<&str>,
    conn: &DbConn,
) -> EmptyResult {
    if !CONFIG.is_multi_tenant() {
        return att.save(conn).await;
    }
    Tenant::save_attachment_releasing(require_user_tenant(user)?, att, reserved, expected_epoch, clear_pending_id, conn)
        .await
}

/// Begins a hosted v2 attachment upload atomically under the tenant lock: enforces per-attachment
/// cross-replica upload serialization, computes growth delta from the locked current attachment
/// row, reserves storage, and stages the durable `upload_in_flight` cleanup row.
/// Returns `Ok(None)` in single-tenant mode.
pub async fn begin_v2_attachment_upload(
    user: &User,
    att: &Attachment,
    file_size: i64,
    conn: &DbConn,
) -> Result<Option<crate::db::models::V2UploadLease>, crate::Error> {
    if !CONFIG.is_multi_tenant() {
        return Ok(None);
    }
    let tid = require_user_tenant(user)?;
    let lease = Tenant::begin_v2_attachment_upload(
        tid,
        Some(user.uuid.clone()),
        att,
        file_size,
        CONFIG.tenancy_authority_max_age_secs(),
        &CONFIG.served_cells(),
        conn,
    )
    .await?;
    Ok(Some(lease))
}

/// Finalizes a v2 attachment upload: verifies the attachment row still exists (updating
/// `file_size`), verifies `expected_epoch` in multi-tenant mode, revalidates actual growth against
/// `reserved`, releases `reserved` upload bytes, and clears `clear_pending_id` in one transaction.
/// On error nothing is released and any staged cleanup row stays pending.
pub async fn finalize_v2_attachment_upload(
    user: &User,
    att: &Attachment,
    file_size: i64,
    reserved: i64,
    expected_epoch: Option<i64>,
    clear_pending_id: Option<&str>,
    conn: &DbConn,
) -> EmptyResult {
    if !CONFIG.is_multi_tenant() {
        return att.update_file_size_if_exists(file_size, conn).await;
    }
    Tenant::finalize_v2_attachment_upload(
        require_user_tenant(user)?,
        att,
        file_size,
        reserved,
        expected_epoch,
        clear_pending_id,
        conn,
    )
    .await
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
    fn cell_and_tenant_prefixed_attachment_and_send_paths() {
        let cipher_id = CipherId::from("11111111-2222-3333-4444-555555555555".to_owned());
        let mut att = Attachment::new(AttachmentId("att-id-1".to_owned()), cipher_id, "doc.pdf".to_owned(), 1024, None);
        let legacy_path = att.get_file_path_in_cell(None).unwrap();
        assert!(!legacy_path.contains("tenants/"));
        assert!(!legacy_path.contains("cells/"));

        att.tenant_id = Some("org-alpha".to_owned());
        assert!(att.get_file_path_in_cell(None).is_err(), "multi-tenant key must require a valid cell");
        assert!(att.get_file_path_in_cell(Some("../bad")).is_err());
        let tenant_path = att.get_file_path_in_cell(Some("us-east-2")).unwrap();
        assert!(
            tenant_path.ends_with(
                "cells/us-east-2/tenants/org-alpha/attachments/11111111-2222-3333-4444-555555555555/att-id-1"
            ),
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
        assert!(send.get_file_path_in_cell("file-1", None).is_err());
        let send_path = send.get_file_path_in_cell("file-1", Some("us-east-2")).unwrap();
        assert!(
            send_path.contains("cells/us-east-2/tenants/org-alpha/sends/"),
            "unexpected tenant send path: {send_path}"
        );
    }

    #[test]
    fn parse_ky_cells_validates_slug_format_duplicates_and_bounds() {
        assert_eq!(parse_ky_cells("us-east-1").unwrap(), vec!["us-east-1"]);
        assert_eq!(parse_ky_cells(" us-east-1 , us-east-2 ").unwrap(), vec!["us-east-1", "us-east-2"]);
        assert!(parse_ky_cells("").is_err());
        assert!(parse_ky_cells("   ").is_err());
        assert!(parse_ky_cells("us-east-1,").is_err());
        assert!(parse_ky_cells("us-east-1,us-east-1").is_err());
        assert!(parse_ky_cells("US-EAST-1").is_err());
        assert!(parse_ky_cells("a").is_err());
        assert!(parse_ky_cells("1us-east").is_err());
        assert!(parse_ky_cells("us_east_1").is_err());
        assert!(parse_ky_cells(&"a".repeat(33)).is_err());
        assert!(parse_ky_cells(&"a".repeat(32)).is_ok());

        let max_cells = (1..=MAX_SERVED_CELLS).map(|i| format!("us-east-{i}")).collect::<Vec<_>>().join(",");
        assert_eq!(parse_ky_cells(&max_cells).unwrap().len(), MAX_SERVED_CELLS);
        let too_many = (1..=MAX_SERVED_CELLS + 1).map(|i| format!("us-east-{i}")).collect::<Vec<_>>().join(",");
        assert!(parse_ky_cells(&too_many).is_err());

        let served = parse_ky_cells("us-east-1,us-east-2").unwrap();
        assert!(is_cell_served(&served, "us-east-1"));
        assert!(is_cell_served(&served, "us-east-2"));
        assert!(!is_cell_served(&served, "eu-west-1"));
        assert!(!is_cell_served(&served, ""));
    }

    #[test]
    fn pg_pubsub_rejects_unsafe_channel_identifiers() {
        assert!(pubsub::is_safe_pg_ident("kyvault_notify"));
        assert!(pubsub::is_safe_pg_ident("tenant_chan_01"));
        assert!(!pubsub::is_safe_pg_ident(""));
        assert!(!pubsub::is_safe_pg_ident("kyvault; DROP TABLE users;--"));
        assert!(!pubsub::is_safe_pg_ident("bad-hyphen"));
        assert!(!pubsub::is_safe_pg_ident("KyVault_notify"), "the listener and config share this check");
    }
}
