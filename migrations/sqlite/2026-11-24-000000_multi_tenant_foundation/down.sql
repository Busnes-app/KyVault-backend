DROP INDEX IF EXISTS idx_sso_users_tenant_id;
DROP INDEX IF EXISTS idx_sends_tenant_id;
DROP INDEX IF EXISTS idx_attachments_tenant_id;
DROP INDEX IF EXISTS idx_ciphers_tenant_id;
DROP INDEX IF EXISTS idx_organizations_tenant_id;
DROP INDEX IF EXISTS idx_users_tenant_id;

DROP TABLE IF EXISTS tenant_recovery_bundles;
DROP TABLE IF EXISTS tenant_pending_deletions;
DROP TABLE IF EXISTS tenant_erased_subjects;
DROP TABLE IF EXISTS tenants;
