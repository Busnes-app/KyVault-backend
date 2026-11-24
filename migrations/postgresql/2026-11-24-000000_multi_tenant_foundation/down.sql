DROP INDEX IF EXISTS idx_sso_users_tenant_id;
ALTER TABLE sso_users DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS idx_sends_tenant_id;
ALTER TABLE sends DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS idx_attachments_tenant_id;
ALTER TABLE attachments DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS idx_ciphers_tenant_id;
ALTER TABLE ciphers DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS idx_organizations_tenant_id;
ALTER TABLE organizations DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS idx_users_tenant_id;
ALTER TABLE users DROP COLUMN IF EXISTS tenant_id;

DROP TABLE IF EXISTS tenant_recovery_bundles;
DROP TABLE IF EXISTS tenant_processed_events;
DROP TABLE IF EXISTS tenant_sync_cursors;
DROP TABLE IF EXISTS tenants;
