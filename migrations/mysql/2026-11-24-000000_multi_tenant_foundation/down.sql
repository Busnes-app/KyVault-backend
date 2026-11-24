ALTER TABLE sso_users DROP COLUMN tenant_id;
ALTER TABLE sends DROP COLUMN tenant_id;
ALTER TABLE attachments DROP COLUMN tenant_id;
ALTER TABLE ciphers DROP COLUMN tenant_id;
ALTER TABLE organizations DROP COLUMN tenant_id;
ALTER TABLE users DROP COLUMN tenant_id;

DROP TABLE IF EXISTS tenant_recovery_bundles;
DROP TABLE IF EXISTS tenant_processed_events;
DROP TABLE IF EXISTS tenant_sync_cursors;
DROP TABLE IF EXISTS tenants;
