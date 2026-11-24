DROP INDEX idx_sso_users_tenant_id ON sso_users;
ALTER TABLE sso_users DROP COLUMN tenant_id;

DROP INDEX idx_sends_tenant_id ON sends;
ALTER TABLE sends DROP COLUMN tenant_id;

DROP INDEX idx_attachments_tenant_id ON attachments;
ALTER TABLE attachments DROP COLUMN tenant_id;

DROP INDEX idx_ciphers_tenant_id ON ciphers;
ALTER TABLE ciphers DROP COLUMN tenant_id;

DROP INDEX idx_organizations_tenant_id ON organizations;
ALTER TABLE organizations DROP COLUMN tenant_id;

DROP INDEX idx_users_tenant_id ON users;
ALTER TABLE users DROP COLUMN tenant_id;

DROP TABLE IF EXISTS tenant_recovery_bundles;
DROP TABLE IF EXISTS tenant_pending_deletions;
DROP TABLE IF EXISTS tenant_erased_subjects;
DROP TABLE IF EXISTS tenants;
