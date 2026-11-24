-- Multi-tenant foundation tables and nullable tenant_id columns (MySQL compatibility).

CREATE TABLE tenants (
    id VARCHAR(64) PRIMARY KEY NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    home_region VARCHAR(64) NOT NULL DEFAULT '',
    app_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 0,
    quotas_json TEXT NOT NULL,
    storage_pool_bytes BIGINT NOT NULL DEFAULT 0,
    storage_ceiling_bytes BIGINT NOT NULL DEFAULT 0,
    storage_reserved_bytes BIGINT NOT NULL DEFAULT 0,
    storage_grant_expires_at BIGINT,
    storage_org_used_bytes BIGINT NOT NULL DEFAULT 0,
    storage_over_since BIGINT,
    storage_report_seq BIGINT NOT NULL DEFAULT 0,
    storage_last_applied_seq BIGINT NOT NULL DEFAULT 0,
    storage_pending_seq BIGINT,
    storage_pending_used_bytes BIGINT,
    storage_seq_stale BOOLEAN NOT NULL DEFAULT FALSE,
    authority_refreshed_at BIGINT,
    access_epoch BIGINT NOT NULL DEFAULT 1,
    primary_org_uuid CHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME,
    erased_at DATETIME
);

CREATE TABLE tenant_erased_subjects (
    issuer VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0,
    erased_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (issuer, subject)
);

CREATE TABLE tenant_pending_deletions (
    id CHAR(36) PRIMARY KEY NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    user_uuid CHAR(36),
    storage_kind VARCHAR(32) NOT NULL,
    object_key VARCHAR(512) NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tenant_recovery_bundles (
    uuid CHAR(36) PRIMARY KEY NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    user_uuid CHAR(36) NOT NULL,
    bundle_type VARCHAR(32) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    kdf_params_json TEXT NOT NULL,
    wrapped_user_key TEXT NOT NULL,
    wrapped_private_key TEXT,
    recovery_key_hint VARCHAR(256),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME,
    FOREIGN KEY (user_uuid) REFERENCES users (uuid) ON DELETE CASCADE
);

ALTER TABLE users ADD COLUMN tenant_id VARCHAR(64);
CREATE INDEX idx_users_tenant_id ON users (tenant_id);

ALTER TABLE organizations ADD COLUMN tenant_id VARCHAR(64);
CREATE INDEX idx_organizations_tenant_id ON organizations (tenant_id);

ALTER TABLE ciphers ADD COLUMN tenant_id VARCHAR(64);
CREATE INDEX idx_ciphers_tenant_id ON ciphers (tenant_id);

ALTER TABLE attachments ADD COLUMN tenant_id VARCHAR(64);
CREATE INDEX idx_attachments_tenant_id ON attachments (tenant_id);

ALTER TABLE sends ADD COLUMN tenant_id VARCHAR(64);
CREATE INDEX idx_sends_tenant_id ON sends (tenant_id);

ALTER TABLE sso_users ADD COLUMN tenant_id VARCHAR(64);
CREATE INDEX idx_sso_users_tenant_id ON sso_users (tenant_id);
