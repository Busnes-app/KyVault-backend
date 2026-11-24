-- Multi-tenant foundation tables and nullable tenant_id columns (SQLite compatibility).

CREATE TABLE tenants (
    id TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    home_region TEXT NOT NULL DEFAULT '',
    app_enabled BOOLEAN NOT NULL DEFAULT 1,
    revision BIGINT NOT NULL DEFAULT 0,
    quotas_json TEXT NOT NULL DEFAULT '{}',
    storage_pool_bytes BIGINT NOT NULL DEFAULT 0,
    storage_over_since BIGINT,
    primary_org_uuid TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME,
    erased_at DATETIME
);

CREATE TABLE tenant_sync_cursors (
    name TEXT PRIMARY KEY NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0,
    after_id TEXT NOT NULL DEFAULT '',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tenant_processed_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    event_type TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    processed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tenant_recovery_bundles (
    uuid TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL,
    user_uuid TEXT NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    bundle_type TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    kdf_params_json TEXT NOT NULL,
    wrapped_user_key TEXT NOT NULL,
    wrapped_private_key TEXT,
    recovery_key_hint TEXT,
    escrow_org_uuid TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME
);

ALTER TABLE users ADD COLUMN tenant_id TEXT;
CREATE INDEX idx_users_tenant_id ON users (tenant_id);

ALTER TABLE organizations ADD COLUMN tenant_id TEXT;
CREATE INDEX idx_organizations_tenant_id ON organizations (tenant_id);

ALTER TABLE ciphers ADD COLUMN tenant_id TEXT;
CREATE INDEX idx_ciphers_tenant_id ON ciphers (tenant_id);

ALTER TABLE attachments ADD COLUMN tenant_id TEXT;
CREATE INDEX idx_attachments_tenant_id ON attachments (tenant_id);

ALTER TABLE sends ADD COLUMN tenant_id TEXT;
CREATE INDEX idx_sends_tenant_id ON sends (tenant_id);

ALTER TABLE sso_users ADD COLUMN tenant_id TEXT;
CREATE INDEX idx_sso_users_tenant_id ON sso_users (tenant_id);
