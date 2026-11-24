-- Multi-tenant foundation for KyVault (Busnes hosted password manager).
-- Nullable tenant_id preserves 100% single-tenant Vaultwarden compatibility.

CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'active',
    home_region TEXT NOT NULL DEFAULT '',
    app_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 0,
    quotas_json TEXT NOT NULL DEFAULT '{}',
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
    primary_org_uuid TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    erased_at TIMESTAMP
);

CREATE INDEX idx_tenants_status ON tenants (status);
CREATE INDEX idx_tenants_home_region ON tenants (home_region);

-- Permanent erasure tombstones for deleted/erased OIDC subjects (including
-- subjects unknown locally at erasure time) so they can never be re-provisioned.
CREATE TABLE tenant_erased_subjects (
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0,
    erased_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (issuer, subject)
);

CREATE INDEX idx_tenant_erased_subjects_tenant ON tenant_erased_subjects (tenant_id);

-- Durable storage cleanup manifest populated before DB references are removed.
-- Entries are only deleted after verified storage deletion succeeds.
CREATE TABLE tenant_pending_deletions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_uuid TEXT,
    storage_kind TEXT NOT NULL,
    object_key TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tenant_pending_deletions_tenant ON tenant_pending_deletions (tenant_id);
CREATE INDEX idx_tenant_pending_deletions_user ON tenant_pending_deletions (user_uuid);

-- Strict zero-knowledge personal Recovery Kit bundles (user-only offline key wrap;
-- no server escrow and no administrator recovery of personal vault keys).
CREATE TABLE tenant_recovery_bundles (
    uuid TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_uuid TEXT NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    bundle_type TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    kdf_params_json TEXT NOT NULL,
    wrapped_user_key TEXT NOT NULL,
    wrapped_private_key TEXT,
    recovery_key_hint TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP
);

CREATE UNIQUE INDEX idx_tenant_recovery_bundles_active
    ON tenant_recovery_bundles (tenant_id, user_uuid, bundle_type)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_tenant_recovery_bundles_user ON tenant_recovery_bundles (user_uuid);

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
