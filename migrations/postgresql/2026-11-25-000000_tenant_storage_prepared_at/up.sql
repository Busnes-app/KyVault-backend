-- Last time a storage report was handed out, so failing tenants rotate behind the rest.
ALTER TABLE tenants ADD COLUMN storage_prepared_at BIGINT;
