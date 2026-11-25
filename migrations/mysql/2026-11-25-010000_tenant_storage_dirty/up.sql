-- Set when usage changes for a tenant that is not otherwise reporting, so it reports once more.
ALTER TABLE tenants ADD COLUMN storage_dirty BOOLEAN NOT NULL DEFAULT FALSE;
