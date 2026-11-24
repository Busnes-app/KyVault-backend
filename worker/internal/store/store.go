package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store encapsulates all PostgreSQL persistence for kyvault-worker.
type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.pool.QueryRow(ctx, "SELECT 1").Scan(&one)
}

// TenantRecord mirrors the tenants table.
type TenantRecord struct {
	ID               string
	Status           string
	HomeRegion       string
	AppEnabled       bool
	Revision         int64
	QuotasJSON       string
	StoragePoolBytes int64
	StorageOverSince *int64
	PrimaryOrgUUID   *string
}

// UpsertTenant applies an authoritative tenant snapshot from KyIdentity without
// ever resurrecting a deleted/erasing tenant or regressing to an older revision.
// Returns (fenced=true) if the tenant transitioned into or remains in a non-active state
// requiring session eviction.
func (s *Store) UpsertTenant(ctx context.Context, rec TenantRecord) (bool, error) {
	if strings.TrimSpace(rec.ID) == "" {
		return false, errors.New("tenant id is required")
	}
	if rec.QuotasJSON == "" {
		rec.QuotasJSON = "{}"
	}
	if rec.Status == "" {
		rec.Status = "active"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var prevStatus string
	var prevRev int64
	var prevEnabled bool
	err = tx.QueryRow(
		ctx,
		"SELECT status, revision, app_enabled FROM tenants WHERE id = $1 FOR UPDATE",
		rec.ID,
	).Scan(&prevStatus, &prevRev, &prevEnabled)
	exists := true
	if errors.Is(err, pgx.ErrNoRows) {
		exists = false
	} else if err != nil {
		return false, err
	}

	// Never resurrect an erasing or deleted tenant tombstone.
	if exists && (prevStatus == "deleted" || prevStatus == "erasing") {
		if rec.Status != "deleted" && rec.Status != "erasing" {
			return false, tx.Commit(ctx)
		}
	}
	// Reject stale out-of-order revisions when revision > 0.
	if exists && rec.Revision > 0 && prevRev > 0 && rec.Revision < prevRev {
		return false, tx.Commit(ctx)
	}

	if !exists {
		_, err = tx.Exec(ctx, `
			INSERT INTO tenants (
				id, status, home_region, app_enabled, revision, quotas_json,
				storage_pool_bytes, storage_over_since, primary_org_uuid, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		`, rec.ID, rec.Status, rec.HomeRegion, rec.AppEnabled, rec.Revision, rec.QuotasJSON,
			rec.StoragePoolBytes, rec.StorageOverSince, rec.PrimaryOrgUUID)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE tenants
			SET status = $2,
			    home_region = CASE WHEN $3 <> '' THEN $3 ELSE home_region END,
			    app_enabled = $4,
			    revision = GREATEST(revision, $5),
			    quotas_json = $6,
			    storage_pool_bytes = $7,
			    storage_over_since = $8,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = $1
		`, rec.ID, rec.Status, rec.HomeRegion, rec.AppEnabled, rec.Revision, rec.QuotasJSON,
			rec.StoragePoolBytes, rec.StorageOverSince)
	}
	if err != nil {
		return false, err
	}

	fenced := !rec.AppEnabled || rec.Status == "suspended" || rec.Status == "disabled" ||
		rec.Status == "erasing" || rec.Status == "deleted"
	newlyFenced := fenced && (!exists || (prevEnabled && prevStatus == "active"))

	if newlyFenced {
		if err := fenceTenantTx(ctx, tx, rec.ID); err != nil {
			return false, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return newlyFenced, nil
}

// MarkTenantStatus updates tenant status (e.g. from webhook) and fences sessions when needed.
func (s *Store) MarkTenantStatus(ctx context.Context, tenantID, status string, appEnabled *bool) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var prevStatus string
	err = tx.QueryRow(ctx, "SELECT status FROM tenants WHERE id = $1 FOR UPDATE", tenantID).Scan(&prevStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		enabled := status == "active"
		if appEnabled != nil {
			enabled = *appEnabled
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO tenants (id, status, home_region, app_enabled, revision, quotas_json, storage_pool_bytes, created_at, updated_at)
			VALUES ($1, $2, '', $3, 0, '{}', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		`, tenantID, status, enabled)
		if err != nil {
			return false, err
		}
	} else if err != nil {
		return false, err
	} else {
		if (prevStatus == "deleted" || prevStatus == "erasing") && status != "deleted" && status != "erasing" {
			return false, tx.Commit(ctx)
		}
		if appEnabled != nil {
			_, err = tx.Exec(ctx, `
				UPDATE tenants SET status = $2, app_enabled = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $1
			`, tenantID, status, *appEnabled)
		} else {
			_, err = tx.Exec(ctx, `
				UPDATE tenants SET status = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1
			`, tenantID, status)
		}
		if err != nil {
			return false, err
		}
	}

	fenced := status != "active" || (appEnabled != nil && !*appEnabled)
	if fenced {
		if err := fenceTenantTx(ctx, tx, tenantID); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return fenced, nil
}

func fenceTenantTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	// Rotate security_stamp for every user in the tenant (using unique UUID per user)
	// and revoke all device refresh tokens so JWTs/refresh fail immediately.
	rows, err := tx.Query(ctx, "SELECT uuid FROM users WHERE tenant_id = $1", tenantID)
	if err != nil {
		return err
	}
	var userIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		userIDs = append(userIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, uid := range userIDs {
		if _, err := tx.Exec(ctx, "UPDATE users SET security_stamp = $2 WHERE uuid = $1", uid, uuid.NewString()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE devices SET refresh_token = '' WHERE user_uuid = $1", uid); err != nil {
			return err
		}
	}
	return nil
}

// ClaimEvent atomically claims an idempotency/replay key in tenant_processed_events.
// Returns true if this caller claimed it (first time seen), false on duplicate/replay.
func (s *Store) ClaimEvent(ctx context.Context, eventID, eventType string, expiresAt int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO tenant_processed_events (event_id, event_type, expires_at, processed_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
		ON CONFLICT (event_id) DO NOTHING
	`, eventID, eventType, expiresAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// IsEventProcessed returns true if eventID exists in tenant_processed_events (e.g. erasure tombstone).
func (s *Store) IsEventProcessed(ctx context.Context, eventID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM tenant_processed_events WHERE event_id = $1)", eventID).Scan(&exists)
	return exists, err
}

// PruneExpiredEvents removes expired replay-guard rows while leaving far-future tombstones intact.
func (s *Store) PruneExpiredEvents(ctx context.Context, nowUnix int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, "DELETE FROM tenant_processed_events WHERE expires_at > 0 AND expires_at < $1", nowUnix)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// SyncCursor tracks monotonic polling cursors in tenant_sync_cursors.
type SyncCursor struct {
	Name     string
	Revision int64
	AfterID  string
}

func (s *Store) GetCursor(ctx context.Context, name string) (SyncCursor, error) {
	var c SyncCursor
	c.Name = name
	err := s.pool.QueryRow(ctx, "SELECT revision, after_id FROM tenant_sync_cursors WHERE name = $1", name).Scan(&c.Revision, &c.AfterID)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	return c, err
}

func (s *Store) SaveCursor(ctx context.Context, c SyncCursor) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tenant_sync_cursors (name, revision, after_id, updated_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
		ON CONFLICT (name) DO UPDATE
		SET revision = GREATEST(tenant_sync_cursors.revision, EXCLUDED.revision),
		    after_id = EXCLUDED.after_id,
		    updated_at = CURRENT_TIMESTAMP
	`, c.Name, c.Revision, c.AfterID)
	return err
}

// NextSequence atomically increments and returns a monotonic integer sequence stored in tenant_sync_cursors.
func (s *Store) NextSequence(ctx context.Context, name string) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant_sync_cursors (name, revision, after_id, updated_at)
		VALUES ($1, 1, '', CURRENT_TIMESTAMP)
		ON CONFLICT (name) DO UPDATE
		SET revision = tenant_sync_cursors.revision + 1,
		    updated_at = CURRENT_TIMESTAMP
		RETURNING revision
	`, name).Scan(&seq)
	return seq, err
}

// FindUserUUIDBySubject resolves a KyIdentity OIDC subject (sso_users.identifier, users.external_id, users.uuid) or email to a local user UUID.
func (s *Store) FindUserUUIDBySubject(ctx context.Context, subject, email string) (string, string, error) {
	if subject != "" {
		var uid string
		var tid *string
		err := s.pool.QueryRow(ctx, `
			SELECT u.uuid, u.tenant_id
			FROM sso_users su
			JOIN users u ON u.uuid = su.user_uuid
			WHERE su.identifier = $1
			LIMIT 1
		`, subject).Scan(&uid, &tid)
		if err == nil {
			return uid, deref(tid), nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", "", err
		}
		// Fallback: direct match on users.external_id or users.uuid
		err = s.pool.QueryRow(ctx, "SELECT uuid, tenant_id FROM users WHERE external_id = $1 OR uuid = $1 LIMIT 1", subject).Scan(&uid, &tid)
		if err == nil {
			return uid, deref(tid), nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", "", err
		}
	}
	if email != "" {
		var uid string
		var tid *string
		err := s.pool.QueryRow(ctx, "SELECT uuid, tenant_id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1", email).Scan(&uid, &tid)
		if err == nil {
			return uid, deref(tid), nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", "", err
		}
	}
	return "", "", pgx.ErrNoRows
}

// RevokeUserSessions rotates users.security_stamp and clears all device refresh tokens.
// If disableUser is true, also sets users.enabled = false.
func (s *Store) RevokeUserSessions(ctx context.Context, userUUID string, disableUser bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if disableUser {
		if _, err := tx.Exec(ctx, "UPDATE users SET enabled = FALSE, security_stamp = $2 WHERE uuid = $1", userUUID, uuid.NewString()); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, "UPDATE users SET security_stamp = $2 WHERE uuid = $1", userUUID, uuid.NewString()); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, "UPDATE devices SET refresh_token = '' WHERE user_uuid = $1", userUUID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UpdateUserProfile updates enabled/name for an existing non-erased user.
func (s *Store) UpdateUserProfile(ctx context.Context, userUUID, displayName string, active bool) error {
	if !active {
		return s.RevokeUserSessions(ctx, userUUID, true)
	}
	if displayName != "" {
		_, err := s.pool.Exec(ctx, "UPDATE users SET enabled = TRUE, name = $2 WHERE uuid = $1", userUUID, displayName)
		return err
	}
	_, err := s.pool.Exec(ctx, "UPDATE users SET enabled = TRUE WHERE uuid = $1", userUUID)
	return err
}

// EraseUserPersonalData permanently purges a user's personal vault, attachments, devices,
// recovery bundles, SSO links, and user row while preserving tenant-owned shared org ciphers.
// Returns attachment paths (relative to tenant/storage root) to delete from object storage.
func (s *Store) EraseUserPersonalData(ctx context.Context, userUUID, subjectKey string) (string, []string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback(ctx)

	var tenantID *string
	err = tx.QueryRow(ctx, "SELECT tenant_id FROM users WHERE uuid = $1 FOR UPDATE", userUUID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Record permanent tombstone even if user wasn't present locally.
		if subjectKey != "" {
			_, _ = tx.Exec(ctx, `
				INSERT INTO tenant_processed_events (event_id, event_type, expires_at, processed_at)
				VALUES ($1, 'user.erased', 253402300799, CURRENT_TIMESTAMP)
				ON CONFLICT (event_id) DO NOTHING
			`, "erased_user:"+subjectKey)
		}
		return "", nil, tx.Commit(ctx)
	}
	if err != nil {
		return "", nil, err
	}
	tid := deref(tenantID)

	// Collect personal-cipher attachment paths (do NOT touch organization ciphers!).
	rows, err := tx.Query(ctx, `
		SELECT a.cipher_uuid, a.id
		FROM attachments a
		JOIN ciphers c ON c.uuid = a.cipher_uuid
		WHERE c.user_uuid = $1 AND c.organization_uuid IS NULL
	`, userUUID)
	if err != nil {
		return "", nil, err
	}
	var objKeys []string
	for rows.Next() {
		var cipherID, attID string
		if err := rows.Scan(&cipherID, &attID); err != nil {
			rows.Close()
			return "", nil, err
		}
		if tid != "" {
			objKeys = append(objKeys, fmt.Sprintf("tenants/%s/attachments/%s/%s", tid, cipherID, attID))
		}
	}
	rows.Close()

	// Collect user's personal send directories.
	sendRows, err := tx.Query(ctx, "SELECT uuid FROM sends WHERE user_uuid = $1", userUUID)
	if err != nil {
		return "", nil, err
	}
	for sendRows.Next() {
		var sendID string
		if err := sendRows.Scan(&sendID); err != nil {
			sendRows.Close()
			return "", nil, err
		}
		if tid != "" {
			objKeys = append(objKeys, fmt.Sprintf("tenants/%s/sends/%s/", tid, sendID))
		}
	}
	sendRows.Close()

	// Delete personal data only; preserve ciphers where organization_uuid IS NOT NULL.
	stmts := []string{
		"DELETE FROM attachments WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE user_uuid = $1 AND organization_uuid IS NULL)",
		"DELETE FROM folders_ciphers WHERE folder_uuid IN (SELECT uuid FROM folders WHERE user_uuid = $1)",
		"DELETE FROM favorites WHERE user_uuid = $1",
		"DELETE FROM ciphers WHERE user_uuid = $1 AND organization_uuid IS NULL",
		"DELETE FROM folders WHERE user_uuid = $1",
		"DELETE FROM sends WHERE user_uuid = $1",
		"DELETE FROM devices WHERE user_uuid = $1",
		"DELETE FROM twofactor WHERE user_uuid = $1",
		"DELETE FROM twofactor_incomplete WHERE user_uuid = $1",
		"DELETE FROM twofactor_duo_ctx WHERE user_email IN (SELECT email FROM users WHERE uuid = $1)",
		"DELETE FROM auth_requests WHERE user_uuid = $1",
		"DELETE FROM sso_users WHERE user_uuid = $1",
		"DELETE FROM emergency_access WHERE grantor_uuid = $1 OR grantee_uuid = $1",
		"DELETE FROM users_collections WHERE user_uuid = $1",
		"DELETE FROM groups_users WHERE users_organizations_uuid IN (SELECT uuid FROM users_organizations WHERE user_uuid = $1)",
		"DELETE FROM users_organizations WHERE user_uuid = $1",
		"DELETE FROM tenant_recovery_bundles WHERE user_uuid = $1",
		"DELETE FROM archives WHERE user_uuid = $1",
		"DELETE FROM users WHERE uuid = $1",
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(ctx, stmt, userUUID); err != nil {
			return "", nil, fmt.Errorf("erase user stmt %q: %w", stmt, err)
		}
	}

	// Permanent tombstone (year 9999) so replayed sync events can never resurrect this user.
	if subjectKey != "" {
		_, err = tx.Exec(ctx, `
			INSERT INTO tenant_processed_events (event_id, event_type, expires_at, processed_at)
			VALUES ($1, 'user.erased', 253402300799, CURRENT_TIMESTAMP)
			ON CONFLICT (event_id) DO NOTHING
		`, "erased_user:"+subjectKey)
		if err != nil {
			return "", nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", nil, err
	}
	return tid, objKeys, nil
}

// BeginTenantErasure marks a tenant as 'erasing' and fences all its users/devices.
// Must succeed before object storage deletion begins.
func (s *Store) BeginTenantErasure(ctx context.Context, tenantID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO tenants (id, status, home_region, app_enabled, revision, quotas_json, storage_pool_bytes, created_at, updated_at, deleted_at)
		VALUES ($1, 'erasing', '', FALSE, 0, '{}', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO UPDATE
		SET status = CASE WHEN tenants.status = 'deleted' THEN 'deleted' ELSE 'erasing' END,
		    app_enabled = FALSE,
		    deleted_at = COALESCE(tenants.deleted_at, CURRENT_TIMESTAMP),
		    updated_at = CURRENT_TIMESTAMP
	`, tenantID)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "UPDATE users SET enabled = FALSE WHERE tenant_id = $1", tenantID); err != nil {
		return err
	}
	if err := fenceTenantTx(ctx, tx, tenantID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CompleteTenantDBPurge atomically removes all database rows belonging to tenantID
// and transitions tenants.status to 'deleted' with erased_at timestamp (preserving the tombstone row).
// Call ONLY after object storage under tenants/<tenantID>/ has been verified deleted.
func (s *Store) CompleteTenantDBPurge(ctx context.Context, tenantID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Lock tenant row first to serialize with any concurrent writer.
	var status string
	err = tx.QueryRow(ctx, "SELECT status FROM tenants WHERE id = $1 FOR UPDATE", tenantID).Scan(&status)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if status == "deleted" {
		return tx.Commit(ctx)
	}

	stmts := []string{
		"DELETE FROM attachments WHERE tenant_id = $1 OR cipher_uuid IN (SELECT uuid FROM ciphers WHERE tenant_id = $1)",
		"DELETE FROM ciphers_collections WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE tenant_id = $1) OR collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid IN (SELECT uuid FROM organizations WHERE tenant_id = $1))",
		"DELETE FROM folders_ciphers WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE tenant_id = $1) OR folder_uuid IN (SELECT uuid FROM folders WHERE user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1))",
		"DELETE FROM favorites WHERE user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1) OR cipher_uuid IN (SELECT uuid FROM ciphers WHERE tenant_id = $1)",
		"DELETE FROM ciphers WHERE tenant_id = $1",
		"DELETE FROM collections_groups WHERE collections_uuid IN (SELECT uuid FROM collections WHERE org_uuid IN (SELECT uuid FROM organizations WHERE tenant_id = $1))",
		"DELETE FROM users_collections WHERE user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1) OR collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid IN (SELECT uuid FROM organizations WHERE tenant_id = $1))",
		"DELETE FROM collections WHERE org_uuid IN (SELECT uuid FROM organizations WHERE tenant_id = $1)",
		"DELETE FROM groups_users WHERE groups_uuid IN (SELECT uuid FROM groups WHERE organizations_uuid IN (SELECT uuid FROM organizations WHERE tenant_id = $1))",
		"DELETE FROM groups WHERE organizations_uuid IN (SELECT uuid FROM organizations WHERE tenant_id = $1)",
		"DELETE FROM org_policies WHERE org_uuid IN (SELECT uuid FROM organizations WHERE tenant_id = $1)",
		"DELETE FROM organization_api_key WHERE org_uuid IN (SELECT uuid FROM organizations WHERE tenant_id = $1)",
		"DELETE FROM event WHERE org_uuid IN (SELECT uuid FROM organizations WHERE tenant_id = $1) OR user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM sends WHERE tenant_id = $1 OR user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM emergency_access WHERE grantor_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1) OR grantee_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM devices WHERE user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM twofactor WHERE user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM twofactor_incomplete WHERE user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM twofactor_duo_ctx WHERE user_email IN (SELECT email FROM users WHERE tenant_id = $1)",
		"DELETE FROM auth_requests WHERE user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM sso_users WHERE tenant_id = $1 OR user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM folders WHERE user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM users_organizations WHERE org_uuid IN (SELECT uuid FROM organizations WHERE tenant_id = $1) OR user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM invitations WHERE email IN (SELECT email FROM users WHERE tenant_id = $1)",
		"DELETE FROM tenant_recovery_bundles WHERE tenant_id = $1",
		"DELETE FROM archives WHERE user_uuid IN (SELECT uuid FROM users WHERE tenant_id = $1)",
		"DELETE FROM organizations WHERE tenant_id = $1",
		"DELETE FROM users WHERE tenant_id = $1",
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(ctx, stmt, tenantID); err != nil {
			return fmt.Errorf("purge tenant %s stmt %q: %w", tenantID, stmt, err)
		}
	}

	_, err = tx.Exec(ctx, `
		UPDATE tenants
		SET status = 'deleted',
		    app_enabled = FALSE,
		    primary_org_uuid = NULL,
		    erased_at = CURRENT_TIMESTAMP,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`, tenantID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ListErasingTenants returns tenant IDs stuck in 'erasing' status so retries finish cleanly.
func (s *Store) ListErasingTenants(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, "SELECT id FROM tenants WHERE status = 'erasing'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// TenantUsage holds canonical storage & object metering figures for one tenant.
type TenantUsage struct {
	TenantID         string `json:"org_id"`
	AttachmentBytes  int64  `json:"attachment_bytes"`
	SendFileBytes    int64  `json:"send_file_bytes"`
	CipherDataBytes  int64  `json:"cipher_data_bytes"`
	TotalUsedBytes   int64  `json:"used_bytes"`
	CipherCount      int64  `json:"cipher_count"`
	ActiveUserCount  int64  `json:"user_count"`
	ReportedAt       string `json:"reported_at"`
}

// ComputeTenantUsage calculates canonical storage usage across all non-deleted tenants.
func (s *Store) ComputeTenantUsage(ctx context.Context) ([]TenantUsage, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			t.id,
			COALESCE((SELECT SUM(a.file_size)::BIGINT FROM attachments a WHERE a.tenant_id = t.id), 0) AS att_bytes,
			COALESCE((SELECT SUM(OCTET_LENGTH(c.data))::BIGINT FROM ciphers c WHERE c.tenant_id = t.id), 0) AS cipher_bytes,
			COALESCE((SELECT COUNT(*)::BIGINT FROM ciphers c WHERE c.tenant_id = t.id AND c.deleted_at IS NULL), 0) AS cipher_cnt,
			COALESCE((SELECT COUNT(*)::BIGINT FROM users u WHERE u.tenant_id = t.id AND u.enabled = TRUE), 0) AS user_cnt
		FROM tenants t
		WHERE t.status <> 'deleted'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nowRFC3339 := time.Now().UTC().Format(time.RFC3339)
	var out []TenantUsage
	for rows.Next() {
		var u TenantUsage
		if err := rows.Scan(&u.TenantID, &u.AttachmentBytes, &u.CipherDataBytes, &u.CipherCount, &u.ActiveUserCount); err != nil {
			return nil, err
		}
		u.ReportedAt = nowRFC3339
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Add send file sizes (stored as JSON in sends.data).
	for i := range out {
		sRows, err := s.pool.Query(ctx, "SELECT data FROM sends WHERE tenant_id = $1 AND atype = 1", out[i].TenantID)
		if err != nil {
			return nil, err
		}
		var sendBytes int64
		for sRows.Next() {
			var raw string
			if err := sRows.Scan(&raw); err == nil {
				sendBytes += parseSendSize(raw)
			}
		}
		sRows.Close()
		out[i].SendFileBytes = sendBytes
		out[i].TotalUsedBytes = out[i].AttachmentBytes + out[i].SendFileBytes + out[i].CipherDataBytes
	}

	return out, nil
}

func parseSendSize(raw string) int64 {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return 0
	}
	for _, k := range []string{"size", "Size"} {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				if n > 0 {
					return int64(n)
				}
			case string:
				var parsed int64
				if _, err := fmt.Sscanf(n, "%d", &parsed); err == nil && parsed > 0 {
					return parsed
				}
			}
		}
	}
	return 0
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
