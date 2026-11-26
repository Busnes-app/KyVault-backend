package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// schemaLockKey serializes concurrent CREATE ... IF NOT EXISTS from several workers,
// which can otherwise collide on the catalog.
const schemaLockKey = 0x6b797661756c74 // "kyvault"

const schema = `
CREATE TABLE IF NOT EXISTS worker_sync_cursors (
	name       TEXT PRIMARY KEY,
	revision   BIGINT NOT NULL CHECK (revision >= 0),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS worker_known_orgs (
	org_id      TEXT PRIMARY KEY,
	home_region TEXT NOT NULL,
	first_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS worker_processed_events (
	event_key   TEXT PRIMARY KEY,
	kind        TEXT NOT NULL,
	status      TEXT NOT NULL CHECK (status IN ('pending', 'completed')),
	lease_token TEXT,
	lease_until BIGINT NOT NULL DEFAULT 0,
	expires_at  BIGINT NOT NULL,
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS worker_processed_events_expires_at ON worker_processed_events (expires_at);
`

// Postgres is the durable Store, shared by every worker replica.
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres creates the worker's tables if missing. Safe to run concurrently and
// on every start.
func OpenPostgres(ctx context.Context, pool *pgxpool.Pool) (*Postgres, error) {
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(schemaLockKey)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, schema)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("state: create schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Cursor(ctx context.Context, name string) (int64, error) {
	var rev int64
	err := p.pool.QueryRow(ctx, "SELECT revision FROM worker_sync_cursors WHERE name = $1", name).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return rev, err
}

func (p *Postgres) SaveCursor(ctx context.Context, name string, rev int64) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO worker_sync_cursors (name, revision) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE
		SET revision = GREATEST(worker_sync_cursors.revision, EXCLUDED.revision), updated_at = now()`,
		name, rev)
	return err
}

func (p *Postgres) KnownOrgCell(ctx context.Context, orgID string) (string, bool, error) {
	var cell string
	err := p.pool.QueryRow(ctx, "SELECT home_region FROM worker_known_orgs WHERE org_id = $1", orgID).Scan(&cell)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return cell, true, nil
}

func (p *Postgres) RememberOrgCell(ctx context.Context, orgID, cell string) error {
	if orgID == "" || cell == "" {
		return nil
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO worker_known_orgs (org_id, home_region) VALUES ($1, $2)
		ON CONFLICT (org_id) DO NOTHING`,
		orgID, cell)
	return err
}

func (p *Postgres) Claim(ctx context.Context, key, kind, token string, now, leaseUntil, expiresAt time.Time) (Claim, error) {
	var got string
	err := p.pool.QueryRow(ctx, `
		INSERT INTO worker_processed_events (event_key, kind, status, lease_token, lease_until, expires_at)
		VALUES ($1, $2, 'pending', $3, $4, $5)
		ON CONFLICT (event_key) DO UPDATE
		SET lease_token = EXCLUDED.lease_token, lease_until = EXCLUDED.lease_until,
		    expires_at = GREATEST(worker_processed_events.expires_at, EXCLUDED.expires_at), updated_at = now()
		WHERE worker_processed_events.status = 'pending' AND worker_processed_events.lease_until <= $6
		RETURNING event_key`,
		key, kind, token, leaseUntil.Unix(), expiresAt.Unix(), now.Unix()).Scan(&got)
	if err == nil {
		return Claimed, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	var status string
	err = p.pool.QueryRow(ctx, "SELECT status FROM worker_processed_events WHERE event_key = $1", key).Scan(&status)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return InFlight, nil // pruned between the two statements; the sender retries
	case err != nil:
		return 0, err
	case status == "completed":
		return Completed, nil
	default:
		return InFlight, nil
	}
}

func (p *Postgres) Complete(ctx context.Context, key string, expiresAt time.Time) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE worker_processed_events
		SET status = 'completed', lease_token = NULL, lease_until = 0,
		    expires_at = GREATEST(expires_at, $2), updated_at = now()
		WHERE event_key = $1`, key, expiresAt.Unix())
	return err
}

func (p *Postgres) Release(ctx context.Context, key, token string) error {
	_, err := p.pool.Exec(ctx,
		"DELETE FROM worker_processed_events WHERE event_key = $1 AND status = 'pending' AND lease_token = $2",
		key, token)
	return err
}

func (p *Postgres) Prune(ctx context.Context, now time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM worker_processed_events
		WHERE expires_at < $1 AND (status = 'completed' OR lease_until < $1)`, now.Unix())
	return tag.RowsAffected(), err
}

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }
