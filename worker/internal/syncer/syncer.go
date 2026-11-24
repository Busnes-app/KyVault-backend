// Package syncer moves KyIdentity's suite directory into the vault: org lifecycle and
// erased subjects by polling, storage grants by exchange, and object cleanup by draining
// the vault's durable queue. Every vault mutation goes through the Rust management API;
// this package only keeps its own cursors.
package syncer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kyvault-worker/internal/s3clean"
	"github.com/Busnes-app/kyvault-worker/internal/state"
	"github.com/Busnes-app/kyvault-worker/internal/vaultapi"
)

const (
	CursorOrgs   = "suite_orgs"
	CursorErased = "suite_erased"

	reconcileChunk = 500
)

type Syncer struct {
	Directory *suitedir.Client
	Vault     *vaultapi.Client
	State     state.Store
	// Issuer is the OIDC issuer; KyIdentity subjects are only unique within it.
	Issuer string

	StorageWantBytes   int64
	StorageRenewBefore time.Duration
	// Attachments and Sends are the storage roots; nil means not configured.
	Attachments s3clean.Eraser
	Sends       s3clean.Eraser

	Logger *slog.Logger
	Now    func() time.Time

	kick     chan struct{}
	kickOnce sync.Once

	inflightMu sync.Mutex
	inflight   map[string]bool
}

func (s *Syncer) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Reconcile brings the vault up to KyIdentity's org and erased-subject history; the
// worker reports ready only after it succeeds. fromZero replays both from revision 0,
// as a restored vault needs before serving. Storage sequences are never touched.
func (s *Syncer) Reconcile(ctx context.Context, fromZero bool) error {
	h, err := s.Vault.Health(ctx)
	if err != nil {
		return err
	}
	if h.Status != "ok" || !h.MultiTenant {
		return fmt.Errorf("vault is not a healthy multi-tenant server (status %q, multi_tenant %v)", h.Status, h.MultiTenant)
	}
	if err := s.SyncOrgs(ctx, fromZero); err != nil {
		return fmt.Errorf("orgs: %w", err)
	}
	if err := s.SyncErased(ctx, fromZero); err != nil {
		return fmt.Errorf("erased: %w", err)
	}
	return nil
}

// SyncOrgs applies every org change after the saved cursor (or from zero) and saves
// the cursor only after the vault accepted all of them. A complete pass, one that
// reached KyIdentity's current revision, also refreshes every active tenant's authority.
func (s *Syncer) SyncOrgs(ctx context.Context, fromZero bool) error {
	since, err := s.since(ctx, CursorOrgs, fromZero)
	if err != nil {
		return err
	}
	for {
		orgs, next, err := s.Directory.Orgs(ctx, since)
		if err != nil {
			return err
		}
		// suitedir.Orgs returns one below the last revision when it stopped at its page bound.
		complete := len(orgs) == 0 || next >= orgs[len(orgs)-1].Revision
		for i := 0; i == 0 || i < len(orgs); i += reconcileChunk {
			chunk := orgs[i:min(i+reconcileChunk, len(orgs))]
			last := i+reconcileChunk >= len(orgs)
			if err := s.reconcile(ctx, chunk, complete && last); err != nil {
				return err
			}
		}
		if err := s.State.SaveCursor(ctx, CursorOrgs, next); err != nil {
			return fmt.Errorf("save %s cursor: %w", CursorOrgs, err)
		}
		if complete {
			return nil
		}
		since = next
	}
}

func (s *Syncer) reconcile(ctx context.Context, orgs []suitedir.Org, touchAll bool) error {
	req := vaultapi.ReconcileRequest{Orgs: make([]vaultapi.Org, len(orgs)), TouchAllActive: touchAll}
	for i, o := range orgs {
		req.Orgs[i] = vaultapi.Org{ID: o.ID, Status: o.Status, HomeRegion: o.HomeRegion, Enabled: o.Enabled, Revision: o.Revision, Quotas: o.Quotas}
	}
	res, err := s.Vault.ReconcileOrgs(ctx, req)
	if err != nil {
		return err
	}
	if len(res.FencedTenantIDs) > 0 {
		s.log().Info("vault fenced tenants", "tenant_ids", res.FencedTenantIDs)
	}
	for _, id := range res.PurgeRequiredTenantIDs {
		p, err := s.Vault.BeginPurge(ctx, id)
		if err != nil {
			return fmt.Errorf("begin purge of %s: %w", id, err)
		}
		s.log().Info("tenant purge begun", "tenant_id", id, "status", p.Status, "pending_deletions", p.PendingDeletions)
		s.TriggerCleanup()
	}
	return nil
}

// SyncErased erases every subject listed after the saved cursor (or from zero), reading
// until KyIdentity lists nothing more. The cursor advances only past applied erasures.
func (s *Syncer) SyncErased(ctx context.Context, fromZero bool) error {
	since, err := s.since(ctx, CursorErased, fromZero)
	if err != nil {
		return err
	}
	for {
		subjects, next, err := s.Directory.Erased(ctx, since)
		if err != nil {
			return err
		}
		if len(subjects) == 0 {
			return nil
		}
		for _, sub := range subjects {
			res, err := s.Vault.EraseUser(ctx, vaultapi.EraseRequest{
				Issuer: s.Issuer, Subject: sub.Sub, TenantID: &sub.OrgID, Revision: &sub.Revision,
			})
			if err != nil {
				return fmt.Errorf("erase subject at revision %d: %w", sub.Revision, err)
			}
			if res.PendingDeletionsQueued > 0 {
				s.TriggerCleanup()
			}
		}
		if err := s.State.SaveCursor(ctx, CursorErased, next); err != nil {
			return fmt.Errorf("save %s cursor: %w", CursorErased, err)
		}
		since = next
	}
}

func (s *Syncer) since(ctx context.Context, cursor string, fromZero bool) (int64, error) {
	if fromZero {
		return 0, nil
	}
	v, err := s.State.Cursor(ctx, cursor)
	if err != nil {
		return 0, fmt.Errorf("read %s cursor: %w", cursor, err)
	}
	return v, nil
}

// TriggerCleanup asks RunCleanup for a drain pass now. It never blocks.
func (s *Syncer) TriggerCleanup() {
	select {
	case s.kickChan() <- struct{}{}:
	default:
	}
}

func (s *Syncer) kickChan() chan struct{} {
	s.kickOnce.Do(func() { s.kick = make(chan struct{}, 1) })
	return s.kick
}

// RunCleanup drains the cleanup queue every interval and whenever triggered, one pass at
// a time, until ctx ends.
func (s *Syncer) RunCleanup(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.DrainCleanup(ctx); err != nil && ctx.Err() == nil {
			s.log().Warn("cleanup drain incomplete; failed items stay pending", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kickChan():
		}
	}
}

// Loop runs fn every interval until ctx ends. The first run is the caller's.
func Loop(ctx context.Context, logger *slog.Logger, name string, interval time.Duration, fn func(context.Context) error) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := fn(ctx); err != nil && ctx.Err() == nil {
				logger.Warn("background loop failed", "loop", name, "err", err)
			}
		}
	}
}

var errNotConfigured = errors.New("storage root not configured")
