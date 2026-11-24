package syncer

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/Busnes-app/kyvault-worker/internal/config"
	"github.com/Busnes-app/kyvault-worker/internal/vaultapi"
)

const (
	cleanupPage      = 100
	maxCleanupPasses = 100
)

var (
	safeTenant  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	safeSegment = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}$`)
)

// DrainCleanup executes the vault's durable cleanup queue. Each item is reported back as
// completed or failed; a failed item stays pending in the vault (and its tenant in
// purge_pending) for the next pass. Nothing is deleted from the queue by the worker alone.
func (s *Syncer) DrainCleanup(ctx context.Context) error {
	var failures []error
	for range maxCleanupPasses {
		items, err := s.Vault.PendingCleanup(ctx, cleanupPage)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			break
		}
		req := vaultapi.CleanupCompleteRequest{CompletedIDs: []string{}, Failed: []vaultapi.CleanupFailure{}}
		for _, it := range items {
			if err := s.eraseItem(ctx, it); err != nil {
				msg := err.Error()
				if len(msg) > 500 {
					msg = msg[:500]
				}
				req.Failed = append(req.Failed, vaultapi.CleanupFailure{ID: it.ID, Error: msg})
				failures = append(failures, fmt.Errorf("item %s (%s): %w", it.ID, it.StorageKind, err))
				continue
			}
			req.CompletedIDs = append(req.CompletedIDs, it.ID)
		}
		res, err := s.Vault.CompleteCleanup(ctx, req)
		if err != nil {
			return err
		}
		if len(res.FinalizedTenantIDs) > 0 {
			s.log().Info("tenant purge finalized", "tenant_ids", res.FinalizedTenantIDs)
		}
		// Every item failed, or the queue is drained: more passes would only repeat them.
		if len(req.CompletedIDs) == 0 || len(items) < cleanupPage {
			break
		}
	}
	return errors.Join(failures...)
}

func (s *Syncer) eraseItem(ctx context.Context, it vaultapi.CleanupItem) error {
	if err := checkItem(it, s.Cells); err != nil {
		return err
	}
	switch it.StorageKind {
	case "attachment":
		if s.Attachments == nil {
			return fmt.Errorf("attachments %w", errNotConfigured)
		}
		return s.Attachments.DeleteObject(ctx, it.ObjectKey)
	case "send":
		if s.Sends == nil {
			return fmt.Errorf("sends %w", errNotConfigured)
		}
		return s.Sends.DeleteObject(ctx, it.ObjectKey)
	default: // tenant_prefix: a tenant's tree exists under both roots
		if s.Attachments == nil || s.Sends == nil {
			return fmt.Errorf("attachments and sends %w", errNotConfigured)
		}
		return errors.Join(s.Attachments.DeletePrefix(ctx, it.ObjectKey), s.Sends.DeletePrefix(ctx, it.ObjectKey))
	}
}

// checkItem accepts only cell-scoped keys the vault writes for the item's own tenant inside
// one of this deployment's served cells:
// cells/<cell>/tenants/<tid>/attachments/<cipher>/<id>,
// cells/<cell>/tenants/<tid>/sends/<send>[/<file>], or
// cells/<cell>/tenants/<tid>/ for a whole-tenant sweep.
func checkItem(it vaultapi.CleanupItem, servedCells []string) error {
	if !safeTenant.MatchString(it.TenantID) {
		return fmt.Errorf("unsafe tenant id %q", it.TenantID)
	}
	afterCells, ok := strings.CutPrefix(it.ObjectKey, "cells/")
	if !ok {
		return fmt.Errorf("%s key %q is outside cells/", it.StorageKind, it.ObjectKey)
	}
	cell, afterCell, ok := strings.Cut(afterCells, "/")
	if !ok || !config.IsValidCellSlug(cell) {
		return fmt.Errorf("%s key %q has invalid cell %q", it.StorageKind, it.ObjectKey, cell)
	}
	if len(servedCells) == 0 || !slices.Contains(servedCells, cell) {
		return fmt.Errorf("%s key %q is in unserved cell %q", it.StorageKind, it.ObjectKey, cell)
	}
	base := "tenants/" + it.TenantID + "/"
	var sub string
	var segs []int
	switch it.StorageKind {
	case "attachment":
		sub, segs = "attachments/", []int{2}
	case "send":
		sub, segs = "sends/", []int{1, 2}
	case "tenant_prefix":
		if afterCell != base {
			return fmt.Errorf("tenant_prefix key %q is not %q", it.ObjectKey, "cells/"+cell+"/"+base)
		}
		return nil
	default:
		return fmt.Errorf("unknown storage kind %q", it.StorageKind)
	}
	rest, ok := strings.CutPrefix(afterCell, base+sub)
	if !ok {
		return fmt.Errorf("%s key %q is outside %q", it.StorageKind, it.ObjectKey, "cells/"+cell+"/"+base+sub)
	}
	parts := strings.Split(rest, "/")
	for _, p := range parts {
		if !safeSegment.MatchString(p) {
			return fmt.Errorf("unsafe %s key %q", it.StorageKind, it.ObjectKey)
		}
	}
	for _, n := range segs {
		if len(parts) == n {
			return nil
		}
	}
	return fmt.Errorf("%s key %q has %d segments after %q", it.StorageKind, it.ObjectKey, len(parts), "cells/"+cell+"/"+base+sub)
}
