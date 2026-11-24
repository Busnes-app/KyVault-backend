package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Busnes-app/kyvault-worker/internal/pubsub"
	"github.com/Busnes-app/kyvault-worker/internal/s3clean"
	"github.com/Busnes-app/kyvault-worker/internal/store"
)

// Syncer polls KyIdentity's /api/suite/orgs, /api/suite/erased, and reports usage to /api/suite/storage.
type Syncer struct {
	BaseURL    string
	Token      string
	HomeRegion string
	Store      *store.Store
	Publisher  *pubsub.Publisher
	Eraser     s3clean.Eraser
	HTTPClient *http.Client
	Logger     *slog.Logger
}

func (s *Syncer) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (s *Syncer) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

type orgListResponse struct {
	Orgs       []orgEntry `json:"orgs"`
	NextCursor string     `json:"next_cursor"`
	HasMore    bool       `json:"has_more"`
}

type orgEntry struct {
	OrgID            string          `json:"org_id"`
	ID               string          `json:"id"`
	Status           string          `json:"status"`
	HomeRegion       string          `json:"home_region"`
	AppEnabled       *bool           `json:"app_enabled"`
	Revision         int64           `json:"revision"`
	Quotas           json.RawMessage `json:"quotas"`
	StoragePoolBytes int64           `json:"storage_pool_bytes"`
	StorageOverSince *int64          `json:"storage_over_since"`
}

// PollOrgs pulls complete pages from GET /api/suite/orgs and updates local tenant authority rows.
func (s *Syncer) PollOrgs(ctx context.Context) error {
	if s.BaseURL == "" {
		return nil
	}
	cursor := ""
	seen := 0
	for {
		u, err := url.Parse(s.BaseURL + "/api/suite/orgs")
		if err != nil {
			return err
		}
		q := u.Query()
		if s.HomeRegion != "" {
			q.Set("home_region", s.HomeRegion)
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		u.RawQuery = q.Encode()

		body, err := s.doGet(ctx, u.String())
		if err != nil {
			return fmt.Errorf("poll /api/suite/orgs: %w", err)
		}

		var page orgListResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode /api/suite/orgs: %w", err)
		}

		for _, entry := range page.Orgs {
			orgID := strings.TrimSpace(entry.OrgID)
			if orgID == "" {
				orgID = strings.TrimSpace(entry.ID)
			}
			if orgID == "" {
				continue
			}
			// Only manage tenants assigned to this cluster's HOME_REGION (if home_region is specified).
			if s.HomeRegion != "" && entry.HomeRegion != "" && entry.HomeRegion != s.HomeRegion {
				continue
			}
			appEnabled := true
			if entry.AppEnabled != nil {
				appEnabled = *entry.AppEnabled
			}
			quotasJSON := "{}"
			if len(entry.Quotas) > 0 && string(entry.Quotas) != "null" {
				quotasJSON = string(entry.Quotas)
			}
			rec := store.TenantRecord{
				ID:               orgID,
				Status:           entry.Status,
				HomeRegion:       entry.HomeRegion,
				AppEnabled:       appEnabled,
				Revision:         entry.Revision,
				QuotasJSON:       quotasJSON,
				StoragePoolBytes: entry.StoragePoolBytes,
				StorageOverSince: entry.StorageOverSince,
			}
			newlyFenced, err := s.Store.UpsertTenant(ctx, rec)
			if err != nil {
				return fmt.Errorf("upsert tenant %s: %w", orgID, err)
			}
			if newlyFenced {
				s.log().Info("fenced tenant and broadcasting WebSocket kick", "tenant_id", orgID, "status", rec.Status, "app_enabled", rec.AppEnabled)
				if err := s.Publisher.NotifyTenantKick(ctx, orgID); err != nil {
					s.log().Warn("failed to notify tenant kick", "tenant_id", orgID, "err", err)
				}
			}
			seen++
		}

		if !page.HasMore || page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	s.log().Debug("completed /api/suite/orgs poll", "tenants_synced", seen)
	return nil
}

type erasedListResponse struct {
	Events     []erasedEvent `json:"events"`
	NextCursor string        `json:"next_cursor"`
	HasMore    bool          `json:"has_more"`
}

type erasedEvent struct {
	ID         string `json:"id"`
	EntityType string `json:"entity_type"` // "org" | "tenant" | "user"
	OrgID      string `json:"org_id"`
	Subject    string `json:"subject"`
	UserID     string `json:"user_id"`
	Revision   int64  `json:"revision"`
}

// PollErased pulls GET /api/suite/erased using a durable monotonic watermark and executes
// idempotent tenant/user erasures. Also retries any tenants left in 'erasing' status.
func (s *Syncer) PollErased(ctx context.Context) error {
	// First retry any interrupted tenant erasures so S3/FS retries never get dropped.
	if err := s.RetryErasingTenants(ctx); err != nil {
		s.log().Warn("retrying erasing tenants encountered error", "err", err)
	}
	if s.BaseURL == "" {
		return nil
	}

	cur, err := s.Store.GetCursor(ctx, "suite_erased")
	if err != nil {
		return fmt.Errorf("read suite_erased cursor: %w", err)
	}
	cursor := cur.AfterID
	maxRev := cur.Revision

	for {
		u, err := url.Parse(s.BaseURL + "/api/suite/erased")
		if err != nil {
			return err
		}
		q := u.Query()
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		if maxRev > 0 {
			q.Set("after_revision", fmt.Sprintf("%d", maxRev))
		}
		u.RawQuery = q.Encode()

		body, err := s.doGet(ctx, u.String())
		if err != nil {
			return fmt.Errorf("poll /api/suite/erased: %w", err)
		}

		var page erasedListResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode /api/suite/erased: %w", err)
		}

		for _, ev := range page.Events {
			switch strings.ToLower(strings.TrimSpace(ev.EntityType)) {
			case "org", "tenant":
				if ev.OrgID != "" {
					if err := s.EraseTenant(ctx, ev.OrgID); err != nil {
						return fmt.Errorf("erase tenant %s: %w", ev.OrgID, err)
					}
				}
			case "user":
				subj := ev.Subject
				if subj == "" {
					subj = ev.UserID
				}
				if subj != "" {
					if err := s.EraseUserBySubject(ctx, subj, ""); err != nil {
						return fmt.Errorf("erase user %s: %w", subj, err)
					}
				}
			}
			if ev.Revision > maxRev {
				maxRev = ev.Revision
			}
			if ev.ID != "" {
				cursor = ev.ID
			}
		}

		if page.NextCursor != "" {
			cursor = page.NextCursor
		}

		// Persist durable watermark only after every event on the page succeeded.
		if err := s.Store.SaveCursor(ctx, store.SyncCursor{
			Name:     "suite_erased",
			Revision: maxRev,
			AfterID:  cursor,
		}); err != nil {
			return fmt.Errorf("save suite_erased cursor: %w", err)
		}

		if !page.HasMore {
			break
		}
	}
	return nil
}

// EraseTenant executes the full idempotent tenant erasure pipeline:
//  1. Mark tenant 'erasing', disable users, rotate security stamps, clear refresh tokens.
//  2. Emit PG NOTIFY tenant_kick so all Rust replicas disconnect live WebSockets immediately.
//  3. Delete all objects under tenants/<tenantID>/ in S3 and/or local filesystem.
//     If object deletion fails, leave tenant in 'erasing' for retry — NEVER falsely mark deleted!
//  4. Atomically purge all DB rows for tenantID and mark tenants.status = 'deleted' (tombstone).
func (s *Syncer) EraseTenant(ctx context.Context, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil
	}
	if err := s.Store.BeginTenantErasure(ctx, tenantID); err != nil {
		return fmt.Errorf("begin tenant erasure: %w", err)
	}
	if err := s.Publisher.NotifyTenantKick(ctx, tenantID); err != nil {
		s.log().Warn("notify tenant_kick during erasure failed", "tenant_id", tenantID, "err", err)
	}

	if s.Eraser != nil {
		deleted, err := s.Eraser.DeletePrefix(ctx, "tenants/"+tenantID+"/")
		if err != nil {
			return fmt.Errorf("object storage cleanup for tenant %s failed (will retry): %w", tenantID, err)
		}
		s.log().Info("purged tenant object storage prefix", "tenant_id", tenantID, "objects_deleted", deleted)
	}

	if err := s.Store.CompleteTenantDBPurge(ctx, tenantID); err != nil {
		return fmt.Errorf("complete tenant db purge: %w", err)
	}
	s.log().Info("completed tenant erasure and retained tombstone", "tenant_id", tenantID)
	return nil
}

// RetryErasingTenants resumes any tenant erasure that failed mid-flight (e.g. transient S3 outage).
func (s *Syncer) RetryErasingTenants(ctx context.Context) error {
	ids, err := s.Store.ListErasingTenants(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.EraseTenant(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// EraseUserBySubject purges a user's personal vault & recovery kits while preserving shared org data.
func (s *Syncer) EraseUserBySubject(ctx context.Context, subject, email string) error {
	uid, _, err := s.Store.FindUserUUIDBySubject(ctx, subject, email)
	if err != nil {
		// Still record tombstone if user never signed into KyVault.
		_, _, err2 := s.Store.EraseUserPersonalData(ctx, "", subject)
		return err2
	}
	if err := s.Publisher.NotifyUserLogout(ctx, uid); err != nil {
		s.log().Warn("notify user_logout during user erasure failed", "user_id", uid, "err", err)
	}
	_, objKeys, err := s.Store.EraseUserPersonalData(ctx, uid, subject)
	if err != nil {
		return err
	}
	if s.Eraser != nil {
		for _, prefix := range objKeys {
			if _, delErr := s.Eraser.DeletePrefix(ctx, prefix); delErr != nil {
				s.log().Warn("failed cleaning personal object prefix during user erasure", "prefix", prefix, "err", delErr)
			}
		}
	}
	return nil
}

type storageReportPayload struct {
	Sequence   int64               `json:"sequence"`
	HomeRegion string              `json:"home_region"`
	ReportedAt string              `json:"reported_at"`
	Tenants    []store.TenantUsage `json:"tenants"`
}

// ReportStorage computes canonical per-tenant usage and posts a sequenced batch to POST /api/suite/storage.
func (s *Syncer) ReportStorage(ctx context.Context) error {
	if s.BaseURL == "" {
		return nil
	}
	usage, err := s.Store.ComputeTenantUsage(ctx)
	if err != nil {
		return fmt.Errorf("compute tenant usage: %w", err)
	}
	if len(usage) == 0 {
		return nil
	}
	seq, err := s.Store.NextSequence(ctx, "storage_report_seq")
	if err != nil {
		return fmt.Errorf("next storage sequence: %w", err)
	}
	payload := storageReportPayload{
		Sequence:   seq,
		HomeRegion: s.HomeRegion,
		ReportedAt: time.Now().UTC().Format(time.RFC3339),
		Tenants:    usage,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL+"/api/suite/storage", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
	req.Header.Set("Idempotency-Key", fmt.Sprintf("kyvault-storage-%s-%d", s.HomeRegion, seq))

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("post /api/suite/storage: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("post /api/suite/storage status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	s.log().Debug("reported tenant storage usage", "sequence", seq, "tenants", len(usage))
	return nil
}

func (s *Syncer) doGet(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}
