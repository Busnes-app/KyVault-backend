// Package vaultapi calls the Rust vault server's private management API,
// /internal/tenancy/v1. The vault is the sole writer of vault state; every mutation
// the worker learns of from KyIdentity is forwarded here.
package vaultapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResponse = 4 << 20

// StatusError is a non-200 answer.
type StatusError struct {
	Path string
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("vaultapi: %s: status %d: %s", e.Path, e.Code, e.Body)
}

// Client is safe for concurrent use.
type Client struct {
	base   string
	secret string
	http   http.Client
}

// New returns a client for baseURL. httpClient may be nil (15 s timeout); redirects are
// refused whatever client is passed, so the bearer secret goes nowhere else.
func New(baseURL, secret string, httpClient *http.Client) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("vaultapi: invalid base URL %q", baseURL)
	}
	c := &Client{base: baseURL, secret: secret, http: http.Client{Timeout: 15 * time.Second}}
	if httpClient != nil {
		c.http = *httpClient
	}
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are refused")
	}
	return c, nil
}

type Health struct {
	Status      string   `json:"status"`
	MultiTenant bool     `json:"multi_tenant"`
	Cells       []string `json:"cells"`
}

type Org struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	HomeRegion string          `json:"home_region"`
	Enabled    bool            `json:"enabled"`
	Revision   int64           `json:"revision"`
	Quotas     json.RawMessage `json:"quotas"`
}

type ReconcileRequest struct {
	Orgs           []Org `json:"orgs"`
	TouchAllActive bool  `json:"touch_all_active"`
}

type ReconcileResult struct {
	Applied                 int      `json:"applied"`
	FencedTenantIDs         []string `json:"fenced_tenant_ids"`
	PurgeRequiredTenantIDs  []string `json:"purge_required_tenant_ids"`
	RegionMismatchTenantIDs []string `json:"region_mismatch_tenant_ids"`
}

type LogoutRequest struct {
	Issuer   string  `json:"issuer"`
	Subject  string  `json:"subject"`
	TenantID *string `json:"tenant_id"`
}

type LogoutResult struct {
	Found    bool   `json:"found"`
	UserUUID string `json:"user_uuid"`
}

type SyncRequest struct {
	EventType   string  `json:"event_type"`
	Issuer      string  `json:"issuer"`
	Subject     string  `json:"subject"`
	TenantID    *string `json:"tenant_id"`
	Email       string  `json:"email"`
	DisplayName string  `json:"display_name"`
	Active      bool    `json:"active"`
}

type SyncResult struct {
	Status   string `json:"status"`
	UserUUID string `json:"user_uuid"`
}

type EraseRequest struct {
	Issuer   string  `json:"issuer"`
	Subject  string  `json:"subject"`
	TenantID *string `json:"tenant_id"`
	// Revision is the /api/suite/erased revision; nil for a user.erased webhook.
	Revision *int64 `json:"revision"`
}

type EraseResult struct {
	Status                 string `json:"status"`
	TombstoneRecorded      bool   `json:"tombstone_recorded"`
	UserExisted            bool   `json:"user_existed"`
	PendingDeletionsQueued int    `json:"pending_deletions_queued"`
}

type PurgeResult struct {
	Status           string `json:"status"`
	PendingDeletions int    `json:"pending_deletions"`
}

type CleanupItem struct {
	ID          string  `json:"id"`
	TenantID    string  `json:"tenant_id"`
	UserUUID    *string `json:"user_uuid"`
	StorageKind string  `json:"storage_kind"`
	ObjectKey   string  `json:"object_key"`
	Attempts    int     `json:"attempts"`
}

type CleanupFailure struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

type CleanupCompleteRequest struct {
	CompletedIDs []string         `json:"completed_ids"`
	Failed       []CleanupFailure `json:"failed"`
}

type CleanupCompleteResult struct {
	Deleted            int      `json:"deleted"`
	FailedUpdated      int      `json:"failed_updated"`
	FinalizedTenantIDs []string `json:"finalized_tenant_ids"`
}

type PrepareRequest struct {
	WantBytesDefault int64 `json:"want_bytes_default"`
	RenewBeforeSecs  int64 `json:"renew_before_secs"`
	Limit            int   `json:"limit"`
}

type StorageReport struct {
	OrgID     string `json:"org_id"`
	UsedBytes int64  `json:"used_bytes"`
	Seq       int64  `json:"seq"`
	WantBytes int64  `json:"want_bytes"`
}

// StorageResult mirrors suitedir.StorageResult. Grant fields are nil for unknown_org.
type StorageResult struct {
	OrgID        string `json:"org_id"`
	Result       string `json:"result"`
	Seq          *int64 `json:"seq"`
	CeilingBytes *int64 `json:"ceiling_bytes"`
	TTLSeconds   *int64 `json:"ttl_seconds"`
	PoolBytes    *int64 `json:"pool_bytes"`
	OrgUsedBytes *int64 `json:"org_used_bytes"`
	OverSince    *int64 `json:"over_since"`
}

type ApplyRequest struct {
	// SentAt is the unix second the KyIdentity request was sent; grants expire from it.
	SentAt  int64           `json:"sent_at"`
	Results []StorageResult `json:"results"`
}

type ApplyResult struct {
	Applied        int      `json:"applied"`
	StaleTenantIDs []string `json:"stale_tenant_ids"`
}

func (c *Client) Health(ctx context.Context) (Health, error) {
	var out Health
	return out, c.do(ctx, http.MethodGet, "health", nil, nil, &out)
}

func (c *Client) ReconcileOrgs(ctx context.Context, req ReconcileRequest) (ReconcileResult, error) {
	var out ReconcileResult
	return out, c.do(ctx, http.MethodPost, "orgs/reconcile", nil, req, &out)
}

func (c *Client) Logout(ctx context.Context, req LogoutRequest) (LogoutResult, error) {
	var out LogoutResult
	return out, c.do(ctx, http.MethodPost, "users/logout", nil, req, &out)
}

func (c *Client) SyncUser(ctx context.Context, req SyncRequest) (SyncResult, error) {
	var out SyncResult
	return out, c.do(ctx, http.MethodPost, "users/sync", nil, req, &out)
}

func (c *Client) EraseUser(ctx context.Context, req EraseRequest) (EraseResult, error) {
	var out EraseResult
	return out, c.do(ctx, http.MethodPost, "users/erase", nil, req, &out)
}

func (c *Client) BeginPurge(ctx context.Context, tenantID string) (PurgeResult, error) {
	var out PurgeResult
	return out, c.do(ctx, http.MethodPost, "tenants/"+url.PathEscape(tenantID)+"/purge/begin", nil, struct{}{}, &out)
}

func (c *Client) PendingCleanup(ctx context.Context, limit int) ([]CleanupItem, error) {
	var out struct {
		Items []CleanupItem `json:"items"`
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if err := c.do(ctx, http.MethodGet, "cleanup/pending", q, nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return nil, errors.New("vaultapi: cleanup/pending: response has no items list")
	}
	return out.Items, nil
}

func (c *Client) CompleteCleanup(ctx context.Context, req CleanupCompleteRequest) (CleanupCompleteResult, error) {
	var out CleanupCompleteResult
	return out, c.do(ctx, http.MethodPost, "cleanup/complete", nil, req, &out)
}

func (c *Client) PrepareStorage(ctx context.Context, req PrepareRequest) ([]StorageReport, error) {
	var out struct {
		Reports []StorageReport `json:"reports"`
	}
	if err := c.do(ctx, http.MethodPost, "storage/prepare", nil, req, &out); err != nil {
		return nil, err
	}
	if out.Reports == nil {
		return nil, errors.New("vaultapi: storage/prepare: response has no reports list")
	}
	return out.Reports, nil
}

func (c *Client) ApplyStorage(ctx context.Context, req ApplyRequest) (ApplyResult, error) {
	var out ApplyResult
	return out, c.do(ctx, http.MethodPost, "storage/apply", nil, req, &out)
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	// path is already escaped by the caller.
	target := c.base + "/internal/tenancy/v1/" + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}

	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("vaultapi: %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("vaultapi: %s: %w", path, err)
	}
	if len(raw) > maxResponse {
		return fmt.Errorf("vaultapi: %s: response exceeds %d bytes", path, maxResponse)
	}
	if resp.StatusCode != http.StatusOK {
		snippet := string(raw)
		if len(snippet) > 256 {
			snippet = snippet[:256]
		}
		return &StatusError{Path: path, Code: resp.StatusCode, Body: strings.TrimSpace(snippet)}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("vaultapi: %s: %w", path, err)
	}
	return nil
}
