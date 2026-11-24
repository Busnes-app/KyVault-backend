package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kyvault-worker/internal/fakevault"
	"github.com/Busnes-app/kyvault-worker/internal/s3clean"
	"github.com/Busnes-app/kyvault-worker/internal/state"
	"github.com/Busnes-app/kyvault-worker/internal/vaultapi"
)

const (
	issuer   = "https://id.example"
	clientID = "kyvault"
	secret   = "client-secret"
	orgA     = "aaaaaaaa-0000-4000-8000-000000000001"
	orgB     = "bbbbbbbb-0000-4000-8000-000000000002"
	orgC     = "cccccccc-0000-4000-8000-000000000003"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// identity is KyIdentity's suite directory as docs/SUITE-DIRECTORY.md specifies it.
type identity struct {
	t        *testing.T
	mu       sync.Mutex
	pageSize int
	orgs     []map[string]any // each has "id" and "revision"
	erased   []map[string]any
	unknown  map[string]bool
	queries  []string
	storage  [][]suitedir.StorageReport
	// onStorage runs inside POST /api/suite/storage before it answers.
	onStorage func([]suitedir.StorageReport)
}

func newIdentity(t *testing.T) (*identity, *suitedir.Client) {
	id := &identity{t: t, pageSize: 2, unknown: map[string]bool{}}
	srv := httptest.NewServer(id)
	t.Cleanup(srv.Close)
	return id, &suitedir.Client{Issuer: srv.URL, ClientID: clientID, ClientSecret: secret}
}

func (id *identity) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != clientID || p != secret {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client"}`)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	id.mu.Lock()
	id.queries = append(id.queries, r.URL.Path+"?"+r.URL.RawQuery)
	id.mu.Unlock()
	q := r.URL.Query()
	switch r.URL.Path {
	case "/api/suite/orgs":
		after := q.Get("since")
		if c := q.Get("cursor"); c != "" {
			after = strings.TrimPrefix(c, "c")
		}
		since, _ := strconv.ParseInt(after, 10, 64)
		page, next := id.page(id.orgs, since, q.Get("limit"))
		body := map[string]any{"orgs": page}
		if next != "" {
			body["next"] = "c" + next // opaque cursor
		}
		_ = json.NewEncoder(w).Encode(body)
	case "/api/suite/erased":
		since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
		page, next := id.page(id.erased, since, q.Get("limit"))
		body := map[string]any{"subjects": page}
		if next != "" {
			body["next"] = next
		}
		_ = json.NewEncoder(w).Encode(body)
	case "/api/suite/storage":
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var req struct {
			Reports []suitedir.StorageReport `json:"reports"`
		}
		if r.Method != http.MethodPost || dec.Decode(&req) != nil || r.ContentLength > 64<<10 || len(req.Reports) > 500 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_request"}`)
			return
		}
		id.mu.Lock()
		id.storage = append(id.storage, req.Reports)
		hook := id.onStorage
		id.mu.Unlock()
		if hook != nil {
			hook(req.Reports)
		}
		var results []map[string]any
		for _, rep := range req.Reports {
			if id.unknown[rep.OrgID] {
				results = append(results, map[string]any{"org_id": rep.OrgID, "result": "unknown_org"})
				continue
			}
			results = append(results, map[string]any{
				"org_id": rep.OrgID, "result": "ok", "seq": rep.Seq, "ceiling_bytes": rep.UsedBytes + rep.WantBytes,
				"ttl_seconds": 900, "pool_bytes": 1 << 30, "org_used_bytes": rep.UsedBytes * 2, "over_since": nil,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	default:
		http.NotFound(w, r)
	}
}

func (id *identity) page(rows []map[string]any, since int64, limit string) ([]map[string]any, string) {
	id.mu.Lock()
	defer id.mu.Unlock()
	n, _ := strconv.Atoi(limit)
	if n == 0 || n > id.pageSize {
		n = id.pageSize
	}
	out := []map[string]any{}
	for _, row := range rows {
		if row["revision"].(int64) > since {
			out = append(out, row)
		}
	}
	if len(out) < n {
		return out, ""
	}
	out = out[:n]
	return out, strconv.FormatInt(out[n-1]["revision"].(int64), 10)
}

func (id *identity) sent() [][]suitedir.StorageReport {
	id.mu.Lock()
	defer id.mu.Unlock()
	return append([][]suitedir.StorageReport{}, id.storage...)
}

func (id *identity) sawQuery(prefix string) bool {
	id.mu.Lock()
	defer id.mu.Unlock()
	for _, q := range id.queries {
		if strings.HasPrefix(q, prefix) {
			return true
		}
	}
	return false
}

func newSyncer(t *testing.T) (*Syncer, *identity, *fakevault.Vault) {
	id, dir := newIdentity(t)
	v := fakevault.New(t)
	v.Cells = []string{"eu-west-1", "eu-west-2"}
	return &Syncer{Directory: dir, Vault: v.Client(t), State: state.NewMemory(), Cells: []string{"eu-west-1", "eu-west-2"}, Issuer: issuer,
		StorageWantBytes: 256 << 20, StorageRenewBefore: 180 * time.Second}, id, v
}

func orgInCell(id, cell string, rev int64, status string, enabled bool) map[string]any {
	return map[string]any{
		"id": id, "status": status, "revision": rev, "home_region": cell, "enabled": enabled,
		"quotas": map[string]any{"storage_gb": 5}, "storage": map[string]any{"pool_bytes": 1 << 30, "over_since": nil},
	}
}

func org(id string, rev int64, status string, enabled bool) map[string]any {
	return orgInCell(id, "eu-west-1", rev, status, enabled)
}

func TestSyncOrgsFollowsPagesAndReconciles(t *testing.T) {
	s, id, v := newSyncer(t)
	id.orgs = []map[string]any{org(orgA, 1, "active", true), orgInCell(orgB, "eu-west-2", 2, "suspended", true), org(orgC, 3, "active", false)}
	ctx := context.Background()

	if err := s.SyncOrgs(ctx, false); err != nil {
		t.Fatal(err)
	}
	if !id.sawQuery("/api/suite/orgs?limit=500&since=0") || !id.sawQuery("/api/suite/orgs?cursor=c2") {
		t.Fatalf("pages not followed by since then cursor: %v", id.queries)
	}
	calls := fakevault.CallsTo[vaultapi.ReconcileRequest](v, "orgs/reconcile")
	if len(calls) != 1 || len(calls[0].Orgs) != 3 || !calls[0].TouchAllActive {
		t.Fatalf("reconcile calls = %+v", calls)
	}
	got := calls[0].Orgs[2]
	if got.ID != orgC || got.Status != "active" || got.Enabled || got.HomeRegion != "eu-west-1" || got.Revision != 3 || string(got.Quotas) != `{"storage_gb":5}` {
		t.Fatalf("org mapped wrongly: %+v (quotas %s)", got, got.Quotas)
	}
	if c, _ := s.State.Cursor(ctx, CursorOrgs); c != 3 {
		t.Fatalf("cursor = %d, want 3", c)
	}

	// Nothing changed: still one reconcile, so the vault refreshes active tenants' authority.
	if err := s.SyncOrgs(ctx, false); err != nil {
		t.Fatal(err)
	}
	calls = fakevault.CallsTo[vaultapi.ReconcileRequest](v, "orgs/reconcile")
	if len(calls) != 2 || len(calls[1].Orgs) != 0 || !calls[1].TouchAllActive {
		t.Fatalf("empty pass did not touch: %+v", calls)
	}
	if !id.sawQuery("/api/suite/orgs?limit=500&since=3") {
		t.Fatalf("second poll did not start at the cursor: %v", id.queries)
	}
}

func TestReconcileRefusesMismatchedCells(t *testing.T) {
	s, _, v := newSyncer(t)
	v.Cells = []string{"us-east-1"}
	if err := s.Reconcile(context.Background(), false); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected cell mismatch error, got %v", err)
	}
}

func TestSyncOrgsFiltersForeignCellsAndForwardsC4Move(t *testing.T) {
	s, id, v := newSyncer(t)
	var buf bytes.Buffer
	s.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	ctx := context.Background()

	// orgA (eu-west-1) and orgB (eu-west-2) are served; orgC (us-east-1) is foreign (C5).
	id.orgs = []map[string]any{
		orgInCell(orgA, "eu-west-1", 1, "active", true),
		orgInCell(orgB, "eu-west-2", 2, "active", true),
		orgInCell(orgC, "us-east-1", 3, "active", true),
	}
	if err := s.SyncOrgs(ctx, false); err != nil {
		t.Fatal(err)
	}
	calls := fakevault.CallsTo[vaultapi.ReconcileRequest](v, "orgs/reconcile")
	if len(calls) != 1 || len(calls[0].Orgs) != 2 || calls[0].Orgs[0].ID != orgA || calls[0].Orgs[1].ID != orgB {
		t.Fatalf("foreign orgC should be filtered out (C5); calls = %+v", calls)
	}

	// C4: orgA's home_region mutates to an unserved cell (us-east-1). Because orgA was
	// previously served here, SyncOrgs MUST still forward it so the vault fences it.
	id.orgs = append(id.orgs, orgInCell(orgA, "us-east-1", 4, "active", true))
	v.RegionMismatch = []string{orgA}
	if err := s.SyncOrgs(ctx, false); err != nil {
		t.Fatal(err)
	}
	calls = fakevault.CallsTo[vaultapi.ReconcileRequest](v, "orgs/reconcile")
	if len(calls) != 2 || len(calls[1].Orgs) != 1 || calls[1].Orgs[0].ID != orgA || calls[1].Orgs[0].HomeRegion != "us-east-1" {
		t.Fatalf("C4 move for orgA was not forwarded to vault: %+v", calls)
	}
	if !strings.Contains(buf.String(), `level=ERROR msg="CELL MISMATCH (C4)`) {
		t.Fatalf("C4 mismatch not logged loudly:\n%s", buf.String())
	}
	// Stored org cell in worker state stays immutable (eu-west-1).
	cell, ok, _ := s.State.KnownOrgCell(ctx, orgA)
	if !ok || cell != "eu-west-1" {
		t.Fatalf("worker org cell mutated to %q (ok=%v)", cell, ok)
	}
}

func TestSyncOrgsKeepsCursorOnFailure(t *testing.T) {
	s, id, v := newSyncer(t)
	id.orgs = []map[string]any{org(orgA, 5, "active", true)}
	v.Fail["orgs/reconcile"] = 1
	ctx := context.Background()
	if err := s.SyncOrgs(ctx, false); err == nil {
		t.Fatal("expected the vault failure")
	}
	if c, _ := s.State.Cursor(ctx, CursorOrgs); c != 0 {
		t.Fatalf("cursor advanced to %d past an unapplied org", c)
	}
	if err := s.SyncOrgs(ctx, false); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.State.Cursor(ctx, CursorOrgs); c != 5 {
		t.Fatalf("cursor = %d", c)
	}
}

func TestPurgeRequiredBeginsPurgeAndTriggersCleanup(t *testing.T) {
	s, id, v := newSyncer(t)
	id.orgs = []map[string]any{org(orgA, 1, "deleted", false)}
	v.PurgeRequired = []string{orgA}
	if err := s.SyncOrgs(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if n := len(fakevault.CallsTo[struct{}](v, "tenants/"+orgA+"/purge/begin")); n != 1 {
		t.Fatalf("purge/begin calls = %d", n)
	}
	select {
	case <-s.kickChan():
	default:
		t.Fatal("cleanup was not triggered")
	}
}

func erasedRow(sub, orgID string, rev int64) map[string]any {
	return map[string]any{"sub": sub, "org_id": orgID, "revision": rev}
}

func TestSyncErasedPassesIssuerSubjectTenantRevision(t *testing.T) {
	s, id, v := newSyncer(t)
	// orgA and orgB are served; orgC is in a foreign cell and its erasure must be skipped (C5).
	id.orgs = []map[string]any{
		orgInCell(orgA, "eu-west-1", 1, "active", true),
		orgInCell(orgB, "eu-west-2", 2, "active", true),
		orgInCell(orgC, "us-east-1", 3, "active", true),
	}
	id.erased = []map[string]any{
		erasedRow("usr_1", orgA, 4),
		erasedRow("usr_foreign", orgC, 5),
		erasedRow("usr_2", orgA, 6),
		erasedRow("usr_3", orgB, 9),
	}
	v.ErasePending = 2
	v.Fail["users/erase"] = 1
	ctx := context.Background()

	if err := s.SyncErased(ctx, false); err == nil {
		t.Fatal("expected the vault failure")
	}
	if c, _ := s.State.Cursor(ctx, CursorErased); c != 0 {
		t.Fatalf("cursor advanced to %d past an unapplied erasure", c)
	}
	if err := s.SyncErased(ctx, false); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.State.Cursor(ctx, CursorErased); c != 9 {
		t.Fatalf("cursor = %d, want 9", c)
	}
	calls := fakevault.CallsTo[vaultapi.EraseRequest](v, "users/erase")
	for _, c := range calls {
		if c.TenantID != nil && *c.TenantID == orgC {
			t.Fatalf("foreign-cell erasure for orgC was forwarded to vault: %+v", c)
		}
	}
	last := calls[len(calls)-1]
	if last.Issuer != issuer || last.Subject != "usr_3" || last.TenantID == nil || *last.TenantID != orgB || last.Revision == nil || *last.Revision != 9 {
		t.Fatalf("erase request = %+v", last)
	}
	select {
	case <-s.kickChan():
	default:
		t.Fatal("queued deletions did not trigger cleanup")
	}
}

func TestReconcileFromZeroAfterRestore(t *testing.T) {
	s, id, v := newSyncer(t)
	id.orgs = []map[string]any{org(orgA, 3, "deleted", false)}
	id.erased = []map[string]any{erasedRow("usr_1", orgA, 2)}
	ctx := context.Background()
	_ = s.State.SaveCursor(ctx, CursorOrgs, 50)
	_ = s.State.SaveCursor(ctx, CursorErased, 50)

	if err := s.SyncOrgs(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncErased(ctx, true); err != nil {
		t.Fatal(err)
	}
	if !id.sawQuery("/api/suite/orgs?limit=500&since=0") || !id.sawQuery("/api/suite/erased?limit=500&since=0") {
		t.Fatalf("restore reconciliation did not start at zero: %v", id.queries)
	}
	if len(fakevault.CallsTo[vaultapi.EraseRequest](v, "users/erase")) != 1 || len(fakevault.CallsTo[vaultapi.ReconcileRequest](v, "orgs/reconcile")[0].Orgs) != 1 {
		t.Fatal("history was not reapplied")
	}
	if c, _ := s.State.Cursor(ctx, CursorOrgs); c != 50 {
		t.Fatalf("cursor moved backwards to %d", c)
	}
	if len(fakevault.CallsTo[struct{}](v, "storage/prepare")) != 0 {
		t.Fatal("restore reconciliation touched storage sequencing")
	}
}

func TestReportStorageWireFormatAndSentAt(t *testing.T) {
	s, id, v := newSyncer(t)
	clk := &clock{t: time.Unix(1_750_000_000, 0)}
	s.Now = clk.Now
	v.Reports = []vaultapi.StorageReport{{OrgID: orgA, UsedBytes: 1024, Seq: 7, WantBytes: 256 << 20}, {OrgID: orgB, UsedBytes: 0, Seq: 1, WantBytes: 0}}
	id.unknown[orgB] = true
	id.onStorage = func([]suitedir.StorageReport) { clk.Advance(40 * time.Second) } // a slow answer

	if err := s.ReportStorage(context.Background()); err != nil {
		t.Fatal(err)
	}
	prep := fakevault.CallsTo[vaultapi.PrepareRequest](v, "storage/prepare")
	if len(prep) != 1 || prep[0] != (vaultapi.PrepareRequest{WantBytesDefault: 256 << 20, RenewBeforeSecs: 180, Limit: 500}) {
		t.Fatalf("prepare = %+v", prep)
	}
	if sent := id.sent(); len(sent) != 1 || sent[0][0] != (suitedir.StorageReport{OrgID: orgA, UsedBytes: 1024, Seq: 7, WantBytes: 256 << 20}) {
		t.Fatalf("KyIdentity received %+v", sent)
	}
	apply := fakevault.CallsTo[vaultapi.ApplyRequest](v, "storage/apply")
	if len(apply) != 1 || apply[0].SentAt != 1_750_000_000 {
		t.Fatalf("sent_at = %+v; want the send time, not the answer time", apply)
	}
	ok, unknown := apply[0].Results[0], apply[0].Results[1]
	if ok.Result != "ok" || *ok.Seq != 7 || *ok.CeilingBytes != 1024+256<<20 || *ok.TTLSeconds != 900 || *ok.PoolBytes != 1<<30 || *ok.OrgUsedBytes != 2048 || ok.OverSince != nil {
		t.Fatalf("ok result = %+v", ok)
	}
	if unknown.Result != "unknown_org" || unknown.Seq != nil || unknown.CeilingBytes != nil {
		t.Fatalf("unknown_org result carries a grant: %+v", unknown)
	}
}

func TestReportStorageSerializesPerOrg(t *testing.T) {
	s, id, v := newSyncer(t)
	v.Reports = []vaultapi.StorageReport{{OrgID: orgA, UsedBytes: 1, Seq: 1, WantBytes: 1}}
	release, inA := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock) // runs before the fake server closes, so a failure cannot hang it
	var held, overlap atomic.Bool
	var once sync.Once
	id.onStorage = func(b []suitedir.StorageReport) {
		if !slices.ContainsFunc(b, func(r suitedir.StorageReport) bool { return r.OrgID == orgA }) {
			return
		}
		if held.Load() {
			overlap.Store(true)
			return
		}
		once.Do(func() { held.Store(true); close(inA); <-release; held.Store(false) })
	}
	ctx := context.Background()
	first := make(chan error, 1)
	go func() { first <- s.ReportStorage(ctx) }()
	<-inA

	// orgA is mid-exchange; a second poll must not send it again, but orgB goes through.
	v.Reports = []vaultapi.StorageReport{{OrgID: orgA, UsedBytes: 1, Seq: 1, WantBytes: 1}, {OrgID: orgB, UsedBytes: 2, Seq: 3, WantBytes: 4}}
	if err := s.ReportStorage(ctx); err != nil {
		t.Fatal(err)
	}
	sent := id.sent()
	if len(sent) != 2 || len(sent[1]) != 1 || sent[1][0].OrgID != orgB {
		t.Fatalf("second poll sent %+v; want orgB alone", sent)
	}
	if overlap.Load() {
		t.Fatal("orgA was exchanged twice at once")
	}
	unblock()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	// Once the first exchange ends, orgA is reportable again.
	if err := s.ReportStorage(ctx); err != nil {
		t.Fatal(err)
	}
	if sent := id.sent(); len(sent) != 3 || sent[2][0].OrgID != orgA {
		t.Fatalf("orgA stayed locked: %+v", sent)
	}
}

func TestReportStorageLogsStaleLoudly(t *testing.T) {
	s, _, v := newSyncer(t)
	var buf bytes.Buffer
	s.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	v.Reports = []vaultapi.StorageReport{{OrgID: orgA, UsedBytes: 1, Seq: 1, WantBytes: 1}, {OrgID: "NOT-A-UUID", Seq: 1}}
	v.Stale = []string{orgA}
	if err := s.ReportStorage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "level=ERROR msg=\"STORAGE SEQUENCE STALE") || !strings.Contains(buf.String(), "repair-seq") {
		t.Fatalf("stale tenants not logged loudly:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "invalid storage report") {
		t.Fatal("invalid prepared report not logged")
	}
}

func TestChunkReportsRespectsCountAndBodyLimits(t *testing.T) {
	var reports []suitedir.StorageReport
	for i := range 1300 {
		reports = append(reports, suitedir.StorageReport{OrgID: fmt.Sprintf("%08x-0000-4000-8000-000000000000", i), UsedBytes: 1 << 52, Seq: 1 << 62, WantBytes: 1 << 52})
	}
	chunks := chunkReports(reports)
	total := 0
	for _, c := range chunks {
		raw, _ := json.Marshal(map[string]any{"reports": c})
		if len(c) > 500 || len(raw) > 64<<10 {
			t.Fatalf("chunk of %d reports, %d bytes", len(c), len(raw))
		}
		total += len(c)
	}
	if total != 1300 || len(chunks) < 3 {
		t.Fatalf("%d reports in %d chunks", total, len(chunks))
	}
	small := chunkReports(reports[:3])
	if len(small) != 1 || len(small[0]) != 3 {
		t.Fatal("small set split")
	}
}

type flakyEraser struct {
	s3clean.Eraser
	fail bool
}

func (f *flakyEraser) DeleteObject(ctx context.Context, key string) error {
	if f.fail {
		return errors.New("s3 503 SlowDown")
	}
	return f.Eraser.DeleteObject(ctx, key)
}

func TestDrainCleanupReportsAndRetries(t *testing.T) {
	s, _, v := newSyncer(t)
	data := t.TempDir()
	attRoot, sendRoot := filepath.Join(data, "attachments"), filepath.Join(data, "sends")
	files := map[string]string{
		"att":     filepath.Join(attRoot, "cells", "eu-west-1", "tenants", orgA, "attachments", "c1", "a1"),
		"send":    filepath.Join(sendRoot, "cells", "eu-west-1", "tenants", orgA, "sends", "s1", "f1"),
		"purgeA":  filepath.Join(attRoot, "cells", "eu-west-2", "tenants", orgB, "attachments", "c2", "a2"),
		"purgeS":  filepath.Join(sendRoot, "cells", "eu-west-2", "tenants", orgB, "sends", "s2", "f2"),
		"other":   filepath.Join(attRoot, "cells", "eu-west-1", "tenants", orgC, "attachments", "c3", "a3"),
		"foreign": filepath.Join(attRoot, "cells", "us-east-1", "tenants", orgA, "attachments", "c4", "a4"),
		"outside": filepath.Join(data, "db.sqlite3"),
	}
	for _, f := range files {
		_ = os.MkdirAll(filepath.Dir(f), 0o755)
		_ = os.WriteFile(f, []byte("x"), 0o600)
	}
	att := &flakyEraser{Eraser: &s3clean.LocalFS{Root: attRoot}, fail: true}
	s.Attachments, s.Sends = att, &s3clean.LocalFS{Root: sendRoot}
	v.Queue = []vaultapi.CleanupItem{
		{ID: "1", TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/attachments/c1/a1"},
		{ID: "2", TenantID: orgA, StorageKind: "send", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/sends/s1"},
		{ID: "3", TenantID: orgB, StorageKind: "tenant_prefix", ObjectKey: "cells/eu-west-2/tenants/" + orgB + "/"},
		{ID: "4", TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/attachments/../../../db.sqlite3"},
		{ID: "5", TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/eu-west-1/tenants/" + orgC + "/attachments/c3/a3"},
		{ID: "6", TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/us-east-1/tenants/" + orgA + "/attachments/c4/a4"},
	}
	ctx := context.Background()

	if err := s.DrainCleanup(ctx); err == nil {
		t.Fatal("expected failures to be reported")
	}
	remaining := func() []string {
		var ids []string
		for _, it := range v.Queue {
			ids = append(ids, it.ID)
		}
		sort.Strings(ids)
		return ids
	}
	if got := strings.Join(remaining(), ","); got != "1,4,5,6" {
		t.Fatalf("queue after outage = %s, want 1,4,5,6", got)
	}
	if !strings.Contains(v.Failures["1"], "503") || v.Failures["4"] == "" || v.Failures["5"] == "" || !strings.Contains(v.Failures["6"], "unserved cell") {
		t.Fatalf("failures not reported: %v", v.Failures)
	}
	if _, err := os.Stat(files["att"]); err != nil {
		t.Fatal("a failed item's object vanished")
	}

	att.fail = false
	_ = s.DrainCleanup(ctx)
	if got := strings.Join(remaining(), ","); got != "4,5,6" {
		t.Fatalf("queue after recovery = %s, want only the refused items", got)
	}
	for name, want := range map[string]bool{"att": false, "send": false, "purgeA": false, "purgeS": false, "other": true, "foreign": true, "outside": true} {
		if _, err := os.Stat(files[name]); (err == nil) != want {
			t.Errorf("%s exists=%v, want %v", name, err == nil, want)
		}
	}
	complete := fakevault.CallsTo[vaultapi.CleanupCompleteRequest](v, "cleanup/complete")
	if len(complete) < 2 || complete[0].CompletedIDs == nil || complete[0].Failed == nil {
		t.Fatalf("complete requests = %+v", complete)
	}
}

func TestDrainCleanupUnconfiguredRootFails(t *testing.T) {
	s, _, v := newSyncer(t)
	v.Queue = []vaultapi.CleanupItem{{ID: "1", TenantID: orgA, StorageKind: "tenant_prefix", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/"}}
	if err := s.DrainCleanup(context.Background()); err == nil || len(v.Queue) != 1 {
		t.Fatal("cleanup without storage roots must fail and stay pending")
	}
}

func TestCheckItem(t *testing.T) {
	cells := []string{"eu-west-1", "eu-west-2"}
	ok := []vaultapi.CleanupItem{
		{TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/attachments/c/a.b"},
		{TenantID: orgA, StorageKind: "send", ObjectKey: "cells/eu-west-2/tenants/" + orgA + "/sends/s"},
		{TenantID: orgA, StorageKind: "send", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/sends/s/f"},
		{TenantID: orgA, StorageKind: "tenant_prefix", ObjectKey: "cells/eu-west-2/tenants/" + orgA + "/"},
	}
	bad := []vaultapi.CleanupItem{
		{TenantID: orgA, StorageKind: "attachment", ObjectKey: "tenants/" + orgA + "/attachments/c/a.b"},
		{TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/us-east-1/tenants/" + orgA + "/attachments/c/a.b"},
		{TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/EU-WEST-1/tenants/" + orgA + "/attachments/c/a.b"},
		{TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/attachments/c"},
		{TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/attachments/c/../x"},
		{TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/attachments/c/.hidden"},
		{TenantID: orgA, StorageKind: "attachment", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/sends/s/f"},
		{TenantID: orgA, StorageKind: "send", ObjectKey: "cells/eu-west-1/tenants/" + orgB + "/sends/s"},
		{TenantID: orgA, StorageKind: "send", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/sends/s/f/g"},
		{TenantID: orgA, StorageKind: "tenant_prefix", ObjectKey: "cells/eu-west-1/tenants/"},
		{TenantID: orgA, StorageKind: "tenant_prefix", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/attachments/"},
		{TenantID: "../x", StorageKind: "tenant_prefix", ObjectKey: "cells/eu-west-1/tenants/../x/"},
		{TenantID: orgA, StorageKind: "icon_cache", ObjectKey: "cells/eu-west-1/tenants/" + orgA + "/"},
	}
	for _, it := range ok {
		if err := checkItem(it, cells); err != nil {
			t.Errorf("refused %+v: %v", it, err)
		}
	}
	for _, it := range bad {
		if checkItem(it, cells) == nil {
			t.Errorf("accepted %+v", it)
		}
	}
}

func TestReconcileRefusesSingleTenantVaultAndOrdersOrgsFirst(t *testing.T) {
	s, id, v := newSyncer(t)
	id.orgs = []map[string]any{org(orgA, 1, "active", true)}
	id.erased = []map[string]any{erasedRow("usr_1", orgA, 1)}
	v.SingleTenant = true
	if err := s.Reconcile(context.Background(), true); err == nil {
		t.Fatal("a single-tenant vault was accepted")
	}
	if id.sawQuery("/") {
		t.Fatal("KyIdentity was polled before the vault was verified")
	}
	v.SingleTenant = false
	if err := s.Reconcile(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, p := range v.Paths() {
		if p == "orgs/reconcile" || p == "users/erase" {
			order = append(order, p)
		}
	}
	if strings.Join(order, ",") != "orgs/reconcile,users/erase" {
		t.Fatalf("order = %v", order)
	}
}
