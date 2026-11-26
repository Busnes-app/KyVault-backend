// Package fakevault is an in-memory /internal/tenancy/v1 server for tests, following the
// frozen contract the Rust server implements.
package fakevault

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Busnes-app/kyvault-worker/internal/vaultapi"
)

const Secret = "test-internal-secret-0123456789abcdef"

type Call struct {
	Path string
	Body json.RawMessage
}

type Vault struct {
	t   *testing.T
	URL string

	mu sync.Mutex
	// Fail makes the next N calls to a path ("users/sync") answer 500 (or FailStatus[path]).
	Fail       map[string]int
	FailStatus map[string]int
	Calls      []Call
	// Cells is returned by health; defaults to ["eu-west-1"] when empty.
	Cells []string
	// PurgeRequired and RegionMismatch are returned by the next orgs/reconcile, then cleared.
	PurgeRequired  []string
	RegionMismatch []string
	// ErasePending is the pending_deletions_queued each users/erase reports.
	ErasePending int
	// Queue is the durable cleanup queue; completed items leave it, failed ones stay.
	Queue    []vaultapi.CleanupItem
	Failures map[string]string
	// Reports is what storage/prepare returns.
	Reports []vaultapi.StorageReport
	Stale   []string
	// SingleTenant makes health report multi_tenant false.
	SingleTenant bool
}

func New(t *testing.T) *Vault {
	v := &Vault{t: t, Fail: map[string]int{}, FailStatus: map[string]int{}, Failures: map[string]string{}, Cells: []string{"eu-west-1"}}
	srv := httptest.NewServer(v)
	t.Cleanup(srv.Close)
	v.URL = srv.URL
	return v
}

func (v *Vault) Client(t *testing.T) *vaultapi.Client {
	c, err := vaultapi.New(v.URL, Secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// CallsTo returns the decoded bodies sent to path, in order.
func CallsTo[T any](v *Vault, path string) []T {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []T
	for _, c := range v.Calls {
		if c.Path == path {
			var x T
			if len(c.Body) > 0 {
				_ = json.Unmarshal(c.Body, &x)
			}
			out = append(out, x)
		}
	}
	return out
}

// Paths returns the paths called, in order.
func (v *Vault) Paths() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]string, len(v.Calls))
	for i, c := range v.Calls {
		out[i] = c.Path
	}
	return out
}

func (v *Vault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+Secret {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/internal/tenancy/v1/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "application/json" {
		v.t.Errorf("%s without a JSON content type", path)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.Calls = append(v.Calls, Call{Path: path, Body: body})
	if v.Fail[path] > 0 {
		v.Fail[path]--
		code := v.FailStatus[path]
		if code == 0 {
			code = http.StatusInternalServerError
		}
		http.Error(w, `{"error":"simulated"}`, code)
		return
	}
	var out any
	switch {
	case path == "health":
		out = vaultapi.Health{Status: "ok", MultiTenant: !v.SingleTenant, Cells: append([]string{}, v.Cells...)}
	case path == "orgs/reconcile":
		var req vaultapi.ReconcileRequest
		_ = json.Unmarshal(body, &req)
		out = vaultapi.ReconcileResult{
			Applied:                 len(req.Orgs),
			FencedTenantIDs:         []string{},
			PurgeRequiredTenantIDs:  append([]string{}, v.PurgeRequired...),
			RegionMismatchTenantIDs: append([]string{}, v.RegionMismatch...),
		}
		v.PurgeRequired = nil
		v.RegionMismatch = nil
	case path == "users/logout":
		out = vaultapi.LogoutResult{Found: true, UserUUID: "u-1"}
	case path == "users/sync":
		out = vaultapi.SyncResult{Status: "ok", UserUUID: "u-1"}
	case path == "users/erase":
		out = vaultapi.EraseResult{Status: "erased", TombstoneRecorded: true, PendingDeletionsQueued: v.ErasePending}
	case strings.HasPrefix(path, "tenants/") && strings.HasSuffix(path, "/purge/begin"):
		out = vaultapi.PurgeResult{Status: "purge_pending", PendingDeletions: len(v.Queue)}
	case path == "cleanup/pending":
		out = map[string]any{"items": append([]vaultapi.CleanupItem{}, v.Queue...)}
	case path == "cleanup/complete":
		var req vaultapi.CleanupCompleteRequest
		_ = json.Unmarshal(body, &req)
		done := map[string]bool{}
		for _, id := range req.CompletedIDs {
			done[id] = true
		}
		kept := v.Queue[:0]
		for _, it := range v.Queue {
			if !done[it.ID] {
				kept = append(kept, it)
			}
		}
		v.Queue = kept
		for _, f := range req.Failed {
			v.Failures[f.ID] = f.Error
			for i := range v.Queue {
				if v.Queue[i].ID == f.ID {
					v.Queue[i].Attempts++
				}
			}
		}
		out = vaultapi.CleanupCompleteResult{Deleted: len(done), FailedUpdated: len(req.Failed), FinalizedTenantIDs: []string{}}
	case path == "storage/prepare":
		out = map[string]any{"reports": append([]vaultapi.StorageReport{}, v.Reports...)}
	case path == "storage/apply":
		var req vaultapi.ApplyRequest
		_ = json.Unmarshal(body, &req)
		out = vaultapi.ApplyResult{Applied: len(req.Results), StaleTenantIDs: append([]string{}, v.Stale...)}
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
