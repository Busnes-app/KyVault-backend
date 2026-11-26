package vaultapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const secret = "test-internal-secret-0123456789abcdef"

func TestBearerPathAndStatus(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		if strings.HasSuffix(r.URL.Path, "/purge/begin") {
			_, _ = w.Write([]byte(`{"status":"purge_pending","pending_deletions":5}`))
			return
		}
		http.Error(w, `{"error":"bad"}`, http.StatusUnprocessableEntity)
	}))
	defer srv.Close()
	c, err := New(srv.URL+"/", secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.BeginPurge(context.Background(), "org/../x")
	if err != nil || res.PendingDeletions != 5 {
		t.Fatalf("BeginPurge = %+v, %v", res, err)
	}
	if gotPath != "/internal/tenancy/v1/tenants/org%2F..%2Fx/purge/begin" || gotAuth != "Bearer "+secret {
		t.Fatalf("path %q auth %q", gotPath, gotAuth)
	}
	_, err = c.SyncUser(context.Background(), SyncRequest{})
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusUnprocessableEntity {
		t.Fatalf("SyncUser error = %v", err)
	}
}

func TestRefusesRedirectsAndOversizedAnswers(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") != ""
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/tenancy/v1/health" {
			http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
			return
		}
		_, _ = w.Write([]byte(`{"items":["` + strings.Repeat("x", maxResponse) + `"]}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, secret, nil)
	if _, err := c.Health(context.Background()); err == nil || leaked {
		t.Fatalf("redirect followed (err %v, leaked %v)", err, leaked)
	}
	if _, err := c.PendingCleanup(context.Background(), 100); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized answer = %v", err)
	}
}

func TestMissingListsAreErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, secret, nil)
	if _, err := c.PendingCleanup(context.Background(), 1); err == nil {
		t.Error("cleanup/pending without items accepted")
	}
	if _, err := c.PrepareStorage(context.Background(), PrepareRequest{}); err == nil {
		t.Error("storage/prepare without reports accepted")
	}
}
