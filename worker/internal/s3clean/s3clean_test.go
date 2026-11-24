package s3clean

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientDeletePrefixPaginatedAndSigV4(t *testing.T) {
	var mu sync.Mutex
	var deletedKeys []string
	listCalls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIA_TEST/20261124/us-east-1/s3/aws4_request,") {
			t.Errorf("unexpected SigV4 Authorization header: %s", auth)
			http.Error(w, "bad auth", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
			mu.Lock()
			listCalls++
			call := listCalls
			mu.Unlock()
			if got := r.URL.Query().Get("prefix"); got != "vault/tenants/org-alpha/" {
				t.Errorf("unexpected list prefix: %q", got)
			}
			w.Header().Set("Content-Type", "application/xml")
			if call == 1 {
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>tok-2</NextContinuationToken>
  <Contents><Key>vault/tenants/org-alpha/attachments/c1/a1</Key></Contents>
  <Contents><Key>vault/tenants/org-alpha/attachments/c1/a2</Key></Contents>
</ListBucketResult>`))
			} else {
				if got := r.URL.Query().Get("continuation-token"); got != "tok-2" {
					t.Errorf("expected continuation-token=tok-2, got %q", got)
				}
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>vault/tenants/org-alpha/sends/s1/f1</Key></Contents>
</ListBucketResult>`))
			}
			return
		}
		if r.Method == http.MethodPost && r.URL.Query().Has("delete") {
			if r.Header.Get("Content-MD5") == "" {
				t.Error("missing Content-MD5 on DeleteObjects request")
			}
			raw, _ := io.ReadAll(r.Body)
			var req deleteRequest
			if err := xml.Unmarshal(raw, &req); err != nil {
				t.Errorf("invalid delete XML: %v", err)
				http.Error(w, "bad xml", http.StatusBadRequest)
				return
			}
			mu.Lock()
			for _, obj := range req.Objects {
				deletedKeys = append(deletedKeys, obj.Key)
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><DeleteResult></DeleteResult>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &Client{
		Endpoint:        srv.URL,
		Bucket:          "kyvault-bucket",
		Region:          "us-east-1",
		AccessKeyID:     "AKIA_TEST",
		SecretAccessKey: "SECRET_TEST",
		ForcePathStyle:  true,
		KeyPrefix:       "vault",
		HTTPClient:      srv.Client(),
		Now:             func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) },
	}

	n, err := client.DeletePrefix(context.Background(), "tenants/org-alpha/")
	if err != nil {
		t.Fatalf("DeletePrefix failed: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 deleted objects, got %d", n)
	}
	if len(deletedKeys) != 3 {
		t.Fatalf("expected 3 recorded deletes, got %v", deletedKeys)
	}
}

func TestClientRefusesUnsafePrefixes(t *testing.T) {
	client := &Client{Bucket: "b", AccessKeyID: "k", SecretAccessKey: "s"}
	for _, bad := range []string{"", "/", "tenants/", "/tenants/", "attachments/123", "other/tenants/x"} {
		if _, err := client.DeletePrefix(context.Background(), bad); err == nil {
			t.Errorf("expected error for unsafe prefix %q", bad)
		}
	}
}

func TestClientFailsOnRetentionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>tenants/org-a/a1</Key></Contents></ListBucketResult>`))
			return
		}
		_, _ = w.Write([]byte(`<DeleteResult><Error><Key>tenants/org-a/a1</Key><Code>AccessDenied</Code><Message>Object Lock</Message></Error></DeleteResult>`))
	}))
	defer srv.Close()

	client := &Client{
		Endpoint:        srv.URL,
		Bucket:          "b",
		Region:          "us-east-1",
		AccessKeyID:     "k",
		SecretAccessKey: "s",
		ForcePathStyle:  true,
		HTTPClient:      srv.Client(),
	}
	if _, err := client.DeletePrefix(context.Background(), "tenants/org-a/"); err == nil {
		t.Fatal("expected DeletePrefix to fail on AccessDenied retention error")
	}
}

func TestLocalFSEraserIsolationAndTraversalGuard(t *testing.T) {
	root := t.TempDir()
	orgAFile := filepath.Join(root, "tenants", "org-a", "attachments", "c1", "f1")
	orgBFile := filepath.Join(root, "tenants", "org-b", "attachments", "c2", "f2")
	if err := os.MkdirAll(filepath.Dir(orgAFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(orgBFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orgAFile, []byte("secret-a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orgBFile, []byte("secret-b"), 0o600); err != nil {
		t.Fatal(err)
	}

	eraser := &LocalFSEraser{DataFolder: root}

	// Reject traversal & unsafe prefixes
	for _, bad := range []string{"", "tenants/", "tenants/../etc", "attachments/c1"} {
		if _, err := eraser.DeletePrefix(context.Background(), bad); err == nil {
			t.Errorf("expected LocalFSEraser to reject unsafe prefix %q", bad)
		}
	}

	// Erase org-a only
	if _, err := eraser.DeletePrefix(context.Background(), "tenants/org-a/"); err != nil {
		t.Fatalf("erase org-a failed: %v", err)
	}
	if _, err := os.Stat(orgAFile); !os.IsNotExist(err) {
		t.Fatalf("expected org-a file to be deleted, stat err=%v", err)
	}
	if _, err := os.Stat(orgBFile); err != nil {
		t.Fatalf("expected org-b file to remain intact, stat err=%v", err)
	}
}
