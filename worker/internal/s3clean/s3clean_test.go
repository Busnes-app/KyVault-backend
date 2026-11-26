package s3clean

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeS3 is a versioned bucket: every key holds versions and delete markers.
type fakeS3 struct {
	t        *testing.T
	mu       sync.Mutex
	versions map[string][]string // key -> version IDs (delete markers included)
	uploads  map[string]string   // uploadID -> key
	pageSize int
	// deleteErr, when set, is returned per key by DeleteObjects.
	deleteErr string
	// noop makes DeleteObjects answer success without deleting.
	noop bool
	// legacy answers ListBucketResult, as a provider without ListObjectVersions might.
	legacy bool
}

func newFakeS3(t *testing.T) (*fakeS3, *httptest.Server) {
	f := &fakeS3{t: t, versions: map[string][]string{}, uploads: map[string]string{}, pageSize: 2}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeS3) put(key string, versions ...string) {
	f.versions[key] = append(f.versions[key], versions...)
}

func (f *fakeS3) remaining() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k, v := range f.versions {
		if len(v) > 0 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIA/20261124/us-east-1/s3/aws4_request, SignedHeaders=") {
		f.t.Errorf("bad SigV4 header %q", r.Header.Get("Authorization"))
	}
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && q.Has("versions"):
		if f.legacy {
			fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>x</Key></Contents></ListBucketResult>`)
			return
		}
		f.listVersions(w, q)
	case r.Method == http.MethodGet && q.Has("uploads"):
		var b strings.Builder
		b.WriteString(`<ListMultipartUploadsResult><IsTruncated>false</IsTruncated>`)
		for id, key := range f.uploads {
			if strings.HasPrefix(key, q.Get("prefix")) {
				fmt.Fprintf(&b, `<Upload><Key>%s</Key><UploadId>%s</UploadId></Upload>`, key, id)
			}
		}
		b.WriteString(`</ListMultipartUploadsResult>`)
		fmt.Fprint(w, b.String())
	case r.Method == http.MethodDelete && q.Has("uploadId"):
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		if f.uploads[q.Get("uploadId")] != key {
			http.Error(w, "<Error><Code>NoSuchUpload</Code></Error>", http.StatusNotFound)
			return
		}
		delete(f.uploads, q.Get("uploadId"))
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && q.Has("delete"):
		if r.Header.Get("Content-MD5") == "" {
			f.t.Error("DeleteObjects without Content-MD5")
		}
		raw, _ := io.ReadAll(r.Body)
		var req deleteRequest
		if err := xml.Unmarshal(raw, &req); err != nil {
			f.t.Errorf("bad delete body: %v", err)
		}
		var b strings.Builder
		b.WriteString("<DeleteResult>")
		for _, o := range req.Objects {
			if o.VersionID == "" {
				f.t.Errorf("delete of %q without a version ID would only add a delete marker", o.Key)
			}
			if f.deleteErr != "" {
				fmt.Fprintf(&b, "<Error><Key>%s</Key><Code>%s</Code><Message>retained</Message></Error>", o.Key, f.deleteErr)
				continue
			}
			if f.noop {
				continue
			}
			vs := f.versions[o.Key]
			for i, v := range vs {
				if v == o.VersionID {
					f.versions[o.Key] = append(vs[:i:i], vs[i+1:]...)
					break
				}
			}
		}
		b.WriteString("</DeleteResult>")
		fmt.Fprint(w, b.String())
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	}
}

func (f *fakeS3) listVersions(w http.ResponseWriter, q map[string][]string) {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	type entry struct{ key, ver string }
	var all []entry
	for k, vs := range f.versions {
		if strings.HasPrefix(k, get("prefix")) {
			for _, v := range vs {
				all = append(all, entry{k, v})
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].key != all[j].key {
			return all[i].key < all[j].key
		}
		return all[i].ver < all[j].ver
	})
	start := 0
	if km := get("key-marker"); km != "" {
		for start < len(all) && (all[start].key < km || all[start].key == km && all[start].ver <= get("version-id-marker")) {
			start++
		}
	}
	end := min(start+f.pageSize, len(all))
	var b strings.Builder
	b.WriteString("<ListVersionsResult>")
	if end < len(all) {
		fmt.Fprintf(&b, "<IsTruncated>true</IsTruncated><NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>%s</NextVersionIdMarker>",
			all[end-1].key, all[end-1].ver)
	} else {
		b.WriteString("<IsTruncated>false</IsTruncated>")
	}
	for _, e := range all[start:end] {
		tag := "Version"
		if strings.HasPrefix(e.ver, "dm") {
			tag = "DeleteMarker"
		}
		fmt.Fprintf(&b, "<%s><Key>%s</Key><VersionId>%s</VersionId></%s>", tag, e.key, e.ver, tag)
	}
	b.WriteString("</ListVersionsResult>")
	fmt.Fprint(w, b.String())
}

func testClient(srv *httptest.Server) *Client {
	return &Client{
		Endpoint: srv.URL, Bucket: "bucket", Region: "us-east-1", AccessKeyID: "AKIA", SecretAccessKey: "secret",
		ForcePathStyle: true, Root: "data/attachments", HTTPClient: srv.Client(),
		Now: func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) },
	}
}

func TestDeletePrefixRemovesVersionsMarkersAndUploads(t *testing.T) {
	f, srv := newFakeS3(t)
	f.put("data/attachments/cells/eu-west-1/tenants/org-a/attachments/c1/a1", "v1", "v2", "dm3")
	f.put("data/attachments/cells/eu-west-1/tenants/org-a/attachments/c1/a2", "v1")
	f.put("data/attachments/cells/eu-west-1/tenants/org-a/attachments/c2/a3", "dm1")
	f.put("data/attachments/cells/eu-west-1/tenants/org-b/attachments/c9/a9", "v1")
	f.uploads["u1"] = "data/attachments/cells/eu-west-1/tenants/org-a/attachments/c3/partial"
	f.uploads["u2"] = "data/attachments/cells/eu-west-1/tenants/org-b/attachments/c3/partial"

	if err := testClient(srv).DeletePrefix(context.Background(), "cells/eu-west-1/tenants/org-a/"); err != nil {
		t.Fatalf("DeletePrefix: %v", err)
	}
	if got := f.remaining(); len(got) != 1 || got[0] != "data/attachments/cells/eu-west-1/tenants/org-b/attachments/c9/a9" {
		t.Fatalf("remaining = %v, want only org-b", got)
	}
	if _, ok := f.uploads["u1"]; ok {
		t.Fatal("org-a multipart upload was not aborted")
	}
	if _, ok := f.uploads["u2"]; !ok {
		t.Fatal("org-b multipart upload was aborted")
	}
}

func TestDeleteObjectExactKeyOnly(t *testing.T) {
	f, srv := newFakeS3(t)
	key := "cells/eu-west-1/tenants/org-a/sends/s1"
	f.put("data/attachments/"+key, "v1", "dm2")
	f.put("data/attachments/"+key+"/file-1", "v1")
	f.put("data/attachments/"+key+"0/file", "v1") // shares the string prefix, not the path
	if err := testClient(srv).DeleteObject(context.Background(), key); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if got := f.remaining(); len(got) != 1 || got[0] != "data/attachments/"+key+"0/file" {
		t.Fatalf("remaining = %v", got)
	}
}

func TestDeleteFailuresAreErrors(t *testing.T) {
	cases := map[string]func(*fakeS3){
		"retention":    func(f *fakeS3) { f.deleteErr = "AccessDenied" },
		"silent no-op": func(f *fakeS3) { f.noop = true },
		"no versions":  func(f *fakeS3) { f.legacy = true },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f, srv := newFakeS3(t)
			f.put("data/attachments/cells/eu-west-1/tenants/org-a/attachments/c/a", "v1")
			setup(f)
			if err := testClient(srv).DeleteObject(context.Background(), "cells/eu-west-1/tenants/org-a/attachments/c/a"); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestProviderErrorStatusIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "<Error><Code>NoSuchBucket</Code></Error>", http.StatusNotFound)
	}))
	defer srv.Close()
	if err := testClient(srv).DeletePrefix(context.Background(), "cells/eu-west-1/tenants/org-a/"); err == nil {
		t.Fatal("a missing bucket must not count as an empty one")
	}
}

func TestUnsafeKeysRefused(t *testing.T) {
	_, srv := newFakeS3(t)
	c := testClient(srv)
	l := &LocalFS{Root: t.TempDir()}
	for _, bad := range []string{
		"", "/", "tenants/", "tenants/org-a/", "cells/", "cells/eu-west-1/", "cells/eu-west-1/tenants/",
		"cells/EU-WEST-1/tenants/org-a/", "cells/../tenants/org-a/", "/cells/eu-west-1/tenants/org-a/",
		"attachments/x", "cells/eu-west-1/tenants/../x/", "cells/eu-west-1/tenants/a/../../x",
		`cells\eu-west-1\tenants\x/`, "cells/eu-west-1/tenants//x/",
	} {
		if err := c.DeletePrefix(context.Background(), bad); err == nil {
			t.Errorf("S3 DeletePrefix(%q) accepted", bad)
		}
		if err := l.DeletePrefix(context.Background(), bad); err == nil {
			t.Errorf("LocalFS DeletePrefix(%q) accepted", bad)
		}
		if err := l.DeleteObject(context.Background(), strings.TrimSuffix(bad, "/")); err == nil {
			t.Errorf("LocalFS DeleteObject(%q) accepted", bad)
		}
	}
}

func TestLocalFSUsesRealRoots(t *testing.T) {
	data := t.TempDir()
	attachments := filepath.Join(data, "attachments")
	sends := filepath.Join(data, "sends")
	files := []string{
		filepath.Join(attachments, "cells/eu-west-1/tenants/org-a/attachments/c1/a1"),
		filepath.Join(attachments, "cells/eu-west-1/tenants/org-b/attachments/c1/a1"),
		filepath.Join(sends, "cells/eu-west-1/tenants/org-a/sends/s1/f1"),
		filepath.Join(data, "db.sqlite3"),
	}
	for _, f := range files {
		_ = os.MkdirAll(filepath.Dir(f), 0o755)
		_ = os.WriteFile(f, []byte("x"), 0o600)
	}
	ctx := context.Background()
	att, snd := &LocalFS{Root: attachments}, &LocalFS{Root: sends}

	if err := att.DeleteObject(ctx, "cells/eu-west-1/tenants/org-a/attachments/c1/a1"); err != nil {
		t.Fatal(err)
	}
	if err := snd.DeleteObject(ctx, "cells/eu-west-1/tenants/org-a/sends/s1"); err != nil {
		t.Fatal(err)
	}
	if err := att.DeleteObject(ctx, "cells/eu-west-1/tenants/org-a/attachments/c1/a1"); err != nil {
		t.Fatalf("an already deleted object must succeed: %v", err)
	}
	for i, want := range []bool{false, true, false, true} {
		if _, err := os.Stat(files[i]); (err == nil) != want {
			t.Errorf("%s exists=%v, want %v", files[i], err == nil, want)
		}
	}
	if err := att.DeletePrefix(ctx, "cells/eu-west-1/tenants/org-b/"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(attachments, "cells/eu-west-1/tenants/org-b")); !os.IsNotExist(err) {
		t.Fatal("org-b prefix survived")
	}
}

func TestLocalFSSymlinkEscapeAndMissingRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	victim := filepath.Join(outside, "victim")
	_ = os.WriteFile(victim, []byte("x"), 0o600)
	_ = os.MkdirAll(filepath.Join(root, "cells", "eu-west-1", "tenants"), 0o755)
	if err := os.Symlink(outside, filepath.Join(root, "cells", "eu-west-1", "tenants", "org-a")); err != nil {
		t.Fatal(err)
	}
	_ = (&LocalFS{Root: root}).DeleteObject(context.Background(), "cells/eu-west-1/tenants/org-a/victim")
	if _, err := os.Stat(victim); err != nil {
		t.Fatal("a symlink let deletion escape the storage root")
	}

	missing := &LocalFS{Root: filepath.Join(root, "not-mounted")}
	if err := missing.DeleteObject(context.Background(), "cells/eu-west-1/tenants/org-a/attachments/c/a"); err == nil {
		t.Fatal("a missing storage root must fail, not report the object deleted")
	}
}

func TestForRoot(t *testing.T) {
	base := Client{Endpoint: "https://s3.example", AccessKeyID: "k", SecretAccessKey: "s"}
	e, err := ForRoot("s3://vault-bucket/data/attachments/", base)
	if err != nil {
		t.Fatal(err)
	}
	if c := e.(*Client); c.Bucket != "vault-bucket" || c.Root != "data/attachments" || c.Endpoint != base.Endpoint {
		t.Fatalf("parsed %+v", c)
	}
	if e, _ := ForRoot("/srv/data/sends", base); e.(*LocalFS).Root != "/srv/data/sends" {
		t.Fatal("local root not parsed")
	}
	if e, err := ForRoot("", base); e != nil || err != nil {
		t.Fatal("empty root must be unconfigured")
	}
	for _, bad := range []string{"s3://", "s3:///x", "s3://b/x?endpoint=http://evil"} {
		if _, err := ForRoot(bad, base); err == nil {
			t.Errorf("ForRoot(%q) accepted", bad)
		}
	}
}
