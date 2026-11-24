package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/oidcverify"
	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyvault-worker/internal/fakevault"
	"github.com/Busnes-app/kyvault-worker/internal/state"
)

const (
	issuer      = "https://id.example"
	audience    = "kyvault"
	orgID       = "aaaaaaaa-0000-4000-8000-000000000001"
	hookSecret  = "sync-webhook-secret-0123456789abcdef"
	backchannel = "http://schemas.openid.net/event/backchannel-logout"
)

type harness struct {
	srv     *Server
	h       http.Handler
	vault   *fakevault.Vault
	key     *rsa.PrivateKey
	kicks   atomic.Int32
	nextJTI int
}

func newHarness(t *testing.T) *harness {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwks.Close)
	v := fakevault.New(t)
	hs := &harness{vault: v, key: key}
	hs.srv = &Server{
		Issuer:            issuer,
		SyncWebhookSecret: []byte(hookSecret),
		LogoutVerifier:    &oidcverify.Verifier{Issuer: issuer, Audience: audience, JWKSURL: jwks.URL, HTTPClient: jwks.Client()},
		State:             state.NewMemory(),
		Vault:             v.Client(t),
		TriggerCleanup:    func() { hs.kicks.Add(1) },
	}
	hs.srv.SetReady()
	hs.h = hs.srv.Handler()
	return hs
}

func (hs *harness) do(r *http.Request) (int, map[string]any) {
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, r)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func (hs *harness) webhook(t *testing.T, eventType, eventID string, body any) (int, map[string]any) {
	raw, _ := json.Marshal(body)
	headers, err := syncauth.Sign([]byte(hookSecret), time.Now(), eventType, eventID, raw)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/sync/events", bytes.NewReader(raw))
	headers.Apply(r)
	return hs.do(r)
}

func (hs *harness) logout(t *testing.T, claims map[string]any) (int, map[string]any) {
	r := httptest.NewRequest(http.MethodPost, "/api/oidc/backchannel-logout",
		strings.NewReader(url.Values{"logout_token": {hs.sign(t, claims)}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return hs.do(r)
}

func (hs *harness) logoutClaims(sub string) map[string]any {
	hs.nextJTI++
	now := time.Now()
	c := map[string]any{
		"iss": issuer, "aud": audience, "jti": "jti-" + strconv.Itoa(hs.nextJTI),
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"events": map[string]any{backchannel: map[string]any{}},
	}
	if sub != "" {
		c["sub"] = sub
	} else {
		c["sid"] = "session-1"
	}
	return c
}

func (hs *harness) sign(t *testing.T, claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]any{"alg": "RS256", "typ": "logout+jwt", "kid": "k1"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, hs.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func scimUser(active bool) map[string]any {
	return map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":      "usr_123", "externalId": "usr_123", "userName": "alice", "displayName": "Alice",
		"emails": []map[string]any{
			{"value": "post@mail.example", "type": "mailbox", "primary": false},
			{"value": "alice@example.com", "type": "work", "primary": true},
		},
		"active": active, "org_id": orgID,
	}
}

func TestWebhookRetryAfterTransientFailureApplies(t *testing.T) {
	hs := newHarness(t)
	hs.vault.Fail["users/sync"] = 1

	if code, _ := hs.webhook(t, "user.deleted", "evt-1", scimUser(false)); code != http.StatusBadGateway {
		t.Fatalf("first delivery = %d, want 502", code)
	}
	code, body := hs.webhook(t, "user.deleted", "evt-1", scimUser(false))
	if code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("retry = %d %v; a failed attempt must not become a duplicate", code, body)
	}
	code, body = hs.webhook(t, "user.deleted", "evt-1", scimUser(false))
	if code != http.StatusOK || body["status"] != "duplicate" {
		t.Fatalf("replay = %d %v, want duplicate", code, body)
	}

	calls := fakevault.CallsTo[map[string]any](hs.vault, "users/sync")
	if len(calls) != 2 {
		t.Fatalf("vault saw %d sync calls, want the failure and one success", len(calls))
	}
	want := map[string]any{
		"event_type": "user.deleted", "issuer": issuer, "subject": "usr_123", "tenant_id": orgID,
		"email": "alice@example.com", "display_name": "Alice", "active": false,
	}
	for k, v := range want {
		if calls[1][k] != v {
			t.Errorf("sync %s = %v, want %v", k, calls[1][k], v)
		}
	}
}

func TestWebhookUserErased(t *testing.T) {
	hs := newHarness(t)
	hs.vault.ErasePending = 3
	body := map[string]any{"id": "usr_9", "externalId": "usr_9", "active": false, "org_id": orgID}
	if code, b := hs.webhook(t, "user.erased", "evt-2", body); code != http.StatusOK || b["status"] != "ok" {
		t.Fatalf("erase = %d %v", code, b)
	}
	calls := fakevault.CallsTo[map[string]any](hs.vault, "users/erase")
	if len(calls) != 1 || calls[0]["issuer"] != issuer || calls[0]["subject"] != "usr_9" || calls[0]["tenant_id"] != orgID {
		t.Fatalf("erase request = %v", calls)
	}
	if rev, present := calls[0]["revision"]; !present || rev != nil {
		t.Fatalf("webhook erase revision = %v (present %v), want explicit null", rev, present)
	}
	if hs.kicks.Load() != 1 {
		t.Fatal("queued deletions did not trigger cleanup")
	}
}

func TestWebhookRejections(t *testing.T) {
	hs := newHarness(t)

	r := httptest.NewRequest(http.MethodPost, "/api/sync/events", strings.NewReader(`{}`))
	syncauth.Headers{Signature: "sha256=00", Timestamp: time.Now().Format(time.RFC3339), EventType: "user.updated", EventID: "x"}.Apply(r)
	if code, _ := hs.do(r); code != http.StatusUnauthorized {
		t.Errorf("bad signature = %d", code)
	}

	mismatch := scimUser(true)
	mismatch["externalId"] = "usr_other"
	if code, _ := hs.webhook(t, "user.updated", "evt-3", mismatch); code != http.StatusBadRequest {
		t.Errorf("id/externalId mismatch = %d", code)
	}
	noActive := scimUser(true)
	delete(noActive, "active")
	if code, _ := hs.webhook(t, "user.updated", "evt-4", noActive); code != http.StatusBadRequest {
		t.Errorf("missing active = %d", code)
	}
	if code, b := hs.webhook(t, "org.updated", "evt-5", map[string]any{"org_id": orgID}); code != http.StatusOK || b["status"] != "ignored" {
		t.Errorf("unknown type = %d %v", code, b)
	}
	if n := len(fakevault.CallsTo[struct{}](hs.vault, "users/sync")); n != 0 {
		t.Errorf("rejected events reached the vault %d times", n)
	}

	notReady := &Server{SyncWebhookSecret: []byte(hookSecret), State: state.NewMemory()}
	rec := httptest.NewRecorder()
	notReady.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/sync/events", strings.NewReader(`{}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("webhook before reconciliation = %d, want 503", rec.Code)
	}
	rec = httptest.NewRecorder()
	notReady.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz before reconciliation = %d", rec.Code)
	}
}

func TestWebhookInFlightIsRetryable(t *testing.T) {
	hs := newHarness(t)
	now := time.Now()
	_, _ = hs.srv.State.Claim(t.Context(), "sync:evt-6", "user.updated", "other", now, now.Add(time.Minute), now.Add(time.Hour))
	code, _ := hs.webhook(t, "user.updated", "evt-6", scimUser(true))
	if code != http.StatusConflict {
		t.Fatalf("concurrent delivery = %d, want 409", code)
	}
}

func TestBackchannelLogoutClaimAfterSuccess(t *testing.T) {
	hs := newHarness(t)
	hs.vault.Fail["users/logout"] = 1
	claims := hs.logoutClaims("usr_123")

	if code, _ := hs.logout(t, claims); code != http.StatusBadGateway {
		t.Fatalf("first attempt = %d, want 502", code)
	}
	if code, b := hs.logout(t, claims); code != http.StatusOK || b["status"] != "ok" {
		t.Fatalf("retry of the same jti = %d %v", code, b)
	}
	if code, b := hs.logout(t, claims); code != http.StatusOK || b["status"] != "duplicate" {
		t.Fatalf("replay = %d %v, want duplicate", code, b)
	}
	calls := fakevault.CallsTo[map[string]any](hs.vault, "users/logout")
	if len(calls) != 2 || calls[1]["issuer"] != issuer || calls[1]["subject"] != "usr_123" {
		t.Fatalf("logout requests = %v", calls)
	}
	if tid, present := calls[1]["tenant_id"]; !present || tid != nil {
		t.Fatalf("tenant_id = %v (present %v), want explicit null", tid, present)
	}
}

func TestBackchannelLogoutRejections(t *testing.T) {
	hs := newHarness(t)
	if code, _ := hs.logout(t, hs.logoutClaims("")); code != http.StatusBadRequest {
		t.Errorf("sid-only token = %d", code)
	}
	wrongAud := hs.logoutClaims("usr_1")
	wrongAud["aud"] = "another-app"
	if code, _ := hs.logout(t, wrongAud); code != http.StatusBadRequest {
		t.Errorf("wrong audience = %d", code)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/oidc/backchannel-logout", strings.NewReader("logout_token="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if code, _ := hs.do(r); code != http.StatusBadRequest {
		t.Errorf("empty token = %d", code)
	}
	if n := len(fakevault.CallsTo[struct{}](hs.vault, "users/logout")); n != 0 {
		t.Errorf("rejected tokens reached the vault %d times", n)
	}
}

func TestHealthz(t *testing.T) {
	hs := newHarness(t)
	for _, p := range []string{"/healthz", "/readyz"} {
		if code, _ := hs.do(httptest.NewRequest(http.MethodGet, p, nil)); code != http.StatusOK {
			t.Errorf("%s = %d", p, code)
		}
	}
}

func TestLogoutKeyFitsPostgresText(t *testing.T) {
	k := logoutKey(issuer, strings.Repeat("j", 60<<10))
	if strings.ContainsRune(k, 0) || len(k) != len("bcl:")+64 {
		t.Fatalf("key %q is not a bounded NUL-free TEXT value", k[:min(len(k), 80)])
	}
	if logoutKey("https://a", "b/c") == logoutKey("https://a/b", "c") {
		t.Fatal("distinct (issuer, jti) pairs share a key")
	}
}
