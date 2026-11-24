package server_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/oidcverify"
	"github.com/Busnes-app/ky-primitives/scim"
	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyvault-worker/internal/pubsub"
	"github.com/Busnes-app/kyvault-worker/internal/server"
	"github.com/Busnes-app/kyvault-worker/internal/store"
	"github.com/Busnes-app/kyvault-worker/internal/syncer"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type recordingEraser struct {
	failNext atomic.Bool
	prefixes []string
}

func (e *recordingEraser) DeletePrefix(_ context.Context, prefix string) (int, error) {
	if e.failNext.Load() {
		return 0, errors.New("simulated S3 outage")
	}
	e.prefixes = append(e.prefixes, prefix)
	return 2, nil
}

func openTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("KYVAULT_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("KYVAULT_TEST_DATABASE_URL not set; skipping live PostgreSQL integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	// Clean all test tables so every run starts from a clean slate.
	cleanTables := []string{
		"tenant_recovery_bundles",
		"tenant_processed_events",
		"tenant_sync_cursors",
		"attachments",
		"ciphers_collections",
		"folders_ciphers",
		"favorites",
		"ciphers",
		"collections_groups",
		"users_collections",
		"collections",
		"groups_users",
		"groups",
		"org_policies",
		"organization_api_key",
		"event",
		"sends",
		"emergency_access",
		"devices",
		"twofactor",
		"twofactor_incomplete",
		"twofactor_duo_ctx",
		"auth_requests",
		"sso_users",
		"folders",
		"users_organizations",
		"invitations",
		"archives",
		"organizations",
		"users",
		"tenants",
	}
	for _, tbl := range cleanTables {
		if _, err := pool.Exec(ctx, "DELETE FROM "+tbl); err != nil {
			t.Fatalf("cleanup table %s: %v", tbl, err)
		}
	}
	return pool
}

func seedUserAndData(t *testing.T, pool *pgxpool.Pool, tenantID, userUUID, subject, email, orgUUID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	_, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, status, home_region, app_enabled, revision, quotas_json, storage_pool_bytes, created_at, updated_at)
		VALUES ($1, 'active', 'us-east-1', TRUE, 1, '{}', 1073741824, $2, $2)
		ON CONFLICT (id) DO NOTHING
	`, tenantID, now)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO users (
			uuid, enabled, created_at, updated_at, verified_at, email, name,
			password_hash, salt, security_stamp, akey, password_iterations,
			equivalent_domains, excluded_globals,
			client_kdf_type, client_kdf_iter, tenant_id
		) VALUES (
			$1, TRUE, $2, $2, $2, $3, 'Test User',
			'\x00', '\x00', 'initial-stamp', 'enc-key', 600000,
			'[]', '[]',
			0, 600000, $4
		)
	`, userUUID, now, email, tenantID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO sso_users (user_uuid, identifier, created_at, tenant_id)
		VALUES ($1, $2, $3, $4)
	`, userUUID, subject, now, tenantID)
	if err != nil {
		t.Fatalf("insert sso_users: %v", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO devices (uuid, created_at, updated_at, user_uuid, name, atype, refresh_token)
		VALUES ($1, $2, $2, $3, 'Browser', 9, 'live-refresh-token')
	`, "dev-"+userUUID[:20], now, userUUID)
	if err != nil {
		t.Fatalf("insert device: %v", err)
	}

	if orgUUID != "" {
		_, err = pool.Exec(ctx, `
			INSERT INTO organizations (uuid, name, billing_email, tenant_id)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (uuid) DO NOTHING
		`, orgUUID, "Org "+tenantID, email, tenantID)
		if err != nil {
			t.Fatalf("insert organization: %v", err)
		}

		_, err = pool.Exec(ctx, `
			INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, akey, status, atype)
			VALUES ($1, $2, $3, TRUE, 'org-key', 2, 0)
		`, "uo-"+userUUID[:20], userUUID, orgUUID)
		if err != nil {
			t.Fatalf("insert users_organizations: %v", err)
		}

		// Shared organization cipher (owned by tenant/org, NOT personal!)
		_, err = pool.Exec(ctx, `
			INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, atype, name, data, tenant_id)
			VALUES ($1, $2, $2, NULL, $3, 1, 'Shared Secret', '{"cipher":"shared-org-data"}', $4)
		`, "org-cipher-"+tenantID, now, orgUUID, tenantID)
		if err != nil {
			t.Fatalf("insert org cipher: %v", err)
		}
	}

	// Personal cipher + attachment + recovery bundle + send
	personalCipher := "pc-" + userUUID[:30]
	_, err = pool.Exec(ctx, `
		INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, atype, name, data, tenant_id)
		VALUES ($1, $2, $2, $3, NULL, 1, 'Personal Login', '{"cipher":"personal-12345"}', $4)
	`, personalCipher, now, userUUID, tenantID)
	if err != nil {
		t.Fatalf("insert personal cipher: %v", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO attachments (id, cipher_uuid, file_name, file_size, tenant_id)
		VALUES ($1, $2, 'id_rsa.enc', 4096, $3)
	`, "att-"+userUUID[:20], personalCipher, tenantID)
	if err != nil {
		t.Fatalf("insert attachment: %v", err)
	}

	sendUUID := "11111111-1111-1111-1111-" + userUUID[24:36]
	_, err = pool.Exec(ctx, `
		INSERT INTO sends (uuid, user_uuid, name, data, akey, atype, access_count, creation_date, revision_date, deletion_date, disabled, tenant_id)
		VALUES ($1, $2, 'File Send', '{"size": 2048}', 'k', 1, 0, $3, $3, $3, FALSE, $4)
	`, sendUUID, userUUID, now, tenantID)
	if err != nil {
		t.Fatalf("insert send: %v", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO tenant_recovery_bundles (uuid, tenant_id, user_uuid, bundle_type, version, kdf_params_json, wrapped_user_key, created_at, updated_at)
		VALUES ($1, $2, $3, 'personal_kit', 1, '{"kdf":"argon2id"}', 'wrapped-blob', $4, $4)
	`, "kit-"+userUUID[:20], tenantID, userUUID, now)
	if err != nil {
		t.Fatalf("insert recovery bundle: %v", err)
	}
}

func startPGListener(t *testing.T, dsn, channel string) <-chan pubsub.Envelope {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect listener: %v", err)
	}
	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		conn.Close(ctx)
		t.Fatalf("LISTEN %s: %v", channel, err)
	}
	ch := make(chan pubsub.Envelope, 16)
	go func() {
		defer conn.Close(context.Background())
		for {
			n, err := conn.WaitForNotification(ctx)
			if err != nil {
				return
			}
			var env pubsub.Envelope
			if json.Unmarshal([]byte(n.Payload), &env) == nil {
				ch <- env
			}
		}
	}()
	return ch
}

func signLogoutJWT(t *testing.T, priv *rsa.PrivateKey, kid, issuer, audience, subject, jti string) string {
	t.Helper()
	now := time.Now().UTC()
	header := map[string]any{
		"alg": "RS256",
		"typ": "logout+jwt",
		"kid": kid,
	}
	claims := map[string]any{
		"iss": issuer,
		"aud": audience,
		"sub": subject,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signingInput := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestWorkerEndToEndMultiTenantSuiteLifecycle(t *testing.T) {
	pool := openTestDB(t)
	ctx := context.Background()
	dsn := os.Getenv("KYVAULT_TEST_DATABASE_URL")
	channel := "kyvault_notify_test"

	notifyCh := startPGListener(t, dsn, channel)

	const aliceUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	const bobUUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// Seed Tenant A (with Alice + shared Org A) and Tenant B (with Bob + shared Org B).
	seedUserAndData(t, pool, "org-alpha", aliceUUID, "sub-alice", "alice@alpha.example", "vw-org-alpha")
	seedUserAndData(t, pool, "org-beta", bobUUID, "sub-bob", "bob@beta.example", "vw-org-beta")

	// Start a real RSA-2048 JWKS endpoint for ky-primitives/oidcverify.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwksSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "k1",
					"alg": "RS256",
					"use": "sig",
					"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksSrv.Close()

	// Mock KyIdentity suite APIs (/api/suite/orgs, /api/suite/storage, /api/suite/erased).
	var capturedStorage struct {
		Sequence int64               `json:"sequence"`
		Tenants  []store.TenantUsage `json:"tenants"`
	}
	kyIdentitySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer suite-tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/suite/orgs":
			if r.URL.Query().Get("cursor") == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"orgs": []map[string]any{
						{
							"org_id":             "org-alpha",
							"status":             "active",
							"home_region":        "us-east-1",
							"app_enabled":        true,
							"revision":           5,
							"storage_pool_bytes": 5368709120,
						},
						{
							// Different region — must be ignored by us-east-1 worker.
							"org_id":      "org-eu-only",
							"status":      "active",
							"home_region": "eu-west-1",
							"app_enabled": true,
							"revision":    2,
						},
					},
					"has_more":    true,
					"next_cursor": "page-2",
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"orgs": []map[string]any{
						{
							"org_id":      "org-beta",
							"status":      "suspended",
							"home_region": "us-east-1",
							"app_enabled": false,
							"revision":    10,
						},
					},
					"has_more": false,
				})
			}
		case "/api/suite/storage":
			if err := json.NewDecoder(r.Body).Decode(&capturedStorage); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/api/suite/erased":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"events": []map[string]any{
					{"id": "ev-erase-alpha", "entity_type": "org", "org_id": "org-alpha", "revision": 12},
				},
				"has_more": false,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer kyIdentitySrv.Close()

	st := store.New(pool)
	pub := pubsub.NewPublisher(pool, channel, "test-worker")
	eraser := &recordingEraser{}
	syn := &syncer.Syncer{
		BaseURL:    kyIdentitySrv.URL,
		Token:      "suite-tok",
		HomeRegion: "us-east-1",
		Store:      st,
		Publisher:  pub,
		Eraser:     eraser,
		HTTPClient: kyIdentitySrv.Client(),
	}
	syncSecret := []byte("0123456789abcdef0123456789abcdef")
	srv := &server.Server{
		HomeRegion:        "us-east-1",
		SyncWebhookSecret: syncSecret,
		LogoutVerifier: &oidcverify.Verifier{
			Issuer:     "https://id.busnes.test",
			Audience:   "kyvault-client",
			JWKSURL:    jwksSrv.URL,
			HTTPClient: jwksSrv.Client(),
		},
		Store:     st,
		Publisher: pub,
		Syncer:    syn,
	}
	httpHandler := srv.Handler()

	// -------------------------------------------------------------------------
	// 1. OIDC Back-Channel Logout (real RS256 JWKS + PG NOTIFY + JTI replay guard)
	// -------------------------------------------------------------------------
	logoutJWT := signLogoutJWT(t, privKey, "k1", "https://id.busnes.test", "kyvault-client", "sub-alice", "jti-logout-1")
	form := url.Values{"logout_token": {logoutJWT}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/oidc/backchannel-logout", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	httpHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("backchannel logout expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %q", rec.Header().Get("Cache-Control"))
	}

	// Verify Alice's security_stamp rotated and refresh_token cleared.
	var stamp, refresh string
	_ = pool.QueryRow(ctx, "SELECT security_stamp FROM users WHERE uuid = $1", aliceUUID).Scan(&stamp)
	_ = pool.QueryRow(ctx, "SELECT refresh_token FROM devices WHERE user_uuid = $1", aliceUUID).Scan(&refresh)
	if stamp == "initial-stamp" {
		t.Fatal("expected Alice's security_stamp to rotate on backchannel logout")
	}
	if refresh != "" {
		t.Fatalf("expected Alice's refresh_token cleared, got %q", refresh)
	}

	// Verify real PostgreSQL NOTIFY emitted user_logout for Alice!
	select {
	case env := <-notifyCh:
		if env.Kind != "user_logout" || env.UserID != aliceUUID {
			t.Fatalf("unexpected PG NOTIFY envelope: %+v", env)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for user_logout PG NOTIFY")
	}

	// Replay the EXACT same logout_token -> MUST fail 400 (durable JTI replay protection).
	reqReplay := httptest.NewRequest(http.MethodPost, "/api/oidc/backchannel-logout", strings.NewReader(form))
	reqReplay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recReplay := httptest.NewRecorder()
	httpHandler.ServeHTTP(recReplay, reqReplay)
	if recReplay.Code != http.StatusBadRequest {
		t.Fatalf("replayed logout_token must return 400, got %d", recReplay.Code)
	}

	// -------------------------------------------------------------------------
	// 2. Signed Directory Sync Webhooks (syncauth): bad sig -> 401, deactivation,
	//    duplicate idempotency, and user.erased preserving shared org ciphers!
	// -------------------------------------------------------------------------
	badReq := httptest.NewRequest(http.MethodPost, "/api/sync/events", strings.NewReader(`{}`))
	badReq.Header.Set(syncauth.HeaderSignature, "v1=deadbeef")
	badRec := httptest.NewRecorder()
	httpHandler.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid sync signature expected 401, got %d", badRec.Code)
	}

	sendSigned := func(eventType, eventID string, payload any) *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		hdrs, err := syncauth.Sign(syncSecret, time.Now().UTC(), eventType, eventID, body)
		if err != nil {
			t.Fatalf("syncauth.Sign: %v", err)
		}
		r := httptest.NewRequest(http.MethodPost, "/api/sync/events", bytes.NewReader(body))
		r.Header.Set(syncauth.HeaderSignature, hdrs.Signature)
		r.Header.Set(syncauth.HeaderTimestamp, hdrs.Timestamp)
		r.Header.Set(syncauth.HeaderEventType, hdrs.EventType)
		r.Header.Set(syncauth.HeaderEventID, hdrs.EventID)
		w := httptest.NewRecorder()
		httpHandler.ServeHTTP(w, r)
		return w
	}

	// Deactivate Alice via user.updated (active=false)
	wDeact := sendSigned("user.updated", "ev-deact-1", scim.User{
		ExternalID: "sub-alice",
		UserName:   "alice@alpha.example",
		Active:     false,
	})
	if wDeact.Code != http.StatusOK {
		t.Fatalf("user.updated expected 200, got %d: %s", wDeact.Code, wDeact.Body.String())
	}
	var aliceEnabled bool
	_ = pool.QueryRow(ctx, "SELECT enabled FROM users WHERE uuid = $1", aliceUUID).Scan(&aliceEnabled)
	if aliceEnabled {
		t.Fatal("expected Alice to be disabled after inactive user.updated")
	}
	select {
	case env := <-notifyCh:
		if env.Kind != "user_logout" || env.UserID != aliceUUID {
			t.Fatalf("unexpected PG NOTIFY after deactivation: %+v", env)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for user_logout PG NOTIFY on deactivation")
	}

	// Duplicate event_id must return 200 {"status":"duplicate"} without error.
	wDup := sendSigned("user.updated", "ev-deact-1", scim.User{ExternalID: "sub-alice", Active: true})
	if wDup.Code != http.StatusOK || !strings.Contains(wDup.Body.String(), "duplicate") {
		t.Fatalf("expected duplicate ack, got %d: %s", wDup.Code, wDup.Body.String())
	}

	// ReportStorage BEFORE erasure: verify canonical byte counts (4096 att + 2048 send + cipher bytes).
	if err := syn.ReportStorage(ctx); err != nil {
		t.Fatalf("ReportStorage: %v", err)
	}
	if capturedStorage.Sequence != 1 || len(capturedStorage.Tenants) != 2 {
		t.Fatalf("unexpected storage report: %+v", capturedStorage)
	}
	for _, u := range capturedStorage.Tenants {
		if u.AttachmentBytes != 4096 || u.SendFileBytes != 2048 || u.CipherDataBytes == 0 {
			t.Fatalf("unexpected metering for tenant %s: %+v", u.TenantID, u)
		}
	}

	// User erasure: deletes Alice's personal vault/attachments/recovery kits/user row
	// while PRESERVING Tenant A's shared org cipher!
	wEraseUser := sendSigned("user.erased", "ev-erase-alice", scim.User{
		ExternalID: "sub-alice",
		UserName:   "alice@alpha.example",
	})
	if wEraseUser.Code != http.StatusOK {
		t.Fatalf("user.erased expected 200, got %d: %s", wEraseUser.Code, wEraseUser.Body.String())
	}
	select {
	case <-notifyCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for user_logout PG NOTIFY on user.erased")
	}

	var aliceCount, persCipherCount, orgCipherCount, kitCount int
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE uuid = $1", aliceUUID).Scan(&aliceCount)
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM ciphers WHERE uuid = $1", "pc-"+aliceUUID[:30]).Scan(&persCipherCount)
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM ciphers WHERE uuid = 'org-cipher-org-alpha'").Scan(&orgCipherCount)
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM tenant_recovery_bundles WHERE user_uuid = $1", aliceUUID).Scan(&kitCount)
	if aliceCount != 0 || persCipherCount != 0 || kitCount != 0 {
		t.Fatalf("expected Alice personal data purged (users=%d, pers=%d, kits=%d)", aliceCount, persCipherCount, kitCount)
	}
	if orgCipherCount != 1 {
		t.Fatalf("user.erased MUST preserve tenant-owned shared org cipher, got count=%d", orgCipherCount)
	}

	// -------------------------------------------------------------------------
	// 3. PollOrgs: multi-page sync, home_region filtering, tenant suspension + PG NOTIFY tenant_kick
	// -------------------------------------------------------------------------
	if err := syn.PollOrgs(ctx); err != nil {
		t.Fatalf("PollOrgs: %v", err)
	}
	var euCount int
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM tenants WHERE id = 'org-eu-only'").Scan(&euCount)
	if euCount != 0 {
		t.Fatal("worker must ignore tenants assigned to a different home_region")
	}
	var betaStatus, bobRefresh string
	_ = pool.QueryRow(ctx, "SELECT status FROM tenants WHERE id = 'org-beta'").Scan(&betaStatus)
	_ = pool.QueryRow(ctx, "SELECT refresh_token FROM devices WHERE user_uuid = $1", bobUUID).Scan(&bobRefresh)
	if betaStatus != "suspended" || bobRefresh != "" {
		t.Fatalf("expected org-beta suspended & Bob fenced (status=%s, refresh=%q)", betaStatus, bobRefresh)
	}
	select {
	case env := <-notifyCh:
		if env.Kind != "tenant_kick" || env.TenantID != "org-beta" {
			t.Fatalf("unexpected PG NOTIFY on org-beta suspension: %+v", env)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for tenant_kick PG NOTIFY on suspension")
	}

	// -------------------------------------------------------------------------
	// 4. PollErased: S3 failure keeps tenant 'erasing', retry completes full purge + tombstone,
	//    leaving Tenant B 100% untouched!
	// -------------------------------------------------------------------------
	eraser.failNext.Store(true)
	if err := syn.PollErased(ctx); err == nil {
		t.Fatal("expected PollErased to return error when S3 deletion fails")
	}
	var alphaStatus string
	_ = pool.QueryRow(ctx, "SELECT status FROM tenants WHERE id = 'org-alpha'").Scan(&alphaStatus)
	if alphaStatus != "erasing" {
		t.Fatalf("expected org-alpha to remain 'erasing' after S3 failure, got %q", alphaStatus)
	}
	select {
	case env := <-notifyCh:
		if env.Kind != "tenant_kick" || env.TenantID != "org-alpha" {
			t.Fatalf("unexpected PG NOTIFY on org-alpha begin erasure: %+v", env)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for tenant_kick PG NOTIFY on erasure")
	}

	// Recover S3 and retry PollErased -> MUST purge all org-alpha rows, delete S3 prefix,
	// keep deleted tombstone, and leave org-beta 100% intact!
	eraser.failNext.Store(false)
	if err := syn.PollErased(ctx); err != nil {
		t.Fatalf("PollErased retry failed: %v", err)
	}
	_ = pool.QueryRow(ctx, "SELECT status FROM tenants WHERE id = 'org-alpha'").Scan(&alphaStatus)
	if alphaStatus != "deleted" {
		t.Fatalf("expected org-alpha tombstone status='deleted', got %q", alphaStatus)
	}

	var alphaOrgs, alphaCiphers, betaUsers, betaCiphers, betaAtts, betaKits int
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM organizations WHERE tenant_id = 'org-alpha'").Scan(&alphaOrgs)
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM ciphers WHERE tenant_id = 'org-alpha'").Scan(&alphaCiphers)
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE tenant_id = 'org-beta'").Scan(&betaUsers)
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM ciphers WHERE tenant_id = 'org-beta'").Scan(&betaCiphers)
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM attachments WHERE tenant_id = 'org-beta'").Scan(&betaAtts)
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM tenant_recovery_bundles WHERE tenant_id = 'org-beta'").Scan(&betaKits)

	if alphaOrgs != 0 || alphaCiphers != 0 {
		t.Fatalf("expected all org-alpha rows purged, got orgs=%d ciphers=%d", alphaOrgs, alphaCiphers)
	}
	if betaUsers != 1 || betaCiphers != 2 || betaAtts != 1 || betaKits != 1 {
		t.Fatalf("org-alpha erasure MUST NOT touch org-beta! Got users=%d ciphers=%d atts=%d kits=%d", betaUsers, betaCiphers, betaAtts, betaKits)
	}
}
