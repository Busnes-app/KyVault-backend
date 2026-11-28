package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// member is a KyIdentity user and the vault keys only their own client holds.
type member struct {
	sub, email, org, password string
	uuid                      string
	userKey, privateKey       []byte // privateKey is PKCS#8 DER
	kitSecret                 string
}

const kdfIterations = 600000

func (m *member) claims() map[string]any { return kyClaims(m.sub, m.email, m.org) }

func (m *member) device() string { return "e2e-device-" + m.sub }

type tokenAnswer struct {
	AccessToken   string  `json:"access_token"`
	RefreshToken  *string `json:"refresh_token"`
	Key           string  `json:"Key"`
	PrivateKey    string  `json:"PrivateKey"`
	KdfIterations int     `json:"KdfIterations"`
}

func signedIn(t *testing.T, r resp) tokenAnswer {
	t.Helper()
	if r.code != 200 {
		t.Fatalf("sign-in: %d %s", r.code, r.body)
	}
	var a tokenAnswer
	r.json(t, &a)
	return a
}

// onboard is a member's first sign-in: KyIdentity SSO provisions the account, then the client
// sets the master password and uploads its keys, wrapped as a Bitwarden client wraps them.
func (e *env) onboard(t *testing.T, m *member) {
	t.Helper()
	tok := signedIn(t, e.ssoSignIn(t, r1, m.claims(), m.device()))
	m.uuid = e.str(t, "SELECT uuid FROM users WHERE email = $1", m.email)
	if e.str(t, "SELECT tenant_id FROM users WHERE uuid = $1", m.uuid) != m.org {
		t.Fatalf("%s provisioned outside org %s", m.email, m.org)
	}
	m.userKey = make([]byte, 64)
	_, _ = rand.Read(m.userKey)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	m.privateKey, err = x509.MarshalPKCS8PrivateKey(rk)
	must(t, err)
	pub, err := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	must(t, err)
	mk := masterKey(m.password, m.email, kdfIterations)
	body, _ := json.Marshal(map[string]any{
		"kdf": 0, "kdfIterations": kdfIterations,
		"key":                encString(stretch(mk), m.userKey),
		"masterPasswordHash": masterPasswordHash(mk, m.password),
		"keys": map[string]string{
			"encryptedPrivateKey": encString(m.userKey, m.privateKey),
			"publicKey":           std.EncodeToString(pub),
		},
	})
	if r := call(t, "POST", r1+"/api/accounts/set-password", bearer(tok.AccessToken), body); r.code != 200 {
		t.Fatalf("set-password for %s: %d %s", m.email, r.code, r.body)
	}
}

// unlock is the client after sign-in: the master password unwraps the user key the vault
// returned, and that key opens the private key.
func (m *member) unlock(t *testing.T, a tokenAnswer) []byte {
	t.Helper()
	if a.KdfIterations != kdfIterations {
		t.Fatalf("%s: KdfIterations %d", m.email, a.KdfIterations)
	}
	uk, err := decString(stretch(masterKey(m.password, m.email, a.KdfIterations)), a.Key)
	if err != nil || !bytes.Equal(uk, m.userKey) {
		t.Fatalf("%s: master password did not unlock the vault: %v", m.email, err)
	}
	pk, err := decString(uk, a.PrivateKey)
	if err != nil || !bytes.Equal(pk, m.privateKey) {
		t.Fatalf("%s: private key did not open: %v", m.email, err)
	}
	return uk
}

func (m *member) addItem(t *testing.T, base, token, name string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"type": 2, "name": encString(m.userKey, []byte(name)),
		"secureNote": map[string]int{"type": 0}, "encryptedFor": m.uuid})
	var r resp
	// Hosted writes need a storage grant; the worker installs one within a few seconds.
	eventually(t, 20*time.Second, "create item "+name, func() error {
		r = call(t, "POST", base+"/api/ciphers", bearer(token), body)
		if r.code != 200 {
			return fmt.Errorf("%d %s", r.code, r.body)
		}
		return nil
	})
	var c struct {
		ID string `json:"id"`
	}
	r.json(t, &c)
	return c.ID
}

// items decrypts every cipher name in a sync or export answer with key.
func items(t *testing.T, r resp, key []byte) map[string]string {
	t.Helper()
	if r.code != 200 {
		t.Fatalf("read vault: %d %s", r.code, r.body)
	}
	var v struct {
		Ciphers []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"ciphers"`
	}
	r.json(t, &v)
	out := map[string]string{}
	for _, c := range v.Ciphers {
		name, err := decString(key, c.Name)
		if err != nil {
			out[c.ID] = "<not this user's key>"
			continue
		}
		out[c.ID] = string(name)
	}
	return out
}

func (e *env) saveKit(t *testing.T, m *member, token string) {
	t.Helper()
	secret, p := newKit(m.userKey, m.privateKey, m.org, m.uuid)
	body, _ := json.Marshal(p)
	eventually(t, 20*time.Second, "save recovery kit", func() error {
		if r := call(t, "PUT", r1+"/api/tenancy/recovery/personal", bearer(token), body); r.code != 200 {
			return fmt.Errorf("%d %s", r.code, r.body)
		}
		return nil
	})
	m.kitSecret = secret
}

// recover is the Personal Recovery Kit path: the kit secret, not the master password,
// opens the stored envelope; the recovered user key must open the private key and items.
func (m *member) recover(t *testing.T, base, token string) []byte {
	t.Helper()
	r := call(t, "GET", base+"/api/tenancy/recovery/personal", bearer(token), nil)
	if r.code != 200 {
		t.Fatalf("%s: read kit: %d %s", m.email, r.code, r.body)
	}
	var p kitPayload
	r.json(t, &p)
	uk, pk, err := openKit(p, m.kitSecret, m.org, m.uuid)
	if err != nil || !bytes.Equal(uk, m.userKey) || !bytes.Equal(pk, m.privateKey) {
		t.Fatalf("%s: recovery kit did not recover the keys: %v", m.email, err)
	}
	return uk
}

// backup and restore the vault database the way an operator would: pg_dump, then drop the
// database and pg_restore it with every replica and the worker stopped.
func (e *env) backup(t *testing.T) {
	run(t, "docker", "exec", "kyvault-e2e-pg", "pg_dump", "-U", "vault", "-d", "vault", "-Fc", "-f", "/tmp/vault.dump")
}

func (e *env) restore(t *testing.T) {
	t.Helper()
	e.stopWorker(t)
	run(t, "docker", "rm", "-f", "kyvault-e2e-r1", "kyvault-e2e-r2")
	run(t, "docker", "exec", "kyvault-e2e-pg", "psql", "-U", "vault", "-d", "postgres", "-v", "ON_ERROR_STOP=1",
		"-c", "DROP DATABASE vault WITH (FORCE)", "-c", "CREATE DATABASE vault")
	run(t, "docker", "exec", "kyvault-e2e-pg", "pg_restore", "-U", "vault", "-d", "vault", "--exit-on-error", "/tmp/vault.dump")
	e.db.Reset()
	data := filepath.Join(e.dir, "data")
	startReplica(t, "kyvault-e2e-r1", data, replicaEnv(r1Port))
	waitAlive(t, "kyvault-e2e-r1", r1)
	startReplica(t, "kyvault-e2e-r2", data, replicaEnv(r2Port))
	waitAlive(t, "kyvault-e2e-r2", r2)
	e.startWorker(t, true) // TENANCY_RECONCILE_FROM_ZERO, as MULTI_TENANCY.md prescribes
}

func (e *env) waitStatus(t *testing.T, org, status string) {
	t.Helper()
	eventually(t, 20*time.Second, org+" "+status, func() error {
		if r, ok := e.tenant(t, org); !ok || r.Status != status || r.AuthorityAt == nil {
			return fmt.Errorf("%+v", r)
		}
		return nil
	})
}

// TestLiveHostedJourney is the hosted product path end to end on the real binaries: KyIdentity
// SSO sign-in, master-password unlock, Personal Recovery Kit recovery, a database backup and
// restore, isolation afterwards, and the restricted export of a deletion-scheduled org.
func TestLiveHostedJourney(t *testing.T) {
	e := setup(t)
	e.kyid.setOrg(orgA, "active", true, cellA)
	e.kyid.setOrg(orgB, "active", true, cellB)
	e.startWorker(t, false)
	e.waitStatus(t, orgA, "active")
	e.waitStatus(t, orgB, "active")

	alice := &member{sub: "sub-alice", email: "alice@e2e.test", org: orgA, password: "alice master password"}
	carol := &member{sub: "sub-carol", email: "carol@e2e.test", org: orgA, password: "carol master password"}
	bob := &member{sub: "sub-bob", email: "bob@e2e.test", org: orgB, password: "bob master password"}
	ids := map[string]string{}
	var orgItem string

	t.Run("1 SSO sign-in, unlock and items across replicas", func(t *testing.T) {
		for _, m := range []*member{alice, carol, bob} {
			e.onboard(t, m)
			tok := signedIn(t, e.ssoSignIn(t, r2, m.claims(), m.device()))
			key := m.unlock(t, tok)
			ids[m.sub] = m.addItem(t, r1, tok.AccessToken, m.email+" secret")
			if got := items(t, call(t, "GET", r2+"/api/sync", bearer(tok.AccessToken), nil), key); got[ids[m.sub]] != m.email+" secret" || len(got) != 1 {
				t.Fatalf("%s sync on the other replica: %v", m.email, got)
			}
		}
		// Alice owns an organisation in orgA with one shared item: the export must leave it out.
		org := "0a000000-0000-4000-8000-0000000000a9"
		orgItem = "c0a90000-0000-4000-8000-0000000000a9"
		e.exec(t, `INSERT INTO organizations (uuid, name, billing_email, tenant_id) VALUES ($1, 'org', 'o@e2e.test', $2)`, org, orgA)
		for _, u := range []struct {
			uuid  string
			atype int
		}{{alice.uuid, 0}, {carol.uuid, 2}} {
			e.exec(t, `INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, akey, status, atype)
				VALUES (gen_random_uuid()::text, $1, $2, TRUE, 'envelope', 2, $3)`, u.uuid, org, u.atype)
		}
		e.exec(t, `INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, atype, name, data, tenant_id)
			VALUES ($1, now(), now(), NULL, $2, 2, '2.n|a|b', '{}', $3)`, orgItem, org, orgA)
	})

	t.Run("2 Personal Recovery Kit recovers the vault key", func(t *testing.T) {
		for _, m := range []*member{alice, bob} {
			tok := signedIn(t, e.ssoSignIn(t, r1, m.claims(), m.device()))
			e.saveKit(t, m, tok.AccessToken)
			key := m.recover(t, r2, tok.AccessToken)
			if got := items(t, call(t, "GET", r1+"/api/sync", bearer(tok.AccessToken), nil), key); got[ids[m.sub]] != m.email+" secret" {
				t.Fatalf("%s: recovered key does not open the vault: %v", m.email, got)
			}
		}
	})

	t.Run("3 backup and restore", func(t *testing.T) {
		e.backup(t)
		tok := signedIn(t, e.ssoSignIn(t, r1, alice.claims(), alice.device()))
		ids["after"] = alice.addItem(t, r1, tok.AccessToken, "written after the backup")
		e.restore(t)
		e.waitStatus(t, orgA, "active")
		e.waitStatus(t, orgB, "active")

		for _, m := range []*member{alice, bob} {
			tok := signedIn(t, e.ssoSignIn(t, r2, m.claims(), m.device()))
			key := m.unlock(t, tok)
			got := items(t, call(t, "GET", r1+"/api/sync", bearer(tok.AccessToken), nil), key)
			if got[ids[m.sub]] != m.email+" secret" {
				t.Fatalf("%s: restored vault does not unlock to its item: %v", m.email, got)
			}
			if _, ok := got[ids["after"]]; ok {
				t.Fatal("an item written after the backup survived the restore")
			}
			if !bytes.Equal(m.recover(t, r1, tok.AccessToken), key) {
				t.Fatalf("%s: restored kit recovers another key", m.email)
			}
		}
	})

	t.Run("4 orgs stay isolated after the restore", func(t *testing.T) {
		ta := signedIn(t, e.ssoSignIn(t, r1, alice.claims(), alice.device())).AccessToken
		tb := signedIn(t, e.ssoSignIn(t, r2, bob.claims(), bob.device())).AccessToken
		for _, c := range []struct{ tok, other string }{{ta, ids[bob.sub]}, {tb, ids[alice.sub]}, {tb, orgItem}} {
			if r := call(t, "GET", r1+"/api/ciphers/"+c.other, bearer(c.tok), nil); r.code == 200 {
				t.Fatalf("read another org's item %s: %s", c.other, r.body)
			}
		}
		for id := range items(t, call(t, "GET", r2+"/api/sync", bearer(tb), nil), bob.userKey) {
			if id != ids[bob.sub] {
				t.Fatalf("bob's sync shows item %s", id)
			}
		}
		// Bob's subject presented with orgA's org_id is refused, and gains no access.
		if r := e.ssoSignIn(t, r1, with(bob.claims(), "org_id", orgA), bob.device()); r.code != 403 {
			t.Fatalf("cross-org sign-in: want 403, got %d %s", r.code, r.body)
		}
		var st struct {
			TenantID string `json:"tenantId"`
		}
		call(t, "GET", r1+"/api/tenancy/status", bearer(ta), nil).json(t, &st)
		if st.TenantID != orgA {
			t.Fatalf("alice's tenant after restore: %q", st.TenantID)
		}
	})

	t.Run("5 restricted export", func(t *testing.T) {
		export := func(m *member) map[string]any { return with(m.claims(), "export_only", true) }
		bobTok := signedIn(t, e.ssoSignIn(t, r1, bob.claims(), bob.device())).AccessToken
		if r := call(t, "GET", r1+"/api/tenancy/export", bearer(bobTok), nil); r.code != 403 {
			t.Fatalf("an ordinary session read the restricted export: %d %s", r.code, r.body)
		}
		if r := call(t, "GET", single+"/api/tenancy/export", nil, nil); r.code != 404 {
			t.Fatalf("single-tenant export route: want 404, got %d", r.code)
		}
		aliceOld := signedIn(t, e.ssoSignIn(t, r1, alice.claims(), alice.device())).AccessToken
		if r := e.ssoSignIn(t, r1, export(alice), alice.device()); r.code != 403 {
			t.Fatalf("export-only sign-in while orgA is active: want 403, got %d %s", r.code, r.body)
		}

		e.kyid.setOrg(orgA, "deletion_scheduled", true, cellA)
		e.waitStatus(t, orgA, "deletion_scheduled")
		if c := revisionDate(t, r2, aliceOld); c == 200 {
			t.Fatal("an ordinary session survived the deletion schedule")
		}
		if r := e.ssoSignIn(t, r1, alice.claims(), alice.device()); r.code != 403 {
			t.Fatalf("ordinary sign-in to a deletion-scheduled org: want 403, got %d %s", r.code, r.body)
		}

		// An ordinary token, valid in every other way, still does not open the export.
		now := time.Now().Unix()
		ordinary := signRS256(e.vaultKey, map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{
			"nbf": now - 5, "exp": now + 3600, "iss": domain + "|login", "sub": alice.uuid,
			"premium": true, "name": "alice", "email": alice.email, "email_verified": true,
			"sstamp": e.str(t, "SELECT security_stamp FROM users WHERE uuid = $1", alice.uuid),
			"device": alice.device(), "devicetype": "Linux", "client_id": "web",
			"scope": []string{"api", "offline_access"}, "amr": []string{"Application"}, "tid": orgA,
		})
		if r := call(t, "GET", r1+"/api/tenancy/export", bearer(ordinary), nil); r.code != 403 {
			t.Fatalf("an ordinary token read the restricted export: %d %s", r.code, r.body)
		}

		r := e.ssoSignIn(t, r2, export(alice), alice.device())
		tok := signedIn(t, r)
		if tok.RefreshToken != nil || bytes.Contains(r.body, []byte(`"refresh_token"`)) {
			t.Fatalf("export-only sign-in returned a refresh token: %s", r.body)
		}
		key := alice.unlock(t, tok)
		got := items(t, call(t, "GET", r1+"/api/tenancy/export", bearer(tok.AccessToken), nil), key)
		if len(got) != 1 || got[ids[alice.sub]] != alice.email+" secret" {
			t.Fatalf("alice's export (owner of an org holding %s, carol's item %s): %v", orgItem, ids[carol.sub], got)
		}
		carolTok := signedIn(t, e.ssoSignIn(t, r1, export(carol), carol.device())).AccessToken
		if got := items(t, call(t, "GET", r2+"/api/tenancy/export", bearer(carolTok), nil), carol.userKey); len(got) != 1 || got[ids[carol.sub]] != carol.email+" secret" {
			t.Fatalf("carol's export: %v", got)
		}

		// The export session reaches nothing else.
		item, _ := json.Marshal(map[string]any{"type": 2, "name": "2.a|b|c", "secureNote": map[string]int{"type": 0}, "encryptedFor": alice.uuid})
		for _, c := range []struct{ method, path string }{
			{"GET", "/api/sync"}, {"GET", "/api/accounts/revision-date"}, {"GET", "/api/accounts/profile"},
			{"GET", "/api/ciphers/" + ids[alice.sub]}, {"POST", "/api/ciphers"}, {"GET", "/api/tenancy/status"},
			{"GET", "/api/tenancy/recovery/personal"}, {"DELETE", "/api/tenancy/recovery/personal"},
			{"GET", "/api/organizations/0a000000-0000-4000-8000-0000000000a9/export"},
		} {
			if r := call(t, c.method, r1+c.path, bearer(tok.AccessToken), item); r.code != 403 {
				t.Fatalf("export session on %s %s: want 403, got %d %s", c.method, c.path, r.code, r.body)
			}
		}
		if n := e.num(t, "SELECT count(*) FROM tenant_recovery_bundles WHERE user_uuid = $1 AND revoked_at IS NULL", alice.uuid); n != 1 {
			t.Fatalf("export session changed the recovery kit: %d active", n)
		}
		if ws, err := callErr("GET", r1+"/notifications/hub?access_token="+tok.AccessToken, map[string]string{
			"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Version": "13",
			"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
		}, nil); err != nil || ws.code == 101 {
			t.Fatalf("export session opened the notifications hub: %v %d", err, ws.code)
		}
		devToken := e.str(t, "SELECT refresh_token FROM devices WHERE uuid = $1 AND user_uuid = $2", alice.device(), alice.uuid)
		forged := signRS256(e.vaultKey, map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{
			"nbf": now - 5, "exp": now + 3600, "iss": domain + "|login", "sub": "sso",
			"device_token": devToken, "tid": orgA, "export_only": true,
		})
		// The token endpoint answers every refused refresh with 400 invalid_grant.
		if r, err := refresh(r1, forged); err != nil || r.code != 400 || bytes.Contains(r.body, []byte("access_token")) {
			t.Fatalf("export-only refresh grant: %v %d %s", err, r.code, r.body)
		}

		// Who may not export.
		if r := e.ssoSignIn(t, r1, with(export(alice), "roles", []string{"staff_admin"}), alice.device()); r.code != 403 {
			t.Fatalf("staff export-only sign-in: want 403, got %d %s", r.code, r.body)
		}
		if r := e.ssoSignIn(t, r1, kyClaims("sub-new", "new@e2e.test", orgA), "e2e-device-new"); r.code != 403 {
			t.Fatalf("ordinary sign-up in a deletion-scheduled org: %d", r.code)
		}
		if r := e.ssoSignIn(t, r1, with(kyClaims("sub-new", "new@e2e.test", orgA), "export_only", true), "e2e-device-new"); r.code != 403 {
			t.Fatalf("export-only sign-up: want 403, got %d %s", r.code, r.body)
		}
		if n := e.num(t, "SELECT count(*) FROM users WHERE email = 'new@e2e.test'"); n != 0 {
			t.Fatal("an export-only sign-in created an account")
		}
		if r := e.ssoSignIn(t, r1, export(bob), bob.device()); r.code != 403 {
			t.Fatalf("export-only sign-in for active orgB: want 403, got %d %s", r.code, r.body)
		}
		if r := call(t, "GET", r1+"/api/sync", bearer(bobTok), nil); r.code != 200 {
			t.Fatalf("orgB lost access when orgA was scheduled for deletion: %d", r.code)
		}

		// KyIdentity resumes the org: the export window closes, and the still-unexpired export
		// token gains no ordinary access (a resume rotates nothing).
		e.kyid.setOrg(orgA, "active", true, cellA)
		e.waitStatus(t, orgA, "active")
		for _, path := range []string{"/api/sync", "/api/tenancy/export"} {
			if r := call(t, "GET", r1+path, bearer(tok.AccessToken), nil); r.code != 403 {
				t.Fatalf("export token after the org resumed, %s: want 403, got %d", path, r.code)
			}
		}
		e.kyid.setOrg(orgA, "deletion_scheduled", true, cellA)
		e.waitStatus(t, orgA, "deletion_scheduled")
		carolTok = signedIn(t, e.ssoSignIn(t, r1, export(carol), carol.device())).AccessToken

		// C5: once orgA is fenced off this deployment's cells, its export session and sign-in fail too.
		e.kyid.setOrg(orgA, "deletion_scheduled", true, foreignCell)
		eventually(t, 15*time.Second, "orgA fenced on C4", func() error {
			if r := e.mustTenant(t, orgA); r.AuthorityAt != nil {
				return fmt.Errorf("%+v", r)
			}
			return nil
		})
		if r := call(t, "GET", r1+"/api/tenancy/export", bearer(carolTok), nil); r.code == 200 {
			t.Fatal("export session survived the C4 fence")
		}
		if r := e.ssoSignIn(t, r1, export(alice), alice.device()); r.code == 200 {
			t.Fatalf("export-only sign-in after the C4 fence: %s", r.body)
		}
	})
}
