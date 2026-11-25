// Package e2e drives the real vault binary (two multi-tenant replicas on PostgreSQL 17 and
// one single-tenant SQLite instance), the real worker binary, RustFS for S3 and a TLS
// KyIdentity speaking the SUITE-DIRECTORY.md wire format. Run it with worker/e2e/run.sh;
// without KYVAULT_E2E_PG=1 it skips.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	orgA = "aaaaaaaa-0000-4000-8000-000000000001"
	orgB = "bbbbbbbb-0000-4000-8000-000000000002"
	orgC = "cccccccc-0000-4000-8000-000000000003" // another region's org
)

var (
	a1 = vaultUser{"a1000000-0000-4000-8000-000000000001", orgA, "sub-a1"}
	a2 = vaultUser{"a2000000-0000-4000-8000-000000000002", orgA, "sub-a2"}
	a3 = vaultUser{"a3000000-0000-4000-8000-000000000003", orgA, "sub-a3"}
	b1 = vaultUser{"b1000000-0000-4000-8000-000000000001", orgB, "sub-b1"}
)

const (
	orgOA   = "0a000000-0000-4000-8000-0000000000aa"
	orgOB   = "0b000000-0000-4000-8000-0000000000bb"
	ocA     = "c0a00000-0000-4000-8000-00000000000a" // org cipher of OA
	ocB     = "c0b00000-0000-4000-8000-00000000000b"
	pcA1    = "c1a10000-0000-4000-8000-0000000000a1" // personal ciphers
	pcA2    = "c1a20000-0000-4000-8000-0000000000a2"
	pcB1    = "c1b10000-0000-4000-8000-0000000000b1"
	bundleA = "ba000000-0000-4000-8000-0000000000a1"
)

func (e *env) seed(t *testing.T) {
	t.Helper()
	for _, u := range []vaultUser{a1, a2, a3, b1} {
		e.exec(t, `INSERT INTO users (uuid, enabled, created_at, updated_at, email, name, password_hash, salt,
			password_iterations, akey, security_stamp, equivalent_domains, excluded_globals, client_kdf_type,
			client_kdf_iter, tenant_id) VALUES ($1::text, TRUE, now(), now(), $1::text || '@e2e.test', $1::text, '\x00', '\x00',
			600000, 'akey', 'stamp-' || $1::text, '[]', '[]', 0, 600000, $2)`, u.uuid, u.tenant)
		e.exec(t, `INSERT INTO sso_users (user_uuid, identifier, tenant_id) VALUES ($1, $2, $3)`,
			u.uuid, issuer+"/"+u.subject, u.tenant)
		e.exec(t, `INSERT INTO devices (uuid, created_at, updated_at, user_uuid, name, atype, refresh_token)
			VALUES ($1, now(), now(), $2::text, 'e2e', 8, 'rt-' || $2::text)`, u.device(), u.uuid)
	}
	for _, o := range [][2]string{{orgOA, orgA}, {orgOB, orgB}} {
		e.exec(t, `INSERT INTO organizations (uuid, name, billing_email, tenant_id) VALUES ($1, 'org', 'b@e2e.test', $2)`, o[0], o[1])
	}
	for _, m := range [][2]string{{a1.uuid, orgOA}, {a2.uuid, orgOA}, {b1.uuid, orgOB}} {
		e.exec(t, `INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, akey, status, atype)
			VALUES (gen_random_uuid()::text, $1, $2, TRUE, 'envelope', 2, 2)`, m[0], m[1])
	}
	cipher := func(id string, user, org *string, tenant string) {
		e.exec(t, `INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, atype, name, data, tenant_id)
			VALUES ($1, now(), now(), $2, $3, 1, '2.n|a|b', $4, $5)`, id, user, org, strings.Repeat("d", 1000), tenant)
	}
	p := func(s string) *string { return &s }
	cipher(ocA, nil, p(orgOA), orgA)
	cipher(ocB, nil, p(orgOB), orgB)
	cipher(pcA1, p(a1.uuid), nil, orgA)
	cipher(pcA2, p(a2.uuid), nil, orgA)
	cipher(pcB1, p(b1.uuid), nil, orgB)
	e.exec(t, `INSERT INTO tenant_recovery_bundles (uuid, tenant_id, user_uuid, bundle_type, version, kdf_params_json,
		wrapped_user_key, wrapped_private_key) VALUES ($1, $2, $3, 'personal_kit', 1, '{}', $4, $4)`,
		bundleA, orgA, a1.uuid, strings.Repeat("w", 300))
}

// committed is the vault's committed-bytes formula, computed independently in SQL.
func (e *env) committed(t *testing.T, tenant string) int64 {
	return e.num(t, `SELECT
		(SELECT COALESCE(SUM(file_size), 0) FROM attachments WHERE tenant_id = $1) +
		(SELECT COALESCE(SUM(
			COALESCE(OCTET_LENGTH(name), 0) + COALESCE(OCTET_LENGTH(notes), 0) +
			COALESCE(OCTET_LENGTH(fields), 0) + COALESCE(OCTET_LENGTH(data), 0) +
			COALESCE(OCTET_LENGTH(password_history), 0) + COALESCE(OCTET_LENGTH(key), 0)
		), 0) FROM ciphers WHERE tenant_id = $1) +
		(SELECT COALESCE(SUM(OCTET_LENGTH(wrapped_user_key) + COALESCE(OCTET_LENGTH(wrapped_private_key), 0)), 0)
		   FROM tenant_recovery_bundles WHERE tenant_id = $1)`, tenant)
}

type tenantRow struct {
	Status                           string
	HomeRegion                       string
	AppEnabled                       bool
	Epoch, Ceiling, Pool, Reserved   int64
	ReportSeq, Applied               int64
	Expires, PendingSeq, AuthorityAt *int64
	Stale                            bool
	ErasedAt                         *time.Time
}

func (e *env) tenant(t *testing.T, id string) (tenantRow, bool) {
	t.Helper()
	var r tenantRow
	err := e.db.QueryRow(context.Background(), `SELECT status, home_region, app_enabled, access_epoch, storage_ceiling_bytes,
		storage_pool_bytes, storage_reserved_bytes, storage_report_seq, storage_last_applied_seq,
		storage_grant_expires_at, storage_pending_seq, authority_refreshed_at, storage_seq_stale, erased_at
		FROM tenants WHERE id = $1`, id).Scan(&r.Status, &r.HomeRegion, &r.AppEnabled, &r.Epoch, &r.Ceiling, &r.Pool, &r.Reserved,
		&r.ReportSeq, &r.Applied, &r.Expires, &r.PendingSeq, &r.AuthorityAt, &r.Stale, &r.ErasedAt)
	if err == pgx.ErrNoRows {
		return r, false
	}
	must(t, err)
	return r, true
}

func (e *env) mustTenant(t *testing.T, id string) tenantRow {
	t.Helper()
	r, ok := e.tenant(t, id)
	if !ok {
		t.Fatalf("tenant %s missing", id)
	}
	return r
}

func (e *env) stamp(t *testing.T, u vaultUser) (stamp, refresh string) {
	t.Helper()
	return e.str(t, "SELECT security_stamp FROM users WHERE uuid = $1", u.uuid),
		e.str(t, "SELECT refresh_token FROM devices WHERE user_uuid = $1", u.uuid)
}

func revisionDate(t *testing.T, base, token string) int {
	t.Helper()
	return call(t, "GET", base+"/api/accounts/revision-date", bearer(token), nil).code
}

// lastOK returns KyIdentity's last ok exchange for org with seq, if any.
func lastOK(k *kyid, org string, seq int64) (exchange, bool) {
	h := k.history(org)
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].Result == "ok" && h[i].Seq == seq {
			return h[i], true
		}
	}
	return exchange{}, false
}

func cellFor(tenant string) string {
	if tenant == orgB {
		return cellB
	}
	return cellA
}

func TestLivePostgres(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	e.kyid.setOrg(orgA, "active", true, cellA)
	e.kyid.setOrg(orgB, "active", true, cellB)
	e.kyid.setOrg(orgC, "active", true, foreignCell)
	e.seed(t)
	e.startWorker(t, false)

	t.Run("1 migrations and health", func(t *testing.T) {
		for _, base := range []string{r1, r2} {
			r := internal(t, base, "GET", "health", nil)
			var h struct {
				Status      string   `json:"status"`
				MultiTenant bool     `json:"multi_tenant"`
				Cells       []string `json:"cells"`
			}
			r.json(t, &h)
			if r.code != 200 || h.Status != "ok" || !h.MultiTenant || strings.Join(h.Cells, ",") != servedCells {
				t.Fatalf("%s health: %d %s", base, r.code, r.body)
			}
		}
		if r := internal(t, single, "GET", "health", nil); r.code != 404 {
			t.Fatalf("single-tenant health: want 404, got %d %s", r.code, r.body)
		}
		for _, tbl := range []string{"tenants", "tenant_pending_deletions", "tenant_erased_subjects",
			"tenant_recovery_bundles", "worker_sync_cursors", "worker_processed_events", "worker_known_orgs"} {
			if e.num(t, "SELECT count(*) FROM information_schema.tables WHERE table_name = $1", tbl) != 1 {
				t.Fatalf("table %s missing on PostgreSQL", tbl)
			}
		}
	})

	t.Run("2 bearer guard over HTTP", func(t *testing.T) {
		for _, base := range []string{r1, r2} {
			for _, h := range []map[string]string{
				nil,
				{"Authorization": "Bearer wrong-secret-wrong-secret-wrong-secret"},
				{"Authorization": "Bearer " + internalToken + "x"},
				{"Authorization": "Basic " + internalToken},
			} {
				if r := call(t, "GET", base+"/internal/tenancy/v1/health", h, nil); r.code != 401 {
					t.Fatalf("%s health with %v: want 401, got %d", base, h, r.code)
				}
			}
			body := []byte(`{"orgs":[{"id":"dddddddd-0000-4000-8000-000000000004","status":"active","enabled":true,"home_region":"eu-west-1"}]}`)
			if r := call(t, "POST", base+"/internal/tenancy/v1/orgs/reconcile",
				map[string]string{"Authorization": "Bearer nope", "Content-Type": "application/json"}, body); r.code != 401 {
				t.Fatalf("unauthenticated reconcile: %d", r.code)
			}
		}
		if _, ok := e.tenant(t, "dddddddd-0000-4000-8000-000000000004"); ok {
			t.Fatal("unauthenticated reconcile created a tenant")
		}
	})

	t.Run("3 org reconcile and two-replica fencing", func(t *testing.T) {
		for _, id := range []string{orgA, orgB} {
			r := e.mustTenant(t, id)
			if r.Status != "active" || !r.AppEnabled || r.HomeRegion != cellFor(id) || r.AuthorityAt == nil || time.Now().Unix()-*r.AuthorityAt > 60 {
				t.Fatalf("tenant %s after initial reconcile: %+v", id, r)
			}
		}
		if _, ok := e.tenant(t, orgC); ok {
			t.Fatal("other cell's org was provisioned here")
		}

		// Hub connections on replica 2; the fence is applied through replica 1.
		wsA := dialHub(t, r2, e.accessToken(t, a2))
		wsB := dialHub(t, r2, e.accessToken(t, b1))
		oldA2 := e.accessToken(t, a2)
		tokB1 := e.accessToken(t, b1)
		if c := revisionDate(t, r2, oldA2); c != 200 {
			t.Fatalf("a2 before fence on r2: %d", c)
		}

		listen, err := pgx.Connect(ctx, pgURL)
		must(t, err)
		defer listen.Close(ctx)
		_, err = listen.Exec(ctx, `LISTEN kyvault_notify`)
		must(t, err)

		before := e.mustTenant(t, orgA)
		stampA2, rtA2 := e.stamp(t, a2)
		stampB1, _ := e.stamp(t, b1)
		e.kyid.setOrg(orgA, "suspended", true, cellA)

		eventually(t, 15*time.Second, "tenant A suspended", func() error {
			if r := e.mustTenant(t, orgA); r.Status != "suspended" || r.Epoch != before.Epoch+1 {
				return fmt.Errorf("%+v", r)
			}
			return nil
		})
		if s, rt := e.stamp(t, a2); s == stampA2 || rt == rtA2 {
			t.Fatal("tenant A user's stamp or refresh token was not rotated")
		}
		if s, _ := e.stamp(t, b1); s != stampB1 {
			t.Fatal("tenant B user was fenced")
		}
		r := e.mustTenant(t, orgA)
		if r.Ceiling != 0 || r.Expires != nil {
			t.Fatalf("fenced tenant kept a storage grant: %+v", r)
		}

		nctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		for {
			n, err := listen.WaitForNotification(nctx)
			if err != nil {
				t.Fatalf("no tenant_kick NOTIFY: %v", err)
			}
			var env struct {
				Kind     string `json:"kind"`
				TenantID string `json:"tenant_id"`
			}
			_ = json.Unmarshal([]byte(n.Payload), &env)
			if env.Kind == "tenant_kick" && env.TenantID == orgA {
				break
			}
		}
		if !wsA.closedWithin(10 * time.Second) {
			t.Fatal("replica 2 kept tenant A's hub connection open after the fence on replica 1")
		}
		if wsB.closedWithin(2 * time.Second) {
			t.Fatal("replica 2 closed tenant B's hub connection")
		}
		if c := revisionDate(t, r2, oldA2); c == 200 {
			t.Fatal("replica 2 still accepts tenant A's old token")
		}
		if c := revisionDate(t, r2, tokB1); c != 200 {
			t.Fatalf("replica 2 rejected tenant B: %d", c)
		}

		e.kyid.setOrg(orgA, "active", true, cellA)
		eventually(t, 15*time.Second, "tenant A reactivated", func() error {
			if r := e.mustTenant(t, orgA); r.Status != "active" || r.Epoch != before.Epoch+1 {
				return fmt.Errorf("%+v", r)
			}
			return nil
		})
		if c := revisionDate(t, r2, e.accessToken(t, a2)); c != 200 {
			t.Fatalf("reactivated tenant A rejected on r2: %d", c)
		}
	})

	t.Run("4 storage grants", func(t *testing.T) {
		// (a) Grant anchored to the send time, bytes from the live OCTET_LENGTH formula.
		eventually(t, 15*time.Second, "tenant A grant", func() error {
			r := e.mustTenant(t, orgA)
			x, ok := lastOK(e.kyid, orgA, r.Applied)
			if r.Applied == 0 || !ok || r.Expires == nil {
				return fmt.Errorf("no applied grant yet: %+v", r)
			}
			if r.Ceiling != x.Ceiling || r.Pool != poolBytes {
				return fmt.Errorf("ceiling %d pool %d, KyIdentity granted %d", r.Ceiling, r.Pool, x.Ceiling)
			}
			if *r.Expires > x.At+ttlSeconds || *r.Expires < x.At+ttlSeconds-5 {
				return fmt.Errorf("expires %d not anchored to send time %d+%d", *r.Expires, x.At, ttlSeconds)
			}
			if want := e.committed(t, orgA); x.UsedBytes != want {
				return fmt.Errorf("reported used %d, committed %d", x.UsedBytes, want)
			}
			return nil
		})

		// (b) KyIdentity fails; the same seq and bytes are resent.
		e.kyid.setFailing(true)
		var failed exchange
		eventually(t, 10*time.Second, "failed exchange", func() error {
			for _, x := range e.kyid.history(orgA) {
				if x.Result == "failed" {
					failed = x
					return nil
				}
			}
			return fmt.Errorf("none")
		})
		if r := e.mustTenant(t, orgA); r.PendingSeq == nil || *r.PendingSeq != failed.Seq {
			t.Fatalf("pending seq %v, failed report seq %d", r.PendingSeq, failed.Seq)
		}
		time.Sleep(2 * time.Second) // more failed retries
		e.kyid.setFailing(false)
		eventually(t, 10*time.Second, "replayed report", func() error {
			if _, ok := lastOK(e.kyid, orgA, failed.Seq); !ok {
				return fmt.Errorf("seq %d not answered yet", failed.Seq)
			}
			return nil
		})
		for _, x := range e.kyid.history(orgA) {
			if x.Seq == failed.Seq && x.UsedBytes != failed.UsedBytes {
				t.Fatalf("replay of seq %d changed bytes %d -> %d", x.Seq, failed.UsedBytes, x.UsedBytes)
			}
			if x.Seq > failed.Seq && x.At < failed.At {
				t.Fatal("a newer seq was sent before the failed one was answered")
			}
		}

		// (c) stale keeps the grant, never resets seq, needs repair-seq.
		bBefore := e.mustTenant(t, orgB)
		kySeq := bBefore.ReportSeq + 1000
		e.kyid.setStale(orgB, kySeq)
		eventually(t, 10*time.Second, "tenant B stale", func() error {
			if r := e.mustTenant(t, orgB); !r.Stale {
				return fmt.Errorf("%+v", r)
			}
			return nil
		})
		stale := e.mustTenant(t, orgB)
		x, ok := lastOK(e.kyid, orgB, stale.Applied)
		if !ok || stale.Ceiling != x.Ceiling || stale.Expires == nil ||
			*stale.Expires > x.At+ttlSeconds || *stale.Expires < x.At+ttlSeconds-5 {
			t.Fatalf("stale lost the existing grant: %+v (last ok %+v)", stale, x)
		}
		nReports := len(e.kyid.history(orgB))
		time.Sleep(3 * time.Second)
		after := e.mustTenant(t, orgB)
		if after.ReportSeq != stale.ReportSeq || len(e.kyid.history(orgB)) != nReports {
			t.Fatalf("stale tenant kept reporting or seq moved: %d -> %d", stale.ReportSeq, after.ReportSeq)
		}
		if after.ReportSeq >= kySeq {
			t.Fatal("worker reset seq to KyIdentity's on its own")
		}
		if r := internal(t, r2, "POST", "storage/repair-seq", map[string]any{"org_id": orgB, "next_seq": after.ReportSeq}); r.code != 400 {
			t.Fatalf("repair-seq not above current: want 400, got %d", r.code)
		}
		if r := internal(t, r2, "POST", "storage/repair-seq", map[string]any{"org_id": orgB, "next_seq": kySeq + 1}); r.code != 200 {
			t.Fatalf("repair-seq: %d %s", r.code, r.body)
		}
		e.kyid.setStale(orgB, 0)
		eventually(t, 10*time.Second, "tenant B repaired", func() error {
			r := e.mustTenant(t, orgB)
			if r.Stale || r.Applied < kySeq+1 {
				return fmt.Errorf("%+v", r)
			}
			if _, ok := lastOK(e.kyid, orgB, kySeq+1); !ok {
				return fmt.Errorf("first repaired report was not seq %d", kySeq+1)
			}
			return nil
		})

		// (d) Concurrent admission on both replicas against one frozen grant.
		e.kyid.setFailing(true)
		mark := len(e.kyid.history(orgA))
		eventually(t, 10*time.Second, "exchange loop frozen", func() error {
			for _, x := range e.kyid.history(orgA)[mark:] {
				if x.Result == "failed" {
					return nil
				}
			}
			return fmt.Errorf("no failure yet")
		})
		g := e.mustTenant(t, orgA)
		free := g.Ceiling - e.committed(t, orgA) - g.Reserved
		if free <= 0 {
			t.Fatalf("no free grant: %+v", g)
		}
		// Ten simultaneous requests, alternating replicas, each a quarter of the free bytes
		// plus one: exactly three fit. A lost update on storage_reserved_bytes admits more.
		size := free/4 + 1
		tokA2 := e.accessToken(t, a2)
		var wg sync.WaitGroup
		start := make(chan struct{})
		codes := make([]resp, 10)
		for i := range codes {
			base := []string{r1, r2}[i%2]
			wg.Add(1)
			go func() { defer wg.Done(); <-start; codes[i], _ = callErrAttach(base, tokA2, pcA2, size) }()
		}
		close(start)
		wg.Wait()
		var won resp
		wins := 0
		for _, c := range codes {
			if c.code == 200 {
				wins++
				won = c
			} else if !strings.Contains(string(c.body), "quota exceeded") {
				t.Fatalf("loser failed for the wrong reason: %d %s", c.code, c.body)
			}
		}
		if wins != 3 {
			t.Fatalf("want exactly 3 of 10 concurrent %d-byte admissions into %d free bytes, got %d", size, free, wins)
		}
		if r := createAttachment(t, r1, tokA2, pcA2, size); r.code == 200 {
			t.Fatal("upload beyond the ceiling was admitted")
		}
		// A create whose name fits the grant but whose payload does not leaves no cipher behind.
		left := g.Ceiling - e.committed(t, orgA) - e.mustTenant(t, orgA).Reserved
		big, _ := json.Marshal(map[string]any{"collectionIds": []string{}, "cipher": map[string]any{
			"type": 1, "name": "2.refused|a|b", "encryptedFor": a2.uuid,
			"login": map[string]any{"password": strings.Repeat("p", int(left)+1)},
		}})
		if r := call(t, "POST", r2+"/api/ciphers/create", bearer(tokA2), big); r.code == 200 ||
			!strings.Contains(string(r.body), "quota exceeded") {
			t.Fatalf("oversized create: %d %s", r.code, r.body)
		}
		if n := e.num(t, "SELECT count(*) FROM ciphers WHERE name = '2.refused|a|b'"); n != 0 {
			t.Fatalf("refused create left %d cipher rows", n)
		}
		var att struct {
			AttachmentID string `json:"attachmentId"`
		}
		won.json(t, &att)
		if r := uploadAttachment(t, r2, tokA2, pcA2, att.AttachmentID, int(size)); r.code != 200 {
			t.Fatalf("upload to admitted attachment: %d %s", r.code, r.body)
		}
		if !s3Exists(t, attachmentKey(cellA, orgA, pcA2, att.AttachmentID)) {
			t.Fatal("admitted upload not in S3")
		}
		if r := e.mustTenant(t, orgA); r.Reserved != 0 {
			t.Fatalf("reservation leaked: %d", r.Reserved)
		}
		e.exec(t, "UPDATE ciphers SET notes = $1 WHERE uuid = $2", att.AttachmentID, pcA2) // remember for later
		e.kyid.setFailing(false)

		// (e) A suspended tenant cannot finalize an upload it was admitted for.
		tokA1 := e.accessToken(t, a1)
		pre := createAttachment(t, r1, tokA1, pcA1, 1000)
		if pre.code != 200 {
			t.Fatalf("pre-fence create: %d %s", pre.code, pre.body)
		}
		var preAtt struct {
			AttachmentID string `json:"attachmentId"`
		}
		pre.json(t, &preAtt)
		epoch := e.mustTenant(t, orgA).Epoch
		e.kyid.setOrg(orgA, "suspended", true, cellA)
		eventually(t, 15*time.Second, "tenant A fenced", func() error {
			if r := e.mustTenant(t, orgA); r.Epoch != epoch+1 {
				return fmt.Errorf("%+v", r)
			}
			return nil
		})
		if r := uploadAttachment(t, r2, tokA1, pcA1, preAtt.AttachmentID, 1000); r.code == 200 {
			t.Fatal("fenced tenant finalized an upload")
		}
		if s3Exists(t, attachmentKey(cellA, orgA, pcA1, preAtt.AttachmentID)) {
			t.Fatal("fenced upload reached S3")
		}
		e.kyid.setOrg(orgA, "active", true, cellA)
		eventually(t, 15*time.Second, "tenant A grant after reactivation", func() error {
			r := e.mustTenant(t, orgA)
			if r.Status != "active" || r.Expires == nil || *r.Expires < time.Now().Unix() {
				return fmt.Errorf("%+v", r)
			}
			return nil
		})

		// (f) Overlapping uploads to one attachment on both replicas, shrinking and growing it,
		// while new admissions compete for the bytes. Uploads to one attachment are serialized
		// and sized from its current row, so committed plus reserved never passes the grant.
		e.kyid.setFailing(true)
		tokOv := e.accessToken(t, a2)
		var ovCreated resp
		eventually(t, 10*time.Second, "grant for overlap test", func() error {
			ovCreated = createAttachment(t, r1, tokOv, pcA2, 600_000)
			if ovCreated.code != 200 {
				return fmt.Errorf("%d %s", ovCreated.code, ovCreated.body)
			}
			return nil
		})
		var ov struct {
			AttachmentID string `json:"attachmentId"`
		}
		ovCreated.json(t, &ov)
		if r := uploadAttachment(t, r1, tokOv, pcA2, ov.AttachmentID, 600_000); r.code != 200 {
			t.Fatalf("seed overlap attachment: %d %s", r.code, r.body)
		}
		ovStart := make(chan struct{})
		var ovWG sync.WaitGroup
		ovCodes := make([]resp, 12)
		for i := range ovCodes {
			base := []string{r1, r2}[i%2]
			ovWG.Add(1)
			go func() {
				defer ovWG.Done()
				<-ovStart
				switch i % 3 {
				case 0:
					ovCodes[i], _ = callErrUpload(base, tokOv, pcA2, ov.AttachmentID, 100_000)
				case 1:
					ovCodes[i], _ = callErrUpload(base, tokOv, pcA2, ov.AttachmentID, 1_100_000)
				default:
					ovCodes[i], _ = callErrAttach(base, tokOv, pcA2, 400_000)
				}
			}()
		}
		close(ovStart)
		ovWG.Wait()
		for i, c := range ovCodes {
			if c.code == 0 || c.code >= 500 {
				t.Fatalf("overlap request %d: %d %s", i, c.code, c.body)
			}
		}
		if g := e.mustTenant(t, orgA); e.committed(t, orgA)+g.Reserved > g.Ceiling || g.Reserved != 0 {
			t.Fatalf("overlapping uploads broke the grant: committed %d reserved %d ceiling %d",
				e.committed(t, orgA), g.Reserved, g.Ceiling)
		}
		e.kyid.setFailing(false)

		// Real objects for erasure and purge: A1 personal, B1 personal.
		for _, up := range []struct {
			u      vaultUser
			base   string
			cipher string
		}{{a1, r1, pcA1}, {b1, r2, pcB1}} {
			tok := e.accessToken(t, up.u)
			var created resp
			eventually(t, 10*time.Second, "grant for "+up.u.uuid, func() error {
				created = createAttachment(t, up.base, tok, up.cipher, 4096)
				if created.code != 200 {
					return fmt.Errorf("%d %s", created.code, created.body)
				}
				return nil
			})
			var a struct {
				AttachmentID string `json:"attachmentId"`
			}
			created.json(t, &a)
			if r := uploadAttachment(t, up.base, tok, up.cipher, a.AttachmentID, 4096); r.code != 200 {
				t.Fatalf("upload for %s: %d %s", up.u.uuid, r.code, r.body)
			}
			if !s3Exists(t, attachmentKey(cellFor(up.u.tenant), up.u.tenant, up.cipher, a.AttachmentID)) {
				t.Fatal("upload not in S3")
			}
			e.exec(t, "UPDATE ciphers SET notes = $1 WHERE uuid = $2", a.AttachmentID, up.cipher)
		}
	})

	t.Run("5 back-channel logout and webhook claim after success", func(t *testing.T) {
		stamp0, rt0 := e.stamp(t, a3)
		jti := fmt.Sprintf("jti-%d", time.Now().UnixNano())
		tok := e.logoutToken(e.kyid.logoutKey, "k1", a3.subject, jti)
		r := e.backchannel(t, tok)
		if r.code != 200 || !strings.Contains(string(r.body), `"ok"`) {
			t.Fatalf("logout: %d %s", r.code, r.body)
		}
		if s, rt := e.stamp(t, a3); s == stamp0 || rt == rt0 {
			t.Fatal("logout did not rotate stamp and refresh token")
		}
		stamp1, _ := e.stamp(t, a3)
		if r := e.backchannel(t, tok); r.code != 200 || !strings.Contains(string(r.body), "duplicate") {
			t.Fatalf("logout replay: %d %s", r.code, r.body)
		}
		if s, _ := e.stamp(t, a3); s != stamp1 {
			t.Fatal("replay rotated the stamp again")
		}
		forged, _ := rsa.GenerateKey(rand.Reader, 2048)
		if r := e.backchannel(t, e.logoutToken(forged, "k1", a3.subject, jti+"-forged")); r.code != 400 {
			t.Fatalf("forged logout: want 400, got %d", r.code)
		}
		for _, req := range []map[string]any{
			{"issuer": issuer + "/other", "subject": a3.subject},
			{"issuer": issuer, "subject": "sub-a"},
			{"issuer": issuer, "subject": a3.subject, "tenant_id": orgB},
		} {
			r := internal(t, r1, "POST", "users/logout", req)
			if r.code != 200 || !strings.Contains(string(r.body), `"found":false`) {
				t.Fatalf("inexact logout %v matched: %d %s", req, r.code, r.body)
			}
		}

		// user.deleted while the vault is down stays retryable.
		ev := map[string]any{"id": a3.subject, "externalId": a3.subject, "userName": "a3", "active": false, "org_id": orgA}
		id := fmt.Sprintf("evt-%d", time.Now().UnixNano())
		run(t, "docker", "stop", "-t", "10", "kyvault-e2e-r1")
		if r := e.webhook(t, "user.deleted", id, ev); r.code != 502 {
			t.Fatalf("webhook with vault down: want 502, got %d %s", r.code, r.body)
		}
		if n := e.num(t, `SELECT count(*) FROM worker_processed_events WHERE event_key = $1 AND status = 'completed'`, "sync:"+id); n != 0 {
			t.Fatal("failed webhook was marked completed")
		}
		run(t, "docker", "start", "kyvault-e2e-r1")
		waitAlive(t, "kyvault-e2e-r1", r1)
		if r := e.webhook(t, "user.deleted", id, ev); r.code != 200 || !strings.Contains(string(r.body), `"ok"`) {
			t.Fatalf("webhook retry: %d %s", r.code, r.body)
		}
		if e.num(t, "SELECT count(*) FROM users WHERE uuid = $1 AND enabled", a3.uuid) != 0 {
			t.Fatal("user.deleted did not disable the user")
		}
		if r := e.webhook(t, "user.deleted", id, ev); r.code != 200 || !strings.Contains(string(r.body), "duplicate") {
			t.Fatalf("webhook replay: %d %s", r.code, r.body)
		}
	})

	t.Run("5b hosted emergency access off for existing grants", func(t *testing.T) {
		// Grants that predate the policy: confirmed, past-due recovery, approved view.
		grant := func(id string, status, days int) {
			e.exec(t, `INSERT INTO emergency_access (uuid, grantor_uuid, grantee_uuid, email, key_encrypted, atype, status,
				wait_time_days, recovery_initiated_at, updated_at, created_at)
				VALUES ($1, $2, $3, NULL, 'k', 0, $4, $5, now() - interval '3 days', now(), now())`,
				id, a1.uuid, a2.uuid, status, days)
		}
		const confirmed, initiated, approved = "ea000000-0000-4000-8000-000000000001",
			"ea000000-0000-4000-8000-000000000002", "ea000000-0000-4000-8000-000000000003"
		grant(confirmed, 2, 1)
		grant(initiated, 3, 1)
		grant(approved, 4, 1)
		defer e.exec(t, "DELETE FROM emergency_access WHERE grantor_uuid = $1", a1.uuid)

		tok := e.accessToken(t, a2)
		for _, path := range []string{confirmed + "/initiate", approved + "/view", approved + "/policies"} {
			method := "POST"
			if strings.HasSuffix(path, "/policies") {
				method = "GET"
			}
			r := call(t, method, r1+"/api/emergency-access/"+path, bearer(tok), nil)
			if r.code == 200 || !strings.Contains(string(r.body), "Emergency access is not enabled") {
				t.Fatalf("%s: %d %s", path, r.code, r.body)
			}
		}
		// The timeout job runs every second here; it must not auto-approve the past-due request.
		time.Sleep(3 * time.Second)
		if s := e.num(t, "SELECT status FROM emergency_access WHERE uuid = $1", initiated); s != 3 {
			t.Fatalf("timeout job changed a hosted grant to status %d", s)
		}
	})

	t.Run("6 user erasure keeps shared org data", func(t *testing.T) {
		attA1 := e.str(t, "SELECT notes FROM ciphers WHERE uuid = $1", pcA1)
		keyA1 := attachmentKey(cellA, orgA, pcA1, attA1)
		if !s3Exists(t, keyA1) {
			t.Fatal("precondition: A1 attachment in S3")
		}
		e.kyid.erase(a1.subject, orgA)
		eventually(t, 15*time.Second, "A1 erased", func() error {
			if n := e.num(t, "SELECT count(*) FROM users WHERE uuid = $1", a1.uuid); n != 0 {
				return fmt.Errorf("user still present")
			}
			return nil
		})
		for q, want := range map[string]int64{
			"SELECT count(*) FROM ciphers WHERE uuid = '" + pcA1 + "'":                                                             0,
			"SELECT count(*) FROM attachments WHERE cipher_uuid = '" + pcA1 + "'":                                                  0,
			"SELECT count(*) FROM tenant_recovery_bundles WHERE user_uuid = '" + a1.uuid + "'":                                     0,
			"SELECT count(*) FROM sso_users WHERE user_uuid = '" + a1.uuid + "'":                                                   0,
			"SELECT count(*) FROM users_organizations WHERE user_uuid = '" + a1.uuid + "'":                                         0,
			"SELECT count(*) FROM devices WHERE user_uuid = '" + a1.uuid + "'":                                                     0,
			"SELECT count(*) FROM ciphers WHERE uuid = '" + ocA + "'":                                                              1,
			"SELECT count(*) FROM users WHERE uuid = '" + a2.uuid + "'":                                                            1,
			"SELECT count(*) FROM users_organizations WHERE user_uuid = '" + a2.uuid + "'":                                         1,
			"SELECT count(*) FROM organizations WHERE uuid = '" + orgOA + "'":                                                      1,
			"SELECT count(*) FROM tenant_erased_subjects WHERE subject = 'sub-a1' AND tenant_id = '" + orgA + "' AND revision > 0": 1,
		} {
			if got := e.num(t, q); got != want {
				t.Fatalf("%s = %d, want %d", q, got, want)
			}
		}
		eventually(t, 15*time.Second, "A1 object deleted", func() error {
			if s3Exists(t, keyA1) {
				return fmt.Errorf("still in S3")
			}
			if n := e.num(t, "SELECT count(*) FROM tenant_pending_deletions WHERE user_uuid = $1", a1.uuid); n != 0 {
				return fmt.Errorf("%d pending", n)
			}
			return nil
		})
		r := internal(t, r1, "POST", "users/sync", map[string]any{
			"event_type": "user.updated", "issuer": issuer, "subject": a1.subject, "tenant_id": orgA, "active": true,
		})
		if r.code != 200 || !strings.Contains(string(r.body), "erased_tombstone") {
			t.Fatalf("tombstoned subject sync: %d %s", r.code, r.body)
		}
		ev := map[string]any{"id": a1.subject, "externalId": a1.subject, "userName": "a1", "active": true, "org_id": orgA}
		if r := e.webhook(t, "user.updated", fmt.Sprintf("evt-re-%d", time.Now().UnixNano()), ev); r.code != 200 {
			t.Fatalf("reactivation webhook: %d %s", r.code, r.body)
		}
		if n := e.num(t, "SELECT count(*) FROM users WHERE uuid = $1", a1.uuid); n != 0 {
			t.Fatal("erased subject came back")
		}
	})

	t.Run("7 tenant purge with cleanup failure, tenant B untouched", func(t *testing.T) {
		snapB := func() string {
			var parts []string
			for _, q := range []string{
				"SELECT count(*) FROM users WHERE tenant_id = $1",
				"SELECT count(*) FROM ciphers WHERE tenant_id = $1",
				"SELECT count(*) FROM organizations WHERE tenant_id = $1",
				"SELECT count(*) FROM attachments WHERE tenant_id = $1",
				"SELECT count(*) FROM users_organizations uo JOIN users u ON u.uuid = uo.user_uuid WHERE u.tenant_id = $1",
				"SELECT count(*) FROM sso_users WHERE tenant_id = $1",
				"SELECT count(*) FROM devices d JOIN users u ON u.uuid = d.user_uuid WHERE u.tenant_id = $1",
			} {
				parts = append(parts, fmt.Sprint(e.num(t, q, orgB)))
			}
			parts = append(parts, e.str(t, "SELECT security_stamp FROM users WHERE uuid = $1", b1.uuid))
			return strings.Join(parts, ",")
		}
		before := snapB()
		attB1 := e.str(t, "SELECT notes FROM ciphers WHERE uuid = $1", pcB1)
		keyB1 := attachmentKey(cellB, orgB, pcB1, attB1)
		keyA2 := attachmentKey(cellA, orgA, pcA2, e.str(t, "SELECT notes FROM ciphers WHERE uuid = $1", pcA2))
		if !s3Exists(t, keyB1) || !s3Exists(t, keyA2) {
			t.Fatal("precondition: objects in S3")
		}
		if _, err := os.Stat(e.sendsDir); !os.IsNotExist(err) {
			t.Fatalf("precondition: sends root must be missing: %v", err)
		}

		e.kyid.setOrg(orgA, "deleted", false, cellA)
		eventually(t, 15*time.Second, "purge with failing prefix cleanup", func() error {
			r := e.mustTenant(t, orgA)
			if r.Status != "purge_pending" {
				return fmt.Errorf("%+v", r)
			}
			var attempts int64
			var lastErr *string
			err := e.db.QueryRow(ctx, `SELECT attempts, last_error FROM tenant_pending_deletions
				WHERE tenant_id = $1 AND storage_kind = 'tenant_prefix'`, orgA).Scan(&attempts, &lastErr)
			if err != nil || attempts < 1 || lastErr == nil || !strings.Contains(*lastErr, "storage root") {
				return fmt.Errorf("prefix item: attempts %d err %v %v", attempts, lastErr, err)
			}
			return nil
		})
		for _, q := range []string{
			"SELECT count(*) FROM users WHERE tenant_id = $1",
			"SELECT count(*) FROM ciphers WHERE tenant_id = $1",
			"SELECT count(*) FROM organizations WHERE tenant_id = $1",
			"SELECT count(*) FROM attachments WHERE tenant_id = $1",
			"SELECT count(*) FROM sso_users WHERE tenant_id = $1",
		} {
			if n := e.num(t, q, orgA); n != 0 {
				t.Fatalf("%s: %d rows left", q, n)
			}
		}
		if n := e.num(t, "SELECT count(*) FROM tenant_erased_subjects WHERE subject IN ('sub-a2','sub-a3') AND tenant_id = $1", orgA); n != 2 {
			t.Fatalf("purge tombstones: %d", n)
		}
		eventually(t, 10*time.Second, "A2 object deleted while prefix pending", func() error {
			if s3Exists(t, keyA2) {
				return fmt.Errorf("still in S3")
			}
			return nil
		})
		if r := e.mustTenant(t, orgA); r.Status != "purge_pending" || r.ErasedAt != nil {
			t.Fatalf("finalized before cleanup succeeded: %+v", r)
		}

		must(t, os.MkdirAll(e.sendsDir, 0o755)) // storage restored
		eventually(t, 15*time.Second, "tenant A finalized", func() error {
			r := e.mustTenant(t, orgA)
			if r.Status != "deleted" || r.ErasedAt == nil {
				return fmt.Errorf("%+v", r)
			}
			return nil
		})
		if n := e.num(t, "SELECT count(*) FROM tenant_pending_deletions WHERE tenant_id = $1", orgA); n != 0 {
			t.Fatalf("%d pending deletions left", n)
		}
		if n := s3Count(t, "attachments/cells/"+cellA+"/tenants/"+orgA+"/"); n != 0 {
			t.Fatalf("%d tenant A objects left", n)
		}
		if after := snapB(); after != before {
			t.Fatalf("tenant B changed: %s -> %s", before, after)
		}
		if !s3Exists(t, keyB1) {
			t.Fatal("tenant B object was deleted")
		}
		if c := revisionDate(t, r2, e.accessToken(t, b1)); c != 200 {
			t.Fatalf("tenant B rejected after A's purge: %d", c)
		}
		time.Sleep(2 * time.Second) // more polls must not resurrect A
		if r := e.mustTenant(t, orgA); r.Status != "deleted" {
			t.Fatalf("deleted tenant changed: %+v", r)
		}
	})

	t.Run("8 restart and restore reconciliation", func(t *testing.T) {
		cursor := func(name string) int64 {
			return e.num(t, "SELECT COALESCE((SELECT revision FROM worker_sync_cursors WHERE name = $1), 0)", name)
		}
		orgsCur, erasedCur := cursor("suite_orgs"), cursor("suite_erased")
		if orgsCur == 0 || erasedCur == 0 {
			t.Fatalf("cursors not saved: orgs %d erased %d", orgsCur, erasedCur)
		}

		e.stopWorker(t)
		e.kyid.resetSinces()
		e.startWorker(t, false)
		if o, er := e.kyid.sinces(); len(o) == 0 || o[0] != orgsCur || len(er) == 0 || er[0] != erasedCur {
			t.Fatalf("normal restart did not resume from cursors %d/%d: %v %v", orgsCur, erasedCur, o, er)
		}

		seqB := e.mustTenant(t, orgB).ReportSeq
		e.stopWorker(t)
		e.kyid.resetSinces()
		e.startWorker(t, true)
		if o, er := e.kyid.sinces(); len(o) == 0 || o[0] != 0 || len(er) == 0 || er[0] != 0 {
			t.Fatalf("from-zero restart did not start at 0: %v %v", o, er)
		}
		eventually(t, 10*time.Second, "B reports after restore", func() error {
			r := e.mustTenant(t, orgB)
			if r.ReportSeq <= seqB || r.Applied <= seqB {
				return fmt.Errorf("seq %d applied %d, before %d", r.ReportSeq, r.Applied, seqB)
			}
			return nil
		})
		for _, x := range e.kyid.history(orgB) {
			if x.Result == "stale" && x.Seq > seqB {
				t.Fatalf("restore produced a stale report: %+v", x)
			}
		}
		if r := e.mustTenant(t, orgA); r.Status != "deleted" {
			t.Fatalf("restore replay changed deleted tenant A: %+v", r)
		}
		if n := e.num(t, "SELECT count(*) FROM users WHERE uuid = $1", a1.uuid); n != 0 {
			t.Fatal("restore replay resurrected the erased user")
		}
		if cursor("suite_orgs") < orgsCur || cursor("suite_erased") < erasedCur {
			t.Fatal("cursor moved backwards")
		}
	})

	t.Run("9 cells C4 and C5 invariants", func(t *testing.T) {
		// C5: direct internal API and signed webhook refuse unserved-cell orgC with 403.
		if r := internal(t, r1, "POST", "orgs/reconcile", map[string]any{
			"orgs": []map[string]any{{
				"id": orgC, "status": "active", "enabled": true, "home_region": foreignCell, "revision": 100,
			}},
			"touch_all_active": false,
		}); r.code != 403 {
			t.Fatalf("reconcile for unserved cell: want 403, got %d %s", r.code, r.body)
		}
		if _, ok := e.tenant(t, orgC); ok {
			t.Fatal("unserved-cell orgC was created by direct reconcile")
		}
		if r := internal(t, r1, "POST", "users/sync", map[string]any{
			"event_type": "user.updated", "issuer": issuer, "subject": "sub-c1",
			"tenant_id": orgC, "email": "c1@e2e.test", "display_name": "C1", "active": true,
		}); r.code != 403 {
			t.Fatalf("users/sync for unserved cell: want 403, got %d %s", r.code, r.body)
		}
		evC := map[string]any{"id": "sub-c1", "externalId": "sub-c1", "userName": "c1", "active": true, "org_id": orgC}
		if r := e.webhook(t, "user.updated", fmt.Sprintf("evt-c5-%d", time.Now().UnixNano()), evC); r.code != 403 {
			t.Fatalf("webhook for unserved cell: want 403, got %d %s", r.code, r.body)
		}

		// C5: an erasure for foreign orgC advances suite_erased cursor without stalling.
		erasedBefore := e.num(t, "SELECT COALESCE((SELECT revision FROM worker_sync_cursors WHERE name = 'suite_erased'), 0)")
		e.kyid.erase("sub-c-erased", orgC)
		eventually(t, 15*time.Second, "foreign erasure skipped and cursor advanced", func() error {
			cur := e.num(t, "SELECT COALESCE((SELECT revision FROM worker_sync_cursors WHERE name = 'suite_erased'), 0)")
			if cur <= erasedBefore {
				return fmt.Errorf("cursor still %d", cur)
			}
			return nil
		})

		// C4: mutating orgB's home_region refuses the move, fences orgB, and stays fenced across polls.
		tokB1 := e.accessToken(t, b1)
		if c := revisionDate(t, r2, tokB1); c != 200 {
			t.Fatalf("b1 before C4 move: %d", c)
		}
		beforeB := e.mustTenant(t, orgB)
		e.kyid.setOrg(orgB, "active", true, foreignCell)
		eventually(t, 15*time.Second, "orgB fenced on C4 home_region mismatch", func() error {
			r := e.mustTenant(t, orgB)
			if r.Epoch != beforeB.Epoch+1 || r.AuthorityAt != nil {
				return fmt.Errorf("%+v", r)
			}
			return nil
		})
		// Wait past a subsequent empty heartbeat poll to prove touch_all_active does not un-fence orgB.
		time.Sleep(2 * time.Second)
		afterB := e.mustTenant(t, orgB)
		if afterB.HomeRegion != cellB {
			t.Fatalf("C4 violation: orgB home_region mutated to %q, want %q", afterB.HomeRegion, cellB)
		}
		if afterB.AuthorityAt != nil || afterB.Ceiling != 0 {
			t.Fatalf("orgB did not stay fenced after C4 mismatch: %+v", afterB)
		}
		if c := revisionDate(t, r2, tokB1); c == 200 {
			t.Fatal("replica 2 still accepts b1 token after C4 mismatch fence")
		}
	})
}

func callErrAttach(base, token, cipher string, size int64) (resp, error) {
	body, _ := json.Marshal(map[string]any{"key": "2.a|b|c", "fileName": "2.f|g|h", "fileSize": size})
	return callErr("POST", base+"/api/ciphers/"+cipher+"/attachment/v2", bearer(token), body)
}
