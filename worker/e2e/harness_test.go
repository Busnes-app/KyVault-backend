package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Fixed loopback ports; the replicas run on the host network.
const (
	pgPort     = "55417"
	s3Port     = "59000"
	r1Port     = "58081"
	r2Port     = "58082"
	singlePort = "58083"
	workerPort = "58085"
	kyidPort   = "58443"

	label         = "kyvault-e2e=1"
	rustImage     = "kyvault-e2e-rust:local"
	targetVolume  = "kyvault-e2e-target"
	pgImage       = "postgres:18-alpine"
	s3Image       = "rustfs/rustfs:1.0.3"
	cellA         = "eu-west-1"
	cellB         = "eu-west-2"
	foreignCell   = "us-east-1"
	servedCells   = cellA + "," + cellB
	domain        = "https://vault.e2e.test"
	bucket        = "kyvault"
	s3Access      = "e2eaccesskey"
	s3Secret      = "e2esecretkey0123456789"
	internalToken = "e2e-internal-secret-0123456789abcdef"
	webhookSecret = "e2e-webhook-secret-0123456789abcdef"
	clientID      = "kyvault"
	clientSecret  = "kyvault-client-secret"
	pgURL         = "postgres://vault:vaultpw@127.0.0.1:" + pgPort + "/vault"
	// kye2e only starts multi-tenant mode against a `.test` issuer. Replicas resolve this host
	// through --add-host; the worker and the test reach KyIdentity at kyidURL.
	kyidHost   = "kyidentity.e2e.test"
	issuer     = "https://" + kyidHost + ":" + kyidPort
	kyidURL    = "https://127.0.0.1:" + kyidPort
	ttlSeconds = 600
	poolBytes  = 10 << 30
	wantBytes  = 1 << 20
)

var (
	r1     = "http://127.0.0.1:" + r1Port
	r2     = "http://127.0.0.1:" + r2Port
	single = "http://127.0.0.1:" + singlePort
	worker = "http://127.0.0.1:" + workerPort
)

func eventually(t *testing.T, timeout time.Duration, what string, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var err error
	for time.Now().Before(deadline) {
		if err = cond(); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s: %v", timeout, what, err)
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// removeContainers force-removes every container this suite labels, with anonymous volumes.
func removeContainers() {
	out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label="+label).Output()
	if ids := strings.Fields(string(out)); len(ids) > 0 {
		_ = exec.Command("docker", append([]string{"rm", "-fv"}, ids...)...).Run()
	}
}

func dockerLogs(t *testing.T, name string) {
	t.Helper()
	out, _ := exec.Command("docker", "logs", "--tail", "80", name).CombinedOutput()
	t.Logf("---- docker logs %s ----\n%s", name, out)
}

// ---------------------------------------------------------------------------
// HTTP

type resp struct {
	code int
	body []byte
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

var httpc = &http.Client{Timeout: 20 * time.Second}

func call(t *testing.T, method, u string, hdr map[string]string, body []byte) resp {
	t.Helper()
	r, err := callErr(method, u, hdr, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	return r
}

func callErr(method, u string, hdr map[string]string, body []byte) (resp, error) {
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return resp{}, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := httpc.Do(req)
	if err != nil {
		return resp{}, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, b}, nil
}

func internal(t *testing.T, base, method, path string, body any) resp {
	t.Helper()
	hdr := map[string]string{"Authorization": "Bearer " + internalToken, "Content-Type": "application/json"}
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	return call(t, method, base+"/internal/tenancy/v1/"+path, hdr, raw)
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}
}

// ---------------------------------------------------------------------------
// JWTs

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signRS256(key *rsa.PrivateKey, header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return input + "." + b64(sig)
}

type vaultUser struct {
	uuid, tenant, subject string
}

func (u vaultUser) device() string { return "dev-" + u.uuid }

// accessToken mints a login JWT exactly as the vault signs one, with the shared replica key
// and the user's current security stamp.
func (e *env) accessToken(t *testing.T, u vaultUser) string {
	t.Helper()
	now := time.Now().Unix()
	return signRS256(e.vaultKey, map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{
		"nbf": now - 5, "exp": now + 3600, "iss": domain + "|login", "sub": u.uuid,
		"premium": true, "name": u.uuid, "email": u.uuid + "@e2e.test", "email_verified": true,
		"sstamp": e.str(t, "SELECT security_stamp FROM users WHERE uuid = $1", u.uuid),
		"device": u.device(), "devicetype": "Linux", "client_id": "web",
		"scope": []string{"api", "offline_access"}, "amr": []string{"Application"}, "tid": u.tenant,
	})
}

// refreshToken mints an SSO refresh JWT for the user's device refresh token.
func (e *env) refreshToken(u vaultUser, deviceToken string) string {
	now := time.Now().Unix()
	return signRS256(e.vaultKey, map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{
		"nbf": now - 5, "exp": now + 3600, "iss": domain + "|login", "sub": "sso",
		"device_token": deviceToken, "tid": u.tenant,
	})
}

// refresh redeems a refresh JWT at the token endpoint.
func refresh(base, token string) (resp, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {"web"}}
	return callErr("POST", base+"/identity/connect/token",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(form.Encode()))
}

// commitWhenBlocked starts req while tx holds the rows a revocation just wrote, waits until
// req's backend is blocked on one of them, then commits tx. req read those rows before
// blocking, so it resumes with a pre-revocation snapshot: the race the vault must survive.
func (e *env) commitWhenBlocked(t *testing.T, tx pgx.Tx, req func() (resp, error)) resp {
	t.Helper()
	ctx := context.Background()
	type result struct {
		r   resp
		err error
	}
	done := make(chan result, 1)
	go func() { r, err := req(); done <- result{r, err} }()
	eventually(t, 20*time.Second, "request blocked on the revocation's row lock", func() error {
		var n int64
		if err := e.db.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'
			AND wait_event IN ('transactionid', 'tuple')`).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("not blocked yet")
		}
		return nil
	})
	must(t, tx.Commit(ctx))
	select {
	case res := <-done:
		must(t, res.err)
		return res.r
	case <-time.After(30 * time.Second):
		t.Fatal("request did not finish after the revocation committed")
	}
	return resp{}
}

func (e *env) logoutToken(key *rsa.PrivateKey, kid, sub, jti string) string {
	now := time.Now().Unix()
	return signRS256(key, map[string]any{"alg": "RS256", "typ": "logout+jwt", "kid": kid}, map[string]any{
		"iss": issuer, "aud": clientID, "iat": now, "exp": now + 120, "jti": jti, "sub": sub,
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	})
}

// ---------------------------------------------------------------------------
// Fake KyIdentity: the SUITE-DIRECTORY.md wire format, client_secret_basic, JWKS.

type orgState struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Revision   int64  `json:"revision"`
	HomeRegion string `json:"home_region"`
	Enabled    bool   `json:"enabled"`
}

type erasedEntry struct {
	Sub      string `json:"sub"`
	OrgID    string `json:"org_id"`
	Revision int64  `json:"revision"`
}

type report struct {
	OrgID     string `json:"org_id"`
	UsedBytes int64  `json:"used_bytes"`
	Seq       int64  `json:"seq"`
	WantBytes int64  `json:"want_bytes"`
}

// exchange is one report as KyIdentity received and answered it.
type exchange struct {
	report
	At      int64  // unix second the request arrived
	Result  string // ok, stale, failed
	Ceiling int64
}

type kyid struct {
	mu        sync.Mutex
	rev       int64
	orgs      map[string]*orgState
	erased    []erasedEntry
	lastSeq   map[string]int64
	stale     map[string]int64
	failing   bool
	exchanges []exchange
	orgsSince []int64
	erasSince []int64
	badAuth   int

	logoutKey *rsa.PrivateKey
	srv       *http.Server

	// OIDC sign-in (sso_test.go)
	signIns []map[string]any          // claims for the next /authorize calls, in order
	codes   map[string]oidcGrant      // authorization code -> grant
	access  map[string]map[string]any // access token -> userinfo claims
}

func (k *kyid) setOrg(id, status string, enabled bool, region string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rev++
	k.orgs[id] = &orgState{ID: id, Status: status, Revision: k.rev, HomeRegion: region, Enabled: enabled}
}

func (k *kyid) erase(sub, org string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rev++
	k.erased = append(k.erased, erasedEntry{Sub: sub, OrgID: org, Revision: k.rev})
}

func (k *kyid) setFailing(v bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.failing = v
}

func (k *kyid) setStale(org string, seq int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if seq == 0 {
		delete(k.stale, org)
	} else {
		k.stale[org] = seq
	}
}

func (k *kyid) history(org string) []exchange {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []exchange
	for _, x := range k.exchanges {
		if x.OrgID == org {
			out = append(out, x)
		}
	}
	return out
}

func (k *kyid) sinces() (orgs, erased []int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]int64(nil), k.orgsSince...), append([]int64(nil), k.erasSince...)
}

func (k *kyid) resetSinces() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.orgsSince, k.erasSince = nil, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (k *kyid) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := k.logoutKey.PublicKey
		writeJSON(w, 200, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id, sec, ok := r.BasicAuth()
			if !ok || id != clientID || sec != clientSecret {
				k.mu.Lock()
				k.badAuth++
				k.mu.Unlock()
				writeJSON(w, 401, map[string]string{"error": "invalid_client"})
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /api/suite/orgs", auth(func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		k.mu.Lock()
		defer k.mu.Unlock()
		k.orgsSince = append(k.orgsSince, since)
		list := []map[string]any{}
		var orgs []*orgState
		for _, o := range k.orgs {
			if o.Revision > since {
				orgs = append(orgs, o)
			}
		}
		sort.Slice(orgs, func(i, j int) bool { return orgs[i].Revision < orgs[j].Revision })
		for _, o := range orgs {
			list = append(list, map[string]any{
				"id": o.ID, "status": o.Status, "revision": o.Revision, "home_region": o.HomeRegion,
				"enabled": o.Enabled, "quotas": map[string]any{"max_ciphers": 1000},
			})
		}
		writeJSON(w, 200, map[string]any{"orgs": list, "next": ""})
	}))
	mux.HandleFunc("GET /api/suite/erased", auth(func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		k.mu.Lock()
		defer k.mu.Unlock()
		k.erasSince = append(k.erasSince, since)
		subs := []erasedEntry{}
		for _, e := range k.erased {
			if e.Revision > since {
				subs = append(subs, e)
			}
		}
		writeJSON(w, 200, map[string]any{"subjects": subs})
	}))
	mux.HandleFunc("POST /api/suite/storage", auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Reports []report `json:"reports"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad_request"})
			return
		}
		now := time.Now().Unix()
		k.mu.Lock()
		defer k.mu.Unlock()
		if k.failing {
			for _, rep := range body.Reports {
				k.exchanges = append(k.exchanges, exchange{report: rep, At: now, Result: "failed"})
			}
			writeJSON(w, 503, map[string]string{"error": "unavailable"})
			return
		}
		results := []map[string]any{}
		for _, rep := range body.Reports {
			o := k.orgs[rep.OrgID]
			if o == nil {
				results = append(results, map[string]any{"org_id": rep.OrgID, "result": "unknown_org"})
				k.exchanges = append(k.exchanges, exchange{report: rep, At: now, Result: "unknown_org"})
				continue
			}
			result, seq := "ok", rep.Seq
			if s := max(k.stale[rep.OrgID], k.lastSeq[rep.OrgID]); s > rep.Seq || k.stale[rep.OrgID] > 0 {
				result, seq = "stale", max(s, rep.Seq)
			} else {
				k.lastSeq[rep.OrgID] = rep.Seq
			}
			ceiling := rep.UsedBytes + rep.WantBytes
			k.exchanges = append(k.exchanges, exchange{report: rep, At: now, Result: result, Ceiling: ceiling})
			results = append(results, map[string]any{
				"org_id": rep.OrgID, "result": result, "seq": seq, "ceiling_bytes": ceiling,
				"ttl_seconds": ttlSeconds, "pool_bytes": poolBytes, "org_used_bytes": rep.UsedBytes, "over_since": nil,
			})
		}
		writeJSON(w, 200, map[string]any{"results": results})
	}))
	k.oidcRoutes(mux)
	return mux
}

// tlsFiles writes a throwaway CA and a leaf for 127.0.0.1 and kyidHost; the worker and the
// replicas trust the CA via SSL_CERT_FILE.
func tlsFiles(t *testing.T, dir string) (caFile string, cert tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kyvault-e2e-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{kyidHost}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return caFile, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// ---------------------------------------------------------------------------
// S3 (SigV4, path style) against the live RustFS container.

func s3Do(method, key, query string, body []byte) (resp, error) {
	host := "127.0.0.1:" + s3Port
	path := "/" + bucket
	if key != "" {
		path += "/" + key
	}
	u := "http://" + host + path
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return resp{}, err
	}
	now := time.Now().UTC()
	amzDate, day := now.Format("20060102T150405Z"), now.Format("20060102")
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payload)
	canonQuery := ""
	if query != "" {
		vals, _ := url.ParseQuery(query)
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, url.QueryEscape(k)+"="+strings.ReplaceAll(url.QueryEscape(vals.Get(k)), "+", "%20"))
		}
		canonQuery = strings.Join(parts, "&")
	}
	canon := strings.Join([]string{
		method, path, canonQuery,
		"host:" + host + "\nx-amz-content-sha256:" + payload + "\nx-amz-date:" + amzDate + "\n",
		"host;x-amz-content-sha256;x-amz-date", payload,
	}, "\n")
	scope := day + "/us-east-1/s3/aws4_request"
	ch := sha256.Sum256([]byte(canon))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(ch[:])
	mac := func(k []byte, s string) []byte { h := hmac.New(sha256.New, k); h.Write([]byte(s)); return h.Sum(nil) }
	sk := mac(mac(mac(mac([]byte("AWS4"+s3Secret), day), "us-east-1"), "s3"), "aws4_request")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s3Access+"/"+scope+
		", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+hex.EncodeToString(mac(sk, toSign)))
	res, err := httpc.Do(req)
	if err != nil {
		return resp{}, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, b}, nil
}

func s3Exists(t *testing.T, key string) bool {
	t.Helper()
	r, err := s3Do(http.MethodHead, key, "", nil)
	if err != nil {
		t.Fatalf("HEAD %s: %v", key, err)
	}
	switch r.code {
	case 200:
		return true
	case 404:
		return false
	}
	t.Fatalf("HEAD %s: status %d", key, r.code)
	return false
}

func s3Count(t *testing.T, prefix string) int {
	t.Helper()
	r, err := s3Do(http.MethodGet, "", "list-type=2&prefix="+url.QueryEscape(prefix), nil)
	if err != nil || r.code != 200 {
		t.Fatalf("list %s: %v %d %s", prefix, err, r.code, r.body)
	}
	return strings.Count(string(r.body), "<Key>")
}

// ---------------------------------------------------------------------------
// WebSocket: just enough RFC 6455 to hold a hub connection and see it closed.

type wsConn struct {
	c  net.Conn
	br *bufio.Reader
}

func dialHub(t *testing.T, base, token string) *wsConn {
	t.Helper()
	u, _ := url.Parse(base)
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "GET /notifications/hub?access_token=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", token, u.Host)
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, " 101 ") {
		t.Fatalf("websocket upgrade at %s: %q %v", base, status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	return &wsConn{c, br}
}

// closedWithin reports whether the server closed the connection within d. Pings are skipped.
func (w *wsConn) closedWithin(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		_ = w.c.SetReadDeadline(deadline)
		var hdr [2]byte
		if _, err := io.ReadFull(w.br, hdr[:]); err != nil {
			var ne net.Error
			return !(errors.As(err, &ne) && ne.Timeout())
		}
		n := uint64(hdr[1] & 0x7f)
		switch n {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(w.br, ext[:]); err != nil {
				return true
			}
			n = uint64(ext[0])<<8 | uint64(ext[1])
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(w.br, ext[:]); err != nil {
				return true
			}
			n = 0
			for _, b := range ext {
				n = n<<8 | uint64(b)
			}
		}
		if _, err := io.CopyN(io.Discard, w.br, int64(n)); err != nil {
			return true
		}
		if hdr[0]&0x0f == 0x8 {
			return true
		}
	}
}

// ---------------------------------------------------------------------------
// Environment

type env struct {
	dir      string
	db       *pgxpool.Pool
	vaultKey *rsa.PrivateKey
	kyid     *kyid
	caFile   string
	sendsDir string
	workerB  string
	workerP  *exec.Cmd
	workerW  chan error
	workerN  int
}

func (e *env) str(t *testing.T, q string, args ...any) string {
	t.Helper()
	var s string
	if err := e.db.QueryRow(context.Background(), q, args...).Scan(&s); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return s
}

func (e *env) num(t *testing.T, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := e.db.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (e *env) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := e.db.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func replicaEnv(port string) []string {
	return append([]string{
		"DATA_FOLDER=/data",
		"DATABASE_URL=postgresql://vault:vaultpw@127.0.0.1:" + pgPort + "/vault",
		"TENANCY_MODE=multi",
		"KY_CELLS=" + servedCells,
		"TENANCY_INTERNAL_API_SECRET=" + internalToken,
		"TENANCY_PG_NOTIFY_ENABLED=true",
		"SSO_ENABLED=true", "SSO_ONLY=true", "SSO_AUTHORITY=" + issuer,
		"SSO_CLIENT_ID=" + clientID, "SSO_CLIENT_SECRET=" + clientSecret,
		"SSO_AUTH_ONLY_NOT_SESSION=true", "SSL_CERT_FILE=/data/ca.pem",
		"SIGNUPS_ALLOWED=false",
		"DOMAIN=" + domain,
		"AWS_EC2_METADATA_DISABLED=true",
		"ROCKET_ADDRESS=127.0.0.1", "ROCKET_PORT=" + port,
		"WEB_VAULT_ENABLED=false", "LOG_LEVEL=info",
		"LOGIN_RATELIMIT_MAX_BURST=1000", // the journey signs in many times a minute
		"JOB_POLL_INTERVAL_MS=200", "EMERGENCY_REQUEST_TIMEOUT_SCHEDULE=* * * * * *",
	}, s3Env()...)
}

// s3Env is the attachments storage config the replicas and the worker share verbatim.
func s3Env() []string {
	return []string{
		"ATTACHMENTS_FOLDER=s3://" + bucket + "/attachments?endpoint=http://127.0.0.1:" + s3Port +
			"&region=us-east-1&enable_virtual_host_style=false&default_storage_class=STANDARD",
		"AWS_ACCESS_KEY_ID=" + s3Access, "AWS_SECRET_ACCESS_KEY=" + s3Secret, "AWS_REGION=us-east-1",
	}
}

func startReplica(t *testing.T, name, dataDir string, envs []string) {
	t.Helper()
	args := []string{"run", "-d", "--name", name, "--label", label, "--network", "host",
		"--add-host", kyidHost + ":127.0.0.1",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", targetVolume + ":/target:ro", "-v", dataDir + ":/data"}
	for _, e := range envs {
		args = append(args, "-e", e)
	}
	args = append(args, rustImage, "/target/debug/vaultwarden")
	run(t, "docker", args...)
}

func waitAlive(t *testing.T, name, base string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if r, err := callErr("GET", base+"/alive", nil, nil); err == nil && r.code == 200 {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	dockerLogs(t, name)
	t.Fatalf("%s never became alive", name)
}

func setup(t *testing.T) *env {
	t.Helper()
	if os.Getenv("KYVAULT_E2E_PG") != "1" {
		t.Skip("set KYVAULT_E2E_PG=1 (worker/e2e/run.sh) for the live PostgreSQL suite")
	}
	removeContainers()
	t.Cleanup(removeContainers)

	e := &env{dir: t.TempDir()}
	e.sendsDir = filepath.Join(e.dir, "sends") // created later: the injected cleanup failure

	run(t, "docker", "run", "-d", "--name", "kyvault-e2e-pg", "--label", label, "-p", "127.0.0.1:"+pgPort+":5432",
		"-e", "POSTGRES_USER=vault", "-e", "POSTGRES_PASSWORD=vaultpw", "-e", "POSTGRES_DB=vault", pgImage)
	run(t, "docker", "run", "-d", "--name", "kyvault-e2e-s3", "--label", label, "-p", "127.0.0.1:"+s3Port+":9000",
		"-e", "RUSTFS_ACCESS_KEY="+s3Access, "-e", "RUSTFS_SECRET_KEY="+s3Secret, s3Image)

	ctx := context.Background()
	eventually(t, 60*time.Second, "postgres", func() error {
		pool, err := pgxpool.New(ctx, pgURL)
		if err != nil {
			return err
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			return err
		}
		e.db = pool
		return nil
	})
	t.Cleanup(e.db.Close)
	if v := e.str(t, "SHOW server_version"); !strings.HasPrefix(v, "18.") {
		t.Fatalf("want PostgreSQL 18, got %s", v)
	}
	eventually(t, 60*time.Second, "s3 bucket", func() error {
		r, err := s3Do(http.MethodPut, "", "", nil)
		if err != nil {
			return err
		}
		if r.code != 200 && !bytes.Contains(r.body, []byte("BucketAlreadyOwnedByYou")) {
			return fmt.Errorf("create bucket: %d %s", r.code, r.body)
		}
		return nil
	})

	// Shared replica key, pre-provisioned as multi-tenant mode requires.
	var err error
	if e.vaultKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(e.dir, "data")
	must(t, os.MkdirAll(data, 0o755))
	must(t, os.WriteFile(filepath.Join(data, "rsa_key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(e.vaultKey)}), 0o600))

	// KyIdentity fake on TLS.
	e.kyid = &kyid{orgs: map[string]*orgState{}, lastSeq: map[string]int64{}, stale: map[string]int64{},
		codes: map[string]oidcGrant{}, access: map[string]map[string]any{}}
	if e.kyid.logoutKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	var cert tls.Certificate
	e.caFile, cert = tlsFiles(t, e.dir)
	ca, err := os.ReadFile(e.caFile)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(data, "ca.pem"), ca, 0o644))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	noRedirect.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	ln, err := tls.Listen("tcp", "127.0.0.1:"+kyidPort, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	e.kyid.srv = &http.Server{Handler: e.kyid.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = e.kyid.srv.Serve(ln) }()
	t.Cleanup(func() { _ = e.kyid.srv.Close() })

	startReplica(t, "kyvault-e2e-r1", data, replicaEnv(r1Port))
	waitAlive(t, "kyvault-e2e-r1", r1) // r1 runs the migrations first
	startReplica(t, "kyvault-e2e-r2", data, replicaEnv(r2Port))
	waitAlive(t, "kyvault-e2e-r2", r2)

	singleData := filepath.Join(e.dir, "single")
	must(t, os.MkdirAll(singleData, 0o755))
	startReplica(t, "kyvault-e2e-single", singleData, []string{
		"DATA_FOLDER=/data", "DATABASE_URL=sqlite:///data/db.sqlite3", "TENANCY_INTERNAL_API_SECRET=" + internalToken,
		"ROCKET_ADDRESS=127.0.0.1", "ROCKET_PORT=" + singlePort, "WEB_VAULT_ENABLED=false", "DOMAIN=http://127.0.0.1:" + singlePort,
	})
	waitAlive(t, "kyvault-e2e-single", single)

	e.workerB = filepath.Join(e.dir, "kyvault-worker")
	build := exec.Command("go", "build", "-o", e.workerB, "./cmd/kyvault-worker")
	build.Dir = ".."
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build worker: %v\n%s", err, out)
	}
	t.Cleanup(func() { e.stopWorker(t) })
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) startWorker(t *testing.T, fromZero bool) {
	t.Helper()
	e.workerN++
	logPath := filepath.Join(e.dir, fmt.Sprintf("worker-%d.log", e.workerN))
	logf, err := os.Create(logPath)
	must(t, err)
	cmd := exec.Command(e.workerB)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + e.dir, "SSL_CERT_FILE=" + e.caFile,
		"WORKER_LISTEN_ADDR=127.0.0.1:" + workerPort,
		"DATABASE_URL=" + pgURL,
		"KY_CELLS=" + servedCells,
		"VAULT_INTERNAL_API_URL=" + r1,
		"TENANCY_INTERNAL_API_SECRET=" + internalToken,
		"SSO_AUTHORITY=" + issuer, "SSO_CLIENT_ID=" + clientID, "SSO_CLIENT_SECRET=" + clientSecret,
		"KYIDENTITY_BASE_URL=" + kyidURL, "OIDC_JWKS_URL=" + kyidURL + "/.well-known/jwks.json",
		"SYNC_WEBHOOK_SECRET=" + webhookSecret,
		"ORG_POLL_INTERVAL=1s", "ERASED_POLL_INTERVAL=1s", "STORAGE_REPORT_INTERVAL=1s", "CLEANUP_INTERVAL=1s",
		"STORAGE_WANT_BYTES=" + strconv.Itoa(wantBytes),
		"SENDS_FOLDER=" + e.sendsDir,
		"TENANCY_RECONCILE_FROM_ZERO=" + strconv.FormatBool(fromZero),
	}
	cmd.Env = append(cmd.Env, s3Env()...)
	must(t, cmd.Start())
	e.workerP = cmd
	e.workerW = make(chan error, 1)
	go func() { e.workerW <- cmd.Wait(); logf.Close() }()
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := os.ReadFile(logPath)
			lines := strings.Split(string(out), "\n")
			t.Logf("---- %s (tail) ----\n%s", logPath, strings.Join(lines[max(0, len(lines)-60):], "\n"))
		}
	})
	eventually(t, 30*time.Second, "worker ready", func() error {
		r, err := callErr("GET", worker+"/readyz", nil, nil)
		if err != nil {
			return err
		}
		if r.code != 200 {
			return fmt.Errorf("readyz %d %s", r.code, r.body)
		}
		return nil
	})
}

func (e *env) stopWorker(t *testing.T) {
	if e.workerP == nil {
		return
	}
	_ = e.workerP.Process.Signal(os.Interrupt)
	select {
	case <-e.workerW:
	case <-time.After(15 * time.Second):
		_ = e.workerP.Process.Kill()
		<-e.workerW
	}
	e.workerP = nil
}

// ---------------------------------------------------------------------------
// Signed webhook and logout delivery to the worker.

func (e *env) webhook(t *testing.T, eventType, eventID string, body any) resp {
	t.Helper()
	raw, _ := json.Marshal(body)
	h, err := syncauth.Sign([]byte(webhookSecret), time.Now(), eventType, eventID, raw)
	must(t, err)
	req, _ := http.NewRequest("POST", worker+"/api/sync/events", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	h.Apply(req)
	res, err := httpc.Do(req)
	must(t, err)
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, b}
}

func (e *env) backchannel(t *testing.T, token string) resp {
	t.Helper()
	form := url.Values{"logout_token": {token}}.Encode()
	return call(t, "POST", worker+"/api/oidc/backchannel-logout",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(form))
}

// ---------------------------------------------------------------------------
// Vault public API: attachments.

func createAttachment(t *testing.T, base, token, cipher string, size int64) resp {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"key": "2.a|b|c", "fileName": "2.f|g|h", "fileSize": size})
	return call(t, "POST", base+"/api/ciphers/"+cipher+"/attachment/v2", bearer(token), body)
}

func uploadAttachment(t *testing.T, base, token, cipher, attID string, size int) resp {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("key", "2.a|b|c")
	fw, _ := mw.CreateFormFile("data", "blob.bin")
	_, _ = fw.Write(bytes.Repeat([]byte{0x5a}, size))
	_ = mw.Close()
	return call(t, "POST", base+"/api/ciphers/"+cipher+"/attachment/"+attID,
		map[string]string{"Authorization": "Bearer " + token, "Content-Type": mw.FormDataContentType()}, buf.Bytes())
}

// callErrUpload is uploadAttachment without t, for use from goroutines.
func callErrUpload(base, token, cipher, attID string, size int) (resp, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("key", "2.a|b|c")
	fw, _ := mw.CreateFormFile("data", "blob.bin")
	_, _ = fw.Write(bytes.Repeat([]byte{0x5a}, size))
	_ = mw.Close()
	return callErr("POST", base+"/api/ciphers/"+cipher+"/attachment/"+attID,
		map[string]string{"Authorization": "Bearer " + token, "Content-Type": mw.FormDataContentType()}, buf.Bytes())
}

func attachmentKey(cell, tenant, cipher, att string) string {
	return "attachments/cells/" + cell + "/tenants/" + tenant + "/attachments/" + cipher + "/" + att
}
