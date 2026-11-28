package e2e

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// KyIdentity as the OIDC provider: discovery, authorization code with PKCE, userinfo.
// ID tokens are signed with the JWKS key (k1) the worker also verifies logout tokens with.

type oidcGrant struct {
	claims        map[string]any
	nonce         string
	challenge     string
	redirectURI   string
	authorizedFor string // client_id
}

// signIn queues the claims KyIdentity puts in the next sign-in's ID token and userinfo.
func (k *kyid) signIn(claims map[string]any) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.signIns = append(k.signIns, claims)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (k *kyid) oidcRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"userinfo_endpoint":                     issuer + "/userinfo",
			"jwks_uri":                              issuer + "/.well-known/jwks.json",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		k.mu.Lock()
		defer k.mu.Unlock()
		if q.Get("client_id") != clientID || q.Get("response_type") != "code" || len(k.signIns) == 0 {
			writeJSON(w, 400, map[string]string{"error": "invalid_request"})
			return
		}
		code := randHex(16)
		k.codes[code] = oidcGrant{claims: k.signIns[0], nonce: q.Get("nonce"), challenge: q.Get("code_challenge"),
			redirectURI: q.Get("redirect_uri"), authorizedFor: q.Get("client_id")}
		k.signIns = k.signIns[1:]
		back, _ := url.Parse(q.Get("redirect_uri"))
		v := back.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		back.RawQuery = v.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		id, sec, ok := r.BasicAuth()
		if !ok || id != clientID || sec != clientSecret || r.ParseForm() != nil {
			writeJSON(w, 401, map[string]string{"error": "invalid_client"})
			return
		}
		k.mu.Lock()
		defer k.mu.Unlock()
		g, ok := k.codes[r.PostForm.Get("code")]
		delete(k.codes, r.PostForm.Get("code"))
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || r.PostForm.Get("grant_type") != "authorization_code" || g.redirectURI != r.PostForm.Get("redirect_uri") ||
			(g.challenge != "" && g.challenge != b64(sum[:])) {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		now := time.Now().Unix()
		claims := map[string]any{"iss": issuer, "aud": g.authorizedFor, "iat": now, "exp": now + 300, "nonce": g.nonce}
		for key, v := range g.claims {
			claims[key] = v
		}
		at := randHex(24)
		k.access[at] = g.claims
		writeJSON(w, 200, map[string]any{
			"access_token": at, "token_type": "Bearer", "expires_in": 300,
			"id_token": signRS256(k.logoutKey, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"}, claims),
		})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		claims, ok := k.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		k.mu.Unlock()
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "invalid_token"})
			return
		}
		writeJSON(w, 200, claims)
	})
}

// ---------------------------------------------------------------------------
// The web client's side of SSO sign-in, against a replica.

// noRedirect is httpc without redirect following, so each hop of the flow is visible.
var noRedirect = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}}

const webRedirect = domain + "/sso-connector.html"

// ssoSignIn runs the web client's SSO sign-in on base for a KyIdentity user with claims:
// /identity/connect/authorize, KyIdentity's /authorize, the vault's oidc-signin callback,
// then the authorization_code grant. It returns the token endpoint's answer.
func (e *env) ssoSignIn(t *testing.T, base string, claims map[string]any, device string) resp {
	t.Helper()
	e.kyid.signIn(claims)
	verifier := randHex(32)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {"web"}, "redirect_uri": {webRedirect}, "response_type": {"code"},
		"scope": {"api offline_access"}, "state": {"client-" + randHex(8)},
		"code_challenge": {b64(sum[:])}, "code_challenge_method": {"S256"}}
	hop := func(u string, cookie string) *http.Response {
		t.Helper()
		req, err := http.NewRequest("GET", u, nil)
		must(t, err)
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		res, err := noRedirect.Do(req)
		must(t, err)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode/100 != 3 {
			t.Fatalf("GET %s: want a redirect, got %d %s", u, res.StatusCode, body)
		}
		return res
	}
	// The vault sends the browser to KyIdentity and binds the flow to a cookie.
	res := hop(base+"/identity/connect/authorize?"+q.Encode(), "")
	var cookie string
	for _, c := range res.Cookies() {
		cookie = c.Name + "=" + c.Value
	}
	toIdP, err := url.Parse(res.Header.Get("Location"))
	must(t, err)
	if !strings.HasPrefix(toIdP.String(), issuer+"/authorize?") {
		t.Fatalf("authorize redirected to %s, want %s/authorize", toIdP, issuer)
	}
	// KyIdentity answers on the vault's public DOMAIN; this test reaches both by loopback.
	back, err := url.Parse(hop(kyidURL+"/authorize?"+toIdP.RawQuery, "").Header.Get("Location"))
	must(t, err)
	if !strings.HasPrefix(back.String(), domain+"/identity/connect/oidc-signin?") {
		t.Fatalf("KyIdentity redirected to %s", back)
	}
	toClient, err := url.Parse(hop(base+back.RequestURI(), cookie).Header.Get("Location"))
	must(t, err)
	code := toClient.Query().Get("code")
	if !strings.HasPrefix(toClient.String(), webRedirect+"?") || code == "" {
		t.Fatalf("oidc-signin redirected to %s", toClient)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {"web"}, "redirect_uri": {webRedirect}, "scope": {"api offline_access"},
		"device_identifier": {device}, "device_name": {"e2e"}, "device_type": {"10"}}
	return call(t, "POST", base+"/identity/connect/token",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(form.Encode()))
}

// kyClaims are KyIdentity's claims for a member of org.
func kyClaims(sub, email, org string) map[string]any {
	return map[string]any{"sub": sub, "email": email, "email_verified": true, "org_id": org,
		"preferred_username": strings.Split(email, "@")[0]}
}

func with(c map[string]any, key string, v any) map[string]any {
	out := map[string]any{key: v}
	for k, x := range c {
		if k != key {
			out[k] = x
		}
	}
	return out
}
