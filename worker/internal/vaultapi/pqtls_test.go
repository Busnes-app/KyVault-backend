package vaultapi

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/pqtls"
)

// Run in separate processes with default settings and GODEBUG=fips140=on.
// Keep both peers' key exchange defaults: forcing hybrid would hide regressions.
func TestPQTLSDefaultNegotiatesHybrid(t *testing.T) {
	t.Logf("fips140 enabled: %v", fips140.Enabled())
	serverState := make(chan tls.ConnectionState, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverState <- *r.TLS
		_, _ = w.Write([]byte(`{"status":"ok","multi_tenant":true,"cells":[]}`))
	}))
	defer srv.Close()

	httpClient := srv.Client()
	httpClient.Timeout = 10 * time.Second
	c, err := New(srv.URL, secret, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	clientState := make(chan tls.ConnectionState, 1)
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil {
				clientState <- state
			}
		},
	})
	if _, err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	for _, state := range []tls.ConnectionState{<-clientState, <-serverState} {
		pqtls.RequireHybrid(t, state)
		if state.Version != tls.VersionTLS13 {
			t.Fatalf("TLS version = %#x, want TLS 1.3", state.Version)
		}
		t.Logf("negotiated %v with TLS 1.3", state.CurveID)
	}
}
