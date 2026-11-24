// Package server receives KyIdentity's pushes: signed suite webhooks (syncauth) and OIDC
// back-channel logout (oidcverify). Each is forwarded to the vault's management API and
// recorded as completed only after the vault applied it, so a failed attempt stays
// retryable and only a completed one is answered as a duplicate.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Busnes-app/ky-primitives/oidcverify"
	"github.com/Busnes-app/ky-primitives/scim"
	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyvault-worker/internal/state"
	"github.com/Busnes-app/kyvault-worker/internal/vaultapi"
)

const (
	maxWebhookBody = 1 << 20
	maxLogoutBody  = 64 << 10
	// claimLease outlasts one vault call (15 s timeout) with margin.
	claimLease = 2 * time.Minute
	// syncRetention keeps completed webhook IDs while KyIdentity may still retry them.
	syncRetention = 7 * 24 * time.Hour
)

type LogoutVerifier interface {
	VerifyLogout(ctx context.Context, rawToken string) (oidcverify.LogoutClaims, error)
}

type Server struct {
	// Issuer is the configured OIDC issuer; webhook subjects belong to it.
	Issuer            string
	SyncWebhookSecret []byte
	LogoutVerifier    LogoutVerifier
	State             state.Store
	Vault             *vaultapi.Client
	// TriggerCleanup is called when the vault queued object deletions.
	TriggerCleanup func()
	Logger         *slog.Logger
	Now            func() time.Time

	ready atomic.Bool
}

// SetReady opens the webhook route: call it once org and erased-subject state has been
// reconciled, so a restored vault never applies a webhook ahead of its erasure history.
func (s *Server) SetReady() { s.ready.Store(true) }

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("POST /api/sync/events", s.handleSyncEvent)
	mux.HandleFunc("POST /api/oidc/backchannel-logout", s.handleBackchannelLogout)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if err := s.State.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unhealthy", "error": "state database unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "reconciling"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// userEvent is the signed webhook body: a SCIM user with org_id inside the signature.
type userEvent struct {
	ID          string            `json:"id"`
	ExternalID  string            `json:"externalId"`
	UserName    string            `json:"userName"`
	DisplayName string            `json:"displayName"`
	Emails      []scim.MultiValue `json:"emails"`
	Active      *bool             `json:"active"`
	OrgID       string            `json:"org_id"`
}

func (s *Server) handleSyncEvent(w http.ResponseWriter, r *http.Request) {
	if !s.ready.Load() {
		w.Header().Set("Retry-After", "10")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "reconciling"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed reading body"})
		return
	}
	if len(body) > maxWebhookBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload too large"})
		return
	}
	ev, err := syncauth.Verify(s.SyncWebhookSecret, syncauth.FromRequest(r), body, syncauth.Options{Now: s.now})
	if err != nil {
		s.log().Warn("rejected sync webhook", "err", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
		return
	}

	var apply func(context.Context) error
	switch ev.Type {
	case "user.created", "user.updated", "user.deleted", "user.erased":
		apply, err = s.userMutation(ev.Type, body)
		if err != nil {
			s.log().Warn("rejected malformed sync webhook", "event_type", ev.Type, "event_id", ev.ID, "err", err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	default:
		// KyIdentity sends no org.* or tenant.* webhooks; org lifecycle is polled.
		s.log().Info("ignoring unsupported sync event type", "event_type", ev.Type)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored", "event_id": ev.ID})
		return
	}

	s.applyOnce(w, r, "sync:"+ev.ID, ev.Type, s.now().Add(syncRetention), apply, map[string]string{"event_id": ev.ID})
}

func (s *Server) userMutation(eventType string, body []byte) (func(context.Context) error, error) {
	var u userEvent
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, errors.New("invalid user body")
	}
	subject := strings.TrimSpace(u.ExternalID)
	if id := strings.TrimSpace(u.ID); subject == "" {
		subject = id
	} else if id != "" && id != subject {
		return nil, errors.New("id and externalId disagree")
	}
	if subject == "" {
		return nil, errors.New("user has no id")
	}
	var tenant *string
	if org := strings.TrimSpace(u.OrgID); org != "" {
		tenant = &org
	}

	if eventType == "user.erased" {
		return func(ctx context.Context) error {
			res, err := s.Vault.EraseUser(ctx, vaultapi.EraseRequest{Issuer: s.Issuer, Subject: subject, TenantID: tenant})
			if err == nil && res.PendingDeletionsQueued > 0 && s.TriggerCleanup != nil {
				s.TriggerCleanup()
			}
			return err
		}, nil
	}

	active := false
	switch {
	case eventType == "user.deleted":
	case u.Active == nil:
		return nil, errors.New("user has no active attribute")
	default:
		active = *u.Active
	}
	req := vaultapi.SyncRequest{
		EventType: eventType, Issuer: s.Issuer, Subject: subject, TenantID: tenant,
		Email: primaryEmail(u), DisplayName: strings.TrimSpace(u.DisplayName), Active: active,
	}
	return func(ctx context.Context) error {
		_, err := s.Vault.SyncUser(ctx, req)
		return err
	}, nil
}

// handleBackchannelLogout ends the subject's vault sessions for an RFC-conformant
// logout+jwt. The (issuer, jti) pair is the replay key.
func (s *Server) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoutBody)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	token := strings.TrimSpace(r.PostFormValue("logout_token"))
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	claims, err := s.LogoutVerifier.VerifyLogout(r.Context(), token)
	if err != nil {
		s.log().Warn("rejected back-channel logout token", "err", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if claims.Subject == "" {
		// The vault tracks no OIDC sessions, so a sid-only token names nobody it can end.
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "logout_token has no sub"})
		return
	}
	apply := func(ctx context.Context) error {
		_, err := s.Vault.Logout(ctx, vaultapi.LogoutRequest{Issuer: claims.Issuer, Subject: claims.Subject})
		return err
	}
	s.applyOnce(w, r, logoutKey(claims.Issuer, claims.JWTID), "oidc.backchannel_logout", claims.ReplayUntil, apply, nil)
}

// logoutKey is the (issuer, jti) replay key: fixed length and free of NUL, which a
// PostgreSQL TEXT column refuses.
func logoutKey(issuer, jti string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + jti))
	return "bcl:" + hex.EncodeToString(sum[:])
}

// applyOnce claims key, runs apply, records completion only on success, and answers:
// 200 "ok" when applied now, 200 "duplicate" when applied before, 409 while another
// delivery holds the claim, 502/503 when the attempt failed and stays retryable.
func (s *Server) applyOnce(w http.ResponseWriter, r *http.Request, key, kind string, retainUntil time.Time, apply func(context.Context) error, fields map[string]string) {
	answer := func(status string) {
		body := map[string]string{"status": status}
		for k, v := range fields {
			body[k] = v
		}
		writeJSON(w, http.StatusOK, body)
	}
	now := s.now()
	token := state.NewToken()
	claim, err := s.State.Claim(r.Context(), key, kind, token, now, now.Add(claimLease), retainUntil)
	switch {
	case err != nil:
		s.log().Error("claiming event failed", "kind", kind, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "state unavailable"})
		return
	case claim == state.Completed:
		answer("duplicate")
		return
	case claim == state.InFlight:
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusConflict, map[string]string{"error": "delivery in progress"})
		return
	}

	// State bookkeeping must finish even if the sender hangs up mid-call.
	bg := context.WithoutCancel(r.Context())
	if err := apply(r.Context()); err != nil {
		if rerr := s.State.Release(bg, key, token); rerr != nil {
			s.log().Error("releasing claim failed; retry waits for the lease", "kind", kind, "err", rerr)
		}
		var statusErr *vaultapi.StatusError
		if errors.As(err, &statusErr) && statusErr.Code == http.StatusForbidden {
			s.log().Warn("vault refused mutation for unserved cell (C5)", "kind", kind, "err", err)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		s.log().Error("vault mutation failed; left retryable", "kind", kind, "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "vault unavailable"})
		return
	}
	if err := s.State.Complete(bg, key, retainUntil); err != nil {
		// Applied but unrecorded: the sender's retry reapplies it, which the vault treats idempotently.
		s.log().Error("recording completed event failed", "kind", kind, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "state unavailable"})
		return
	}
	answer("ok")
}

// primaryEmail is the sign-in email: the primary entry, never the mailbox address.
func primaryEmail(u userEvent) string {
	for _, e := range u.Emails {
		if e.Primary && e.Type != "mailbox" {
			return strings.TrimSpace(e.Value)
		}
	}
	for _, e := range u.Emails {
		if e.Type != "mailbox" {
			return strings.TrimSpace(e.Value)
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
