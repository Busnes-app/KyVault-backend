package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/oidcverify"
	"github.com/Busnes-app/ky-primitives/scim"
	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyvault-worker/internal/pubsub"
	"github.com/Busnes-app/kyvault-worker/internal/store"
	"github.com/Busnes-app/kyvault-worker/internal/syncer"
	"github.com/jackc/pgx/v5"
)

const maxWebhookBodyBytes = 1 << 20 // 1 MiB

// LogoutVerifier matches oidcverify.Verifier.VerifyLogout so tests can inject a mock or real JWKS verifier.
type LogoutVerifier interface {
	VerifyLogout(ctx context.Context, rawToken string) (oidcverify.LogoutClaims, error)
}

// Server serves /healthz, /api/sync/events (syncauth), and /api/oidc/backchannel-logout (oidcverify).
type Server struct {
	HomeRegion        string
	SyncWebhookSecret []byte
	LogoutVerifier    LogoutVerifier
	Store             *store.Store
	Publisher         *pubsub.Publisher
	Syncer            *syncer.Syncer
	Logger            *slog.Logger
	Now               func() time.Time
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Handler returns the HTTP mux with all worker routes mounted.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /api/sync/events", s.handleSyncEvent)
	mux.HandleFunc("POST /api/oidc/backchannel-logout", s.handleBackchannelLogout)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "unhealthy",
			"error":  "database unreachable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"home_region": s.HomeRegion,
	})
}

type tenantEventPayload struct {
	OrgID      string `json:"org_id"`
	TenantID   string `json:"tenant_id"`
	Status     string `json:"status"`
	AppEnabled *bool  `json:"app_enabled"`
}

func (s *Server) handleSyncEvent(w http.ResponseWriter, r *http.Request) {
	if len(s.SyncWebhookSecret) == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sync webhook not configured"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBodyBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed reading request body"})
		return
	}
	if len(body) > maxWebhookBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload too large"})
		return
	}

	ev, err := syncauth.Verify(s.SyncWebhookSecret, syncauth.FromRequest(r), body, syncauth.Options{
		Now: s.now,
	})
	if err != nil {
		s.log().Warn("rejected sync webhook signature", "err", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
		return
	}

	// Atomically deduplicate event_id in PostgreSQL before applying any mutation.
	dedupKey := "sync:" + ev.ID
	expiresAt := s.now().Add(7 * 24 * time.Hour).Unix()
	claimed, err := s.Store.ClaimEvent(r.Context(), dedupKey, ev.Type, expiresAt)
	if err != nil {
		s.log().Error("failed claiming sync event id", "event_id", ev.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	if !claimed {
		// Idempotent replay acknowledgement.
		writeJSON(w, http.StatusOK, map[string]any{"status": "duplicate", "event_id": ev.ID})
		return
	}

	if err := s.dispatchSyncEvent(r.Context(), ev.Type, body); err != nil {
		s.log().Error("failed processing sync event", "event_type", ev.Type, "event_id", ev.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "event processing failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "event_id": ev.ID, "event_type": ev.Type})
}

func (s *Server) dispatchSyncEvent(ctx context.Context, eventType string, body []byte) error {
	switch eventType {
	case "user.created", "user.updated", "user.deleted", "user.erased":
		var u scim.User
		if err := json.Unmarshal(body, &u); err != nil {
			return err
		}
		subject := strings.TrimSpace(u.ExternalID)
		if subject == "" {
			subject = strings.TrimSpace(u.ID)
		}
		email := primaryEmail(u)

		if eventType == "user.erased" {
			return s.Syncer.EraseUserBySubject(ctx, subject, email)
		}

		// Refuse to reactivate a permanently erased user tombstone.
		if subject != "" {
			erased, err := s.Store.IsEventProcessed(ctx, "erased_user:"+subject)
			if err != nil {
				return err
			}
			if erased {
				return nil
			}
		}

		uid, _, err := s.Store.FindUserUUIDBySubject(ctx, subject, email)
		if errors.Is(err, pgx.ErrNoRows) {
			// User hasn't logged into KyVault yet (JIT provisioned on verified OIDC login).
			return nil
		}
		if err != nil {
			return err
		}

		if eventType == "user.deleted" || !u.Active {
			if err := s.Store.RevokeUserSessions(ctx, uid, true); err != nil {
				return err
			}
			if err := s.Publisher.NotifyUserLogout(ctx, uid); err != nil {
				s.log().Warn("notify user_logout failed after SCIM deactivation", "user_id", uid, "err", err)
			}
			return nil
		}

		return s.Store.UpdateUserProfile(ctx, uid, u.DisplayName, u.Active)

	case "tenant.suspended", "tenant.disabled", "tenant.active", "tenant.export_only", "tenant.erasing", "tenant.deleted":
		var payload tenantEventPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			return err
		}
		tenantID := strings.TrimSpace(payload.OrgID)
		if tenantID == "" {
			tenantID = strings.TrimSpace(payload.TenantID)
		}
		if tenantID == "" {
			return errors.New("tenant event missing org_id")
		}
		if eventType == "tenant.erasing" || eventType == "tenant.deleted" {
			return s.Syncer.EraseTenant(ctx, tenantID)
		}
		status := payload.Status
		if status == "" {
			status = strings.TrimPrefix(eventType, "tenant.")
		}
		fenced, err := s.Store.MarkTenantStatus(ctx, tenantID, status, payload.AppEnabled)
		if err != nil {
			return err
		}
		if fenced {
			if err := s.Publisher.NotifyTenantKick(ctx, tenantID); err != nil {
				s.log().Warn("notify tenant_kick failed after webhook", "tenant_id", tenantID, "err", err)
			}
		}
		return nil

	default:
		// Acknowledge unknown future event types cleanly without failing delivery.
		s.log().Info("ignoring unsupported sync event type", "event_type", eventType)
		return nil
	}
}

// handleBackchannelLogout implements RFC 8959 OIDC Back-Channel Logout verified with ky-primitives/oidcverify.
func (s *Server) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.LogoutVerifier == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "oidc logout verifier not configured"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form body"})
		return
	}
	logoutToken := strings.TrimSpace(r.PostFormValue("logout_token"))
	if logoutToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing logout_token"})
		return
	}

	claims, err := s.LogoutVerifier.VerifyLogout(r.Context(), logoutToken)
	if err != nil {
		s.log().Warn("rejected backchannel logout token", "err", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid logout_token"})
		return
	}

	// Durable JTI replay prevention across all replicas & restarts.
	replayKey := "bcl:" + claims.Issuer + ":" + claims.JWTID
	replayUntil := claims.ReplayUntil.Unix()
	if replayUntil <= 0 {
		replayUntil = s.now().Add(24 * time.Hour).Unix()
	}
	claimed, err := s.Store.ClaimEvent(r.Context(), replayKey, "oidc.backchannel_logout", replayUntil)
	if err != nil {
		s.log().Error("failed storing backchannel logout replay guard", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	if !claimed {
		s.log().Warn("rejected replayed backchannel logout token", "jti", claims.JWTID)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "replayed logout_token"})
		return
	}

	if claims.Subject != "" {
		uid, _, err := s.Store.FindUserUUIDBySubject(r.Context(), claims.Subject, "")
		if err == nil {
			if err := s.Store.RevokeUserSessions(r.Context(), uid, false); err != nil {
				s.log().Error("failed revoking sessions on backchannel logout", "user_id", uid, "err", err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed revoking session"})
				return
			}
			if err := s.Publisher.NotifyUserLogout(r.Context(), uid); err != nil {
				s.log().Warn("failed emitting user_logout PG NOTIFY", "user_id", uid, "err", err)
			}
			s.log().Info("revoked user sessions via OIDC backchannel logout", "user_id", uid, "sub", claims.Subject)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			s.log().Error("database error looking up logout subject", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func primaryEmail(u scim.User) string {
	for _, e := range u.Emails {
		if e.Primary && strings.TrimSpace(e.Value) != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	if len(u.Emails) > 0 && strings.TrimSpace(u.Emails[0].Value) != "" {
		return strings.TrimSpace(u.Emails[0].Value)
	}
	if strings.Contains(u.UserName, "@") {
		return strings.TrimSpace(u.UserName)
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
