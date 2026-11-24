package pubsub

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Envelope matches src/tenancy/pubsub.rs PgNotifyEnvelope on the Rust replicas.
type Envelope struct {
	Origin     string `json:"origin"`
	Kind       string `json:"kind"`
	UserID     string `json:"user_id,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	PayloadB64 string `json:"payload_b64,omitempty"`
}

// Publisher emits PostgreSQL NOTIFY fanout messages (Slice F) consumed by all Rust replicas.
type Publisher struct {
	pool    *pgxpool.Pool
	channel string
	origin  string
}

func NewPublisher(pool *pgxpool.Pool, channel, origin string) *Publisher {
	if origin == "" {
		origin = "kyvault-worker"
	}
	return &Publisher{
		pool:    pool,
		channel: channel,
		origin:  origin,
	}
}

// NotifyUserLogout instructs all Rust replicas to immediately disconnect live
// WebSockets for the given user UUID.
func (p *Publisher) NotifyUserLogout(ctx context.Context, userID string) error {
	return p.publish(ctx, Envelope{
		Origin: p.origin,
		Kind:   "user_logout",
		UserID: userID,
	})
}

// NotifyTenantKick instructs all Rust replicas to immediately disconnect live
// WebSockets for every user belonging to the given tenant ID.
func (p *Publisher) NotifyTenantKick(ctx context.Context, tenantID string) error {
	return p.publish(ctx, Envelope{
		Origin:   p.origin,
		Kind:     "tenant_kick",
		TenantID: tenantID,
	})
}

func (p *Publisher) publish(ctx context.Context, env Envelope) error {
	if p == nil || p.pool == nil {
		return nil
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal notify envelope: %w", err)
	}
	if _, err := p.pool.Exec(ctx, "SELECT pg_notify($1, $2)", p.channel, string(payload)); err != nil {
		return fmt.Errorf("pg_notify(%s): %w", p.channel, err)
	}
	return nil
}
