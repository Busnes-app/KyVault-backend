// Package state holds the worker's own delivery and poll state: monotonic KyIdentity
// cursors and inbound event claims. It never touches native vault tables; the Rust
// server is their sole writer.
package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Claim is the outcome of claiming an inbound event key.
type Claim int

const (
	// Claimed: the caller holds a lease and must Complete or Release the key.
	Claimed Claim = iota
	// InFlight: another delivery holds a live lease; ask the sender to retry later.
	InFlight
	// Completed: the event was already applied; acknowledge it as a duplicate.
	Completed
)

// Store is the worker's state. A claim is only 'completed' after its mutation
// succeeded, so a transient failure never turns a sender's retry into a duplicate.
type Store interface {
	// Cursor returns the saved revision for name, 0 when none.
	Cursor(ctx context.Context, name string) (int64, error)
	// SaveCursor raises name's revision to rev; it never moves backwards.
	SaveCursor(ctx context.Context, name string, rev int64) error

	// Claim takes a lease on key until leaseUntil. A pending key whose lease expired
	// is claimable again. expiresAt bounds how long the key is retained.
	Claim(ctx context.Context, key, kind, token string, now, leaseUntil, expiresAt time.Time) (Claim, error)
	// Complete marks key applied and retains it until expiresAt.
	Complete(ctx context.Context, key string, expiresAt time.Time) error
	// Release drops a pending claim held under token, so a retry can claim it at once.
	Release(ctx context.Context, key, token string) error
	// Prune deletes completed keys past expiry and abandoned pending ones.
	Prune(ctx context.Context, now time.Time) (int64, error)

	Ping(ctx context.Context) error
}

// NewToken returns a random lease token.
func NewToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
