package state

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func stores(t *testing.T) map[string]Store {
	t.Helper()
	out := map[string]Store{"memory": NewMemory()}
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		return out
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)
	var wg sync.WaitGroup
	for range 4 { // idempotent, concurrent schema creation
		wg.Go(func() {
			if _, err := OpenPostgres(ctx, pool); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if _, err := pool.Exec(ctx, "TRUNCATE worker_sync_cursors, worker_known_orgs, worker_processed_events"); err != nil {
		t.Fatal(err)
	}
	pg, _ := OpenPostgres(ctx, pool)
	out["postgres"] = pg
	return out
}

func TestKnownOrgCellIsImmutable(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if _, ok, err := s.KnownOrgCell(ctx, "org-1"); err != nil || ok {
				t.Fatalf("fresh org: ok=%v err=%v", ok, err)
			}
			if err := s.RememberOrgCell(ctx, "org-1", "eu-west-1"); err != nil {
				t.Fatal(err)
			}
			// C4: subsequent writes for the same org must not overwrite home_region.
			if err := s.RememberOrgCell(ctx, "org-1", "us-east-1"); err != nil {
				t.Fatal(err)
			}
			cell, ok, err := s.KnownOrgCell(ctx, "org-1")
			if err != nil || !ok || cell != "eu-west-1" {
				t.Fatalf("known cell = %q, %v, %v; want eu-west-1", cell, ok, err)
			}
		})
	}
}

func TestCursorIsMonotonic(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if v, _ := s.Cursor(ctx, "orgs"); v != 0 {
				t.Fatalf("fresh cursor = %d", v)
			}
			_ = s.SaveCursor(ctx, "orgs", 42)
			_ = s.SaveCursor(ctx, "orgs", 7)
			if v, _ := s.Cursor(ctx, "orgs"); v != 42 {
				t.Fatalf("cursor moved backwards to %d", v)
			}
		})
	}
}

func TestClaimLifecycle(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1_800_000_000, 0)
			lease, exp := now.Add(time.Minute), now.Add(time.Hour)

			mustClaim := func(key, tok string, at time.Time, want Claim) {
				t.Helper()
				got, err := s.Claim(ctx, key, "test", tok, at, at.Add(time.Minute), exp)
				if err != nil || got != want {
					t.Fatalf("Claim(%s,%s) = %v, %v; want %v", key, tok, got, err, want)
				}
			}

			// Release after a failure makes the retry claimable at once.
			mustClaim("e1", "a", now, Claimed)
			mustClaim("e1", "b", now, InFlight)
			_ = s.Release(ctx, "e1", "wrong-token")
			mustClaim("e1", "b", now, InFlight)
			_ = s.Release(ctx, "e1", "a")
			mustClaim("e1", "b", now, Claimed)

			// Completed is a duplicate forever after (until pruned).
			_ = s.Complete(ctx, "e1", exp)
			mustClaim("e1", "c", now.Add(10*time.Minute), Completed)
			_ = s.Release(ctx, "e1", "b")
			mustClaim("e1", "c", now, Completed)

			// A crashed holder's lease expires and the key is claimable again.
			mustClaim("e2", "a", now, Claimed)
			mustClaim("e2", "b", lease.Add(time.Second), Claimed)

			// Prune keeps live keys and drops expired completed ones.
			if n, _ := s.Prune(ctx, now); n != 0 {
				t.Fatalf("pruned %d live keys", n)
			}
			if n, _ := s.Prune(ctx, exp.Add(time.Hour)); n != 2 {
				t.Fatalf("pruned %d, want 2", n)
			}
			mustClaim("e1", "d", now, Claimed)
		})
	}
}

func TestConcurrentClaimHasOneWinner(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			var wg sync.WaitGroup
			var mu sync.Mutex
			got := map[Claim]int{}
			for range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c, err := s.Claim(context.Background(), "race", "test", NewToken(), now, now.Add(time.Minute), now.Add(time.Hour))
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					got[c]++
					mu.Unlock()
				}()
			}
			wg.Wait()
			if got[Claimed] != 1 || got[InFlight] != 15 {
				t.Fatalf("claims = %v, want one winner", got)
			}
		})
	}
}
