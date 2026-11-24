package state

import (
	"context"
	"sync"
	"time"
)

// Memory is an in-process Store for tests and single-process development.
type Memory struct {
	mu      sync.Mutex
	cursors map[string]int64
	events  map[string]memEvent
}

type memEvent struct {
	completed  bool
	token      string
	leaseUntil time.Time
	expiresAt  time.Time
}

func NewMemory() *Memory {
	return &Memory{cursors: map[string]int64{}, events: map[string]memEvent{}}
}

func (m *Memory) Cursor(_ context.Context, name string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursors[name], nil
}

func (m *Memory) SaveCursor(_ context.Context, name string, rev int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rev > m.cursors[name] {
		m.cursors[name] = rev
	}
	return nil
}

func (m *Memory) Claim(_ context.Context, key, _, token string, now, leaseUntil, expiresAt time.Time) (Claim, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.events[key]; ok {
		if e.completed {
			return Completed, nil
		}
		if e.leaseUntil.After(now) {
			return InFlight, nil
		}
		if e.expiresAt.After(expiresAt) {
			expiresAt = e.expiresAt
		}
	}
	m.events[key] = memEvent{token: token, leaseUntil: leaseUntil, expiresAt: expiresAt}
	return Claimed, nil
}

func (m *Memory) Complete(_ context.Context, key string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[key] = memEvent{completed: true, expiresAt: expiresAt}
	return nil
}

func (m *Memory) Release(_ context.Context, key, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.events[key]; ok && !e.completed && e.token == token {
		delete(m.events, key)
	}
	return nil
}

func (m *Memory) Prune(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for k, e := range m.events {
		if e.expiresAt.Before(now) && (e.completed || e.leaseUntil.Before(now)) {
			delete(m.events, k)
			n++
		}
	}
	return n, nil
}

func (m *Memory) Ping(context.Context) error { return nil }
