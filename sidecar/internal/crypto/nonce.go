// nonce.go — per-request nonce store.
// Maintains a map of seen nonces with TTL eviction to prevent replay attacks.
// A background goroutine sweeps expired entries on each TTL interval.
package crypto

import (
	"sync"
	"time"
)

const defaultNonceTTL = 5 * time.Minute

// NonceStore tracks seen nonces and evicts them after TTL expires.
// It is safe for concurrent use.
type NonceStore struct {
	mu     sync.Mutex
	m      map[string]time.Time
	ttl    time.Duration
	stopCh chan struct{}
}

// NewNonceStore creates a NonceStore with the given TTL and starts
// the background eviction goroutine. Call Stop() on shutdown.
//
// Non-positive TTLs fall back to the default window instead of panicking in
// time.NewTicker. This keeps misconfiguration fail-safe without changing the
// constructor shape used across Phase 1/2.
func NewNonceStore(ttl time.Duration) *NonceStore {
	if ttl <= 0 {
		ttl = defaultNonceTTL
	}

	ns := &NonceStore{
		m:      make(map[string]time.Time),
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}
	go ns.evict()
	return ns
}

// Seen returns false and records the nonce if it has not been seen before
// (or has already expired). Returns true if the nonce is still active —
// indicating a replay attempt. The check and record are atomic.
func (ns *NonceStore) Seen(nonce []byte) bool {
	key := string(nonce)
	now := time.Now()

	ns.mu.Lock()
	defer ns.mu.Unlock()

	if exp, ok := ns.m[key]; ok && now.Before(exp) {
		return true // replay
	}
	ns.m[key] = now.Add(ns.ttl)
	return false
}

// Stop halts the background eviction goroutine. Safe to call multiple times.
func (ns *NonceStore) Stop() {
	select {
	case <-ns.stopCh:
		// already stopped
	default:
		close(ns.stopCh)
	}
}

// evict runs in the background, removing expired entries every ttl interval.
func (ns *NonceStore) evict() {
	ticker := time.NewTicker(ns.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-ns.stopCh:
			return
		case now := <-ticker.C:
			ns.mu.Lock()
			for k, exp := range ns.m {
				if now.After(exp) {
					delete(ns.m, k)
				}
			}
			ns.mu.Unlock()
		}
	}
}
