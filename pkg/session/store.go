// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session

import (
	"context"
	"sync"
	"time"
)

// storeEntry is the internal record maintained by MemStore per token hash.
type storeEntry struct {
	session *Session
	revoked bool
}

// MemStore is an in-memory Store implementation keyed by token hash.
// It never holds raw token values. A background goroutine reaps sessions
// whose AbsoluteExpiresAt has passed; call Close() to drain it on shutdown.
type MemStore struct {
	mu      sync.RWMutex
	records map[string]*storeEntry // key = token hash
	byID    map[string][]string    // key = session ID → token hashes (current + maybe prev)
	cfg     Config
	clockFn func() time.Time
	stop    chan struct{}
	done    chan struct{}
}

// NewMemStore creates an in-memory Store and starts its background reaper.
// Callers must call Close() when the store is no longer needed.
func NewMemStore(cfg Config, clockFn func() time.Time) *MemStore {
	if clockFn == nil {
		clockFn = time.Now
	}
	s := &MemStore{
		records: make(map[string]*storeEntry),
		byID:    make(map[string][]string),
		cfg:     cfg,
		clockFn: clockFn,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go s.reap()
	return s
}

// Set stores or updates the Session under the given token hash.
// A session may appear under multiple hashes (current + prior-token grace entry);
// each call registers this hash in the session's index for cleanup via Delete.
func (s *MemStore) Set(_ context.Context, tokenHash string, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[tokenHash]; !exists {
		// Only append to byID when registering a new hash, not on updates.
		s.byID[session.ID] = append(s.byID[session.ID], tokenHash)
	}
	s.records[tokenHash] = &storeEntry{session: session}
	return nil
}

// Get returns the Session for the given token hash.
// Returns ErrSessionNotFound when the hash is not present or the entry is revoked.
func (s *MemStore) Get(_ context.Context, tokenHash string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.records[tokenHash]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if entry.revoked {
		return nil, ErrSessionRevoked
	}
	return entry.session, nil
}

// GetByID returns any live session record for the given session ID.
// Returns ErrSessionNotFound when no non-revoked entry exists for id.
func (s *MemStore) GetByID(_ context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hashes, ok := s.byID[id]
	if !ok || len(hashes) == 0 {
		return nil, ErrSessionNotFound
	}
	for _, h := range hashes {
		entry, ok := s.records[h]
		if ok && !entry.revoked && entry.session != nil {
			return entry.session, nil
		}
	}
	return nil, ErrSessionNotFound
}

// Delete removes all token-hash entries associated with the given session ID.
// Returns ErrSessionNotFound when no entries exist for id (mirrors SQLiteSessionTokenStore).
func (s *MemStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hashes, ok := s.byID[id]
	if !ok {
		return ErrSessionNotFound
	}
	for _, h := range hashes {
		delete(s.records, h)
	}
	delete(s.byID, id)
	return nil
}

// ListAll returns all unique sessions in the store, de-duplicating by session ID.
func (s *MemStore) ListAll(_ context.Context) ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{}, len(s.byID))
	result := make([]*Session, 0, len(s.byID))
	for _, entry := range s.records {
		if entry.session == nil {
			continue
		}
		if _, dup := seen[entry.session.ID]; dup {
			continue
		}
		seen[entry.session.ID] = struct{}{}
		result = append(result, entry.session)
	}
	return result, nil
}

// Close stops the background reaper goroutine and waits for it to exit.
func (s *MemStore) Close() {
	close(s.stop)
	<-s.done
}

// reap runs a periodic sweep to evict sessions past their AbsoluteExpiresAt.
func (s *MemStore) reap() {
	defer close(s.done)
	// Sweep at half the idle timeout so test-injected short TTLs are cleaned promptly.
	interval := s.cfg.IdleTimeout / 2
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

// Sweep immediately evicts all sessions past their AbsoluteExpiresAt.
// Exported for test synchronization; the background reaper calls this periodically.
func (s *MemStore) Sweep() { s.sweep() }

func (s *MemStore) sweep() {
	now := s.clockFn()
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, entry := range s.records {
		if entry.session == nil || !now.After(entry.session.AbsoluteExpiresAt) {
			continue
		}
		id := entry.session.ID
		delete(s.records, hash)
		// Prune this hash from the byID index without clearing the whole session
		// (another hash for the same session may still be valid).
		hashes := s.byID[id]
		filtered := hashes[:0]
		for _, h := range hashes {
			if h != hash {
				filtered = append(filtered, h)
			}
		}
		if len(filtered) == 0 {
			delete(s.byID, id)
		} else {
			s.byID[id] = filtered
		}
	}
}
