// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"sync"
	"time"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// apiKeyIndexMissRefreshFloor is the minimum interval between store scans triggered
// by API-key cache misses (Issue #4574). A hash absent from an index that was
// (re)built — or attempted — more recently than this is rejected without touching the
// store, so a flood of unknown keys costs at most one scan per floor interval however
// many requests arrive. It is also the longest a key created on another controller
// node waits before it authenticates here.
const apiKeyIndexMissRefreshFloor = 5 * time.Second

// apiKeyIndexEntry locates one API key's durable record.
type apiKeyIndexEntry struct {
	TenantID string
	ID       string
}

// apiKeyIndex maps an API key's SHA-256 (its secret-store record name) to the tenant
// holding the record (Issue #4574). It exists so that resolving a key of unknown
// tenant never requires a store-wide scan per request: the index is built with one
// scan at startup, refreshed by one background refresher every
// apiKeyRevalidateInterval, updated in place on create and delete, and refreshed on a
// miss at most once per apiKeyIndexMissRefreshFloor.
//
// The index is a locator, never an authority: every positive answer is confirmed by a
// direct read of the record before a key is accepted, so a stale entry for a deleted
// key cannot authenticate anything. A stale miss only delays a newly created key.
type apiKeyIndex struct {
	mu            sync.Mutex
	byHash        map[string]apiKeyIndexEntry
	lastAttemptAt time.Time     // start of the most recent refresh, successful or not
	inflight      chan struct{} // non-nil while a refresh runs; closed when it ends
	inflightErr   error         // result of the refresh that closed inflight
	// Local puts and removes made while a refresh is in flight. The listing may
	// predate them, so they are re-applied over its result.
	pendingPuts    map[string]apiKeyIndexEntry
	pendingRemoves map[string]struct{}
}

func newAPIKeyIndex() *apiKeyIndex {
	return &apiKeyIndex{byHash: make(map[string]apiKeyIndexEntry)}
}

func (ix *apiKeyIndex) get(keyHash string) (apiKeyIndexEntry, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	e, ok := ix.byHash[keyHash]
	return e, ok
}

// findByID returns the record name and entry of the key with the given ID.
func (ix *apiKeyIndex) findByID(keyID string) (string, apiKeyIndexEntry, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	for h, e := range ix.byHash {
		if e.ID == keyID {
			return h, e, true
		}
	}
	return "", apiKeyIndexEntry{}, false
}

func (ix *apiKeyIndex) put(keyHash string, e apiKeyIndexEntry) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.byHash[keyHash] = e
	if ix.inflight != nil {
		ix.pendingPuts[keyHash] = e
		delete(ix.pendingRemoves, keyHash)
	}
}

func (ix *apiKeyIndex) remove(keyHash string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	delete(ix.byHash, keyHash)
	if ix.inflight != nil {
		ix.pendingRemoves[keyHash] = struct{}{}
		delete(ix.pendingPuts, keyHash)
	}
}

// attemptedWithin reports whether a refresh started less than d before now.
func (ix *apiKeyIndex) attemptedWithin(now time.Time, d time.Duration) bool {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return !ix.lastAttemptAt.IsZero() && now.Sub(ix.lastAttemptAt) < d
}

// refreshAPIKeyIndex rebuilds the index from one listing of every API-key record.
// Concurrent callers share a single in-flight refresh (and its result) rather than
// starting scans of their own.
func (s *Server) refreshAPIKeyIndex(ctx context.Context) error {
	ix := s.apiKeyIdx
	ix.mu.Lock()
	if ix.inflight != nil {
		wait := ix.inflight
		ix.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
		ix.mu.Lock()
		err := ix.inflightErr
		ix.mu.Unlock()
		return err
	}
	done := make(chan struct{})
	ix.inflight = done
	ix.pendingPuts = make(map[string]apiKeyIndexEntry)
	ix.pendingRemoves = make(map[string]struct{})
	ix.lastAttemptAt = s.apiKeyNow()
	ix.mu.Unlock()

	records, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
		},
	})

	ix.mu.Lock()
	if err == nil {
		byHash := make(map[string]apiKeyIndexEntry, len(records))
		for _, rec := range records {
			byHash[rec.Key] = apiKeyIndexEntry{TenantID: rec.TenantID, ID: rec.Metadata["id"]}
		}
		for h, e := range ix.pendingPuts {
			byHash[h] = e
		}
		for h := range ix.pendingRemoves {
			delete(byHash, h)
		}
		ix.byHash = byHash
	}
	ix.inflightErr = err
	ix.inflight = nil
	ix.pendingPuts, ix.pendingRemoves = nil, nil
	close(done)
	ix.mu.Unlock()
	return err
}

// locateAPIKey returns the index entry for keyHash. On a miss it refreshes the index
// — at most once per apiKeyIndexMissRefreshFloor across all callers — and looks again.
func (s *Server) locateAPIKey(ctx context.Context, keyHash string) (apiKeyIndexEntry, bool, error) {
	if e, ok := s.apiKeyIdx.get(keyHash); ok {
		return e, true, nil
	}
	if s.apiKeyIdx.attemptedWithin(s.apiKeyNow(), apiKeyIndexMissRefreshFloor) {
		return apiKeyIndexEntry{}, false, nil
	}
	if err := s.refreshAPIKeyIndex(ctx); err != nil {
		return apiKeyIndexEntry{}, false, err
	}
	e, ok := s.apiKeyIdx.get(keyHash)
	return e, ok, nil
}

// locateAPIKeyByID is locateAPIKey keyed by the key's public ID.
func (s *Server) locateAPIKeyByID(ctx context.Context, keyID string) (string, apiKeyIndexEntry, bool, error) {
	if h, e, ok := s.apiKeyIdx.findByID(keyID); ok {
		return h, e, true, nil
	}
	if s.apiKeyIdx.attemptedWithin(s.apiKeyNow(), apiKeyIndexMissRefreshFloor) {
		return "", apiKeyIndexEntry{}, false, nil
	}
	if err := s.refreshAPIKeyIndex(ctx); err != nil {
		return "", apiKeyIndexEntry{}, false, err
	}
	h, e, ok := s.apiKeyIdx.findByID(keyID)
	return h, e, ok, nil
}
