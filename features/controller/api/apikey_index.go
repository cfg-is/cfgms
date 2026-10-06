// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"errors"
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

// apiKeyIndexRefreshTimeout bounds one index scan. The scan runs detached from any
// request (see refreshAPIKeyIndex), so this — not a caller — decides when it gives up.
const apiKeyIndexRefreshTimeout = 30 * time.Second

// refreshAPIKeyIndex rebuilds the index from one listing of every API-key record and
// waits for the result. Concurrent callers share a single in-flight scan rather than
// starting scans of their own.
//
// The scan runs on its own detached context with apiKeyIndexRefreshTimeout, never on
// a caller's: a client that aborts the request which happened to start the scan must
// not cancel it for everyone waiting on it. A caller whose own ctx ends stops waiting
// (and gets ctx.Err()) while the scan carries on. A scan that ends in a context error
// does not count as an attempt for apiKeyIndexMissRefreshFloor, so it cannot hold
// off the next refresh.
func (s *Server) refreshAPIKeyIndex(ctx context.Context) error {
	_, err := s.refreshAPIKeyIndexIf(ctx, false)
	return err
}

// refreshAPIKeyIndexIf is refreshAPIKeyIndex for the miss path when onlyIfDue is set:
// it joins a scan already in flight, starts one only if none started within
// apiKeyIndexMissRefreshFloor, and otherwise returns ran == false without touching
// the store. The decision is taken under the index lock, so a burst of misses can
// never start a second scan inside the floor.
func (s *Server) refreshAPIKeyIndexIf(ctx context.Context, onlyIfDue bool) (bool, error) {
	ix := s.apiKeyIdx
	ix.mu.Lock()
	done := ix.inflight
	if done == nil && onlyIfDue && !ix.lastAttemptAt.IsZero() &&
		s.apiKeyNow().Sub(ix.lastAttemptAt) < apiKeyIndexMissRefreshFloor {
		ix.mu.Unlock()
		return false, nil
	}
	if done == nil {
		done = make(chan struct{})
		ix.inflight = done
		ix.pendingPuts = make(map[string]apiKeyIndexEntry)
		ix.pendingRemoves = make(map[string]struct{})
		prevAttempt := ix.lastAttemptAt
		ix.lastAttemptAt = s.apiKeyNow()
		s.apiKeyIndexWG.Add(1)
		// #nosec G118 -- the shared scan is deliberately detached from the
		// leader request: a client that aborts its request must not cancel the
		// scan every waiter depends on (Issue #4574). It runs under its own
		// timeout and Close() waits for it via apiKeyIndexWG.
		go s.runAPIKeyIndexScan(done, prevAttempt)
	}
	ix.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		return true, ctx.Err()
	}
	ix.mu.Lock()
	err := ix.inflightErr
	ix.mu.Unlock()
	return true, err
}

// runAPIKeyIndexScan performs the shared scan started by refreshAPIKeyIndex.
func (s *Server) runAPIKeyIndexScan(done chan struct{}, prevAttempt time.Time) {
	defer s.apiKeyIndexWG.Done()
	ix := s.apiKeyIdx

	scanCtx, cancel := context.WithTimeout(context.Background(), apiKeyIndexRefreshTimeout)
	defer cancel()
	records, err := s.secretStore.ListSecrets(scanCtx, &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
		},
	})

	ix.mu.Lock()
	defer ix.mu.Unlock()
	switch {
	case err == nil:
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
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		ix.lastAttemptAt = prevAttempt
	}
	ix.inflightErr = err
	ix.inflight = nil
	ix.pendingPuts, ix.pendingRemoves = nil, nil
	close(done)
}

// refreshing reports whether an index scan is in flight.
func (ix *apiKeyIndex) refreshing() bool {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.inflight != nil
}

// locateAPIKey returns the index entry for keyHash. On a miss it refreshes the index
// — at most once per apiKeyIndexMissRefreshFloor across all callers — and looks again.
func (s *Server) locateAPIKey(ctx context.Context, keyHash string) (apiKeyIndexEntry, bool, error) {
	if e, ok := s.apiKeyIdx.get(keyHash); ok {
		return e, true, nil
	}
	ran, err := s.refreshAPIKeyIndexIf(ctx, true)
	if err != nil {
		return apiKeyIndexEntry{}, false, err
	}
	if !ran {
		return apiKeyIndexEntry{}, false, nil
	}
	e, ok := s.apiKeyIdx.get(keyHash)
	return e, ok, nil
}

// locateAPIKeyByID is locateAPIKey keyed by the key's public ID.
func (s *Server) locateAPIKeyByID(ctx context.Context, keyID string) (string, apiKeyIndexEntry, bool, error) {
	if h, e, ok := s.apiKeyIdx.findByID(keyID); ok {
		return h, e, true, nil
	}
	ran, err := s.refreshAPIKeyIndexIf(ctx, true)
	if err != nil {
		return "", apiKeyIndexEntry{}, false, err
	}
	if !ran {
		return "", apiKeyIndexEntry{}, false, nil
	}
	h, e, ok := s.apiKeyIdx.findByID(keyID)
	return h, e, ok, nil
}

// apiKeyTombstoneTTL is how long a key deleted on this node stays tombstoned. It must
// be at least apiKeyRevalidateInterval: a load that read the record just before the
// delete completes long before then, and after it any cached copy would be dropped by
// re-validation anyway.
const apiKeyTombstoneTTL = 2 * apiKeyRevalidateInterval

// tombstoneAPIKeyLocked records that the key with this hash was deleted at now and
// prunes tombstones older than apiKeyTombstoneTTL. The caller holds s.mu.
func (s *Server) tombstoneAPIKeyLocked(keyHash string, now time.Time) {
	if s.apiKeyTombstones == nil {
		s.apiKeyTombstones = make(map[string]time.Time)
	}
	for h, at := range s.apiKeyTombstones {
		if now.Sub(at) >= apiKeyTombstoneTTL {
			delete(s.apiKeyTombstones, h)
		}
	}
	s.apiKeyTombstones[keyHash] = now
}

// cacheAPIKeyUnlessDeleted caches key under apiKey unless the key was deleted on this
// node within apiKeyTombstoneTTL, and reports whether it cached it. It closes the
// race where a load reads the record, a same-node delete then evicts the cache, and
// the load would otherwise insert the deleted key for a full revalidation interval.
func (s *Server) cacheAPIKeyUnlessDeleted(apiKey, keyHash string, key *APIKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if at, dead := s.apiKeyTombstones[keyHash]; dead && s.apiKeyNow().Sub(at) < apiKeyTombstoneTTL {
		return false
	}
	s.apiKeys[apiKey] = key
	return true
}
