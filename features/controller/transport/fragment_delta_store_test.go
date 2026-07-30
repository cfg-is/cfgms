// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"sort"
	"sync"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	stewarddna "github.com/cfgis/cfgms/features/steward/dna"
)

// InMemoryFragmentDeltaStore is a thread-safe test implementation of FragmentDeltaStore.
//
// It is NOT a mock: there is no expectation recording, no call verification, and
// no framework. SetManifest provides a test-seeding path for direct state setup.
type InMemoryFragmentDeltaStore struct {
	mu        sync.RWMutex
	manifests map[string][]*commonpb.ManifestEntry
}

// NewInMemoryFragmentDeltaStore returns an empty InMemoryFragmentDeltaStore.
func NewInMemoryFragmentDeltaStore() *InMemoryFragmentDeltaStore {
	return &InMemoryFragmentDeltaStore{
		manifests: make(map[string][]*commonpb.ManifestEntry),
	}
}

// SetManifest seeds the stored manifest for a steward.
func (s *InMemoryFragmentDeltaStore) SetManifest(stewardID string, manifest []*commonpb.ManifestEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manifests[stewardID] = manifest
}

// CurrentManifest implements FragmentDeltaStore.
func (s *InMemoryFragmentDeltaStore) CurrentManifest(stewardID string) ([]*commonpb.ManifestEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.manifests[stewardID], nil
}

// ApplyDelta implements FragmentDeltaStore. Per the interface contract, the
// stored fragment_hash is DERIVED from the fragment's canonical bytes — the
// steward-asserted Fragment.FragmentHash field is never copied.
func (s *InMemoryFragmentDeltaStore) ApplyDelta(stewardID string, fragments []*commonpb.Fragment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := make(map[string]*commonpb.ManifestEntry, len(s.manifests[stewardID]))
	for _, e := range s.manifests[stewardID] {
		existing[e.GetFragmentId()] = e
	}
	for _, f := range fragments {
		existing[f.GetFragmentId()] = &commonpb.ManifestEntry{
			FragmentId:   f.GetFragmentId(),
			FragmentHash: stewarddna.FragmentHash(f.GetCanonicalBytes()),
		}
	}

	manifest := make([]*commonpb.ManifestEntry, 0, len(existing))
	for _, entry := range existing {
		manifest = append(manifest, entry)
	}
	sort.Slice(manifest, func(i, j int) bool {
		return manifest[i].GetFragmentId() < manifest[j].GetFragmentId()
	})
	s.manifests[stewardID] = manifest
	return nil
}

var _ FragmentDeltaStore = (*InMemoryFragmentDeltaStore)(nil)
