// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// FragmentDeltaStore persists the controller's view of each steward's fragment
// manifest and applies fragment deltas received over the data plane.
//
// The real entitygraph-backed implementation is wired in story S7. Tests use
// InMemoryFragmentDeltaStore (defined in fragment_delta_store_test.go).
type FragmentDeltaStore interface {
	// CurrentManifest returns the stored (fragment_id, fragment_hash) manifest
	// for a steward, or nil if no manifest has been recorded yet.
	CurrentManifest(stewardID string) ([]*commonpb.ManifestEntry, error)

	// ApplyDelta merges the received fragments into the stored manifest.
	// Existing entries for the received fragment IDs are replaced; entries
	// for fragment IDs not in the delta are kept unchanged.
	//
	// CONTRACT (security-critical): implementations MUST derive each stored
	// fragment_hash from dna.FragmentHash(fragment.CanonicalBytes) and MUST NOT
	// copy the steward-asserted Fragment.FragmentHash field. The asserted field
	// is attacker-controlled; copying it lets a compromised steward store the
	// leaf hash of old content alongside mutated canonical bytes, pinning the
	// aggregate root so no re-sync is ever triggered. The transport layer
	// (verifyFragmentLeaves) rejects deltas where the two disagree, so a
	// conforming implementation observes identical values — deriving keeps the
	// invariant enforced at the storage boundary as well.
	ApplyDelta(stewardID string, fragments []*commonpb.Fragment) error
}
