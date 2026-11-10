// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"fmt"
	"sort"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
)

// MapState adapts an already-materialised map[string]interface{} state snapshot to
// modules.ConfigState so it can be canonicalized by CanonicalizeFragment.
//
// It is a projection of state a module already produced via its own AsMap(), not a
// second independent reader of the underlying resource (ADR-017 §2a): the only
// method with real behaviour is AsMap. It therefore takes no part in a Get/Set
// convergence cycle, and the remaining ConfigState methods are inert.
type MapState map[string]interface{}

// AsMap returns the wrapped snapshot.
func (s MapState) AsMap() map[string]interface{} { return s }

// ToYAML is inert: MapState exists only to feed the canonical encoder.
func (s MapState) ToYAML() ([]byte, error) { return nil, nil }

// FromYAML is inert: MapState is read-only.
func (s MapState) FromYAML(_ []byte) error { return nil }

// Validate is inert: the snapshot was already validated by its producing module.
func (s MapState) Validate() error { return nil }

// GetManagedFields is inert: MapState declares no field ownership.
func (s MapState) GetManagedFields() []string { return nil }

var _ modules.ConfigState = MapState(nil)

// NewFragment canonicalizes state (S2) and hashes it (S3) into an ADR-017 Fragment.
//
// It is the single construction point for fragments assembled outside
// PartitionHostFacts — the steward's monitor bridge for cluster:* state and the
// controller-side fixtures that exercise the cluster registry parse path both use
// it, so canonical bytes and fragment hash can never drift apart.
func NewFragment(fragmentID, authority string, state modules.ConfigState) (*commonpb.Fragment, error) {
	canonical, err := CanonicalizeFragment(fragmentID, authority, state)
	if err != nil {
		return nil, fmt.Errorf("NewFragment %q: %w", fragmentID, err)
	}
	return &commonpb.Fragment{
		FragmentId:     fragmentID,
		Authority:      authority,
		CanonicalBytes: canonical,
		FragmentHash:   FragmentHash(canonical),
	}, nil
}

// FlattenFragments decodes every fragment's canonical bytes and merges their
// string key-value pairs into a single flat map — the projection of ADR-017
// fragment state onto the flat attribute shape that controller-side consumers
// (fleet inventory, role-policy selectors, DNA fingerprinting, attribute
// filters) still read.
//
// Keys whose value is not a non-empty string are omitted: the flat projection is
// a string map by contract, and an empty value is indistinguishable from an
// absent one to every consumer.
//
// Fragments with empty or malformed canonical bytes are skipped rather than
// failing the whole projection. Canonical bytes arrive from stewards, which per
// the threat model run on hosts that may be compromised, so one hostile fragment
// must not blank out the well-formed ones.
//
// Merge order is deterministic: fragments are visited in ascending fragment-ID
// order, so when two fragments declare the same key the highest fragment ID
// wins, every time. Determinism is load-bearing — the controller hashes this
// projection into the DNA fingerprint
// (features/controller/fleet/storage/storage.go), and a map-iteration-order
// merge would make that fingerprint flap between identical snapshots.
func FlattenFragments(frags []*commonpb.Fragment) map[string]string {
	ordered := make([]*commonpb.Fragment, 0, len(frags))
	for _, frag := range frags {
		if frag == nil || len(frag.GetCanonicalBytes()) == 0 {
			continue
		}
		ordered = append(ordered, frag)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].GetFragmentId() < ordered[j].GetFragmentId()
	})

	flat := make(map[string]string)
	for _, frag := range ordered {
		decoded, err := DecodeCanonicalFragment(frag.GetCanonicalBytes())
		if err != nil {
			continue
		}
		for k, v := range decoded {
			if s, ok := v.(string); ok && s != "" {
				flat[k] = s
			}
		}
	}
	return flat
}
