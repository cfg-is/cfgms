// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package dnasync implements the DNA-sync → entity-graph internal writer
// (ADR-022 §9, ADR-023 §2). It translates fragment deltas received from
// stewards into entity-graph observations, scoped per peer authority.
//
// Authority-boundary invariant (SE threat #1 — authority confusion): the eid
// authority segment is built entirely from the mTLS-verified peerHostAuthority
// argument. No field the steward supplies in fragment data (fragment_id,
// authority, payload) can reach the eid authority segment — the attack is
// structurally unrepresentable, not detected-and-rejected.
//
// EID construction is handled by ResolveSubjectEID (resolve.go), which covers
// three branches: cluster-scoped VMs (vm kind with ha_role.cluster_name), bare
// cluster-kind fragments, and host-scoped fragments.
//
// Source attribution for host-scoped observations uses peerHostAuthority (not
// the module authority) so that ClaimScope.Source and Observation.Source remain
// equal, enabling the retraction machinery to fire correctly.
package dnasync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// Writer is the DNA-sync → entity-graph internal writer.
type Writer struct {
	provider interfaces.EntityGraphProvider
}

// New returns a Writer backed by provider. provider must not be nil.
func New(provider interfaces.EntityGraphProvider) (*Writer, error) {
	if provider == nil {
		return nil, fmt.Errorf("dnasync/writer: provider must not be nil")
	}
	return &Writer{provider: provider}, nil
}

// WriteFragmentDelta ingests a set of fragment deltas from a single peer into
// the entity graph as ObservationKindState observations.
//
// EID construction is delegated to ResolveSubjectEID (resolve.go), which handles
// three branches:
//   - Cluster-scoped VM (vm kind with ha_role.cluster_name in payload):
//     eid = cluster:<clusterName>/vm:<vmName>, no ClaimScope.
//   - Cluster-kind fragments (AuthorityClasses does NOT contain "host"):
//     eid = cluster:<clusterName> (bare, no local_id), no ClaimScope.
//   - Host-scoped fragments (AuthorityClasses contains "host", or unknown kind):
//     eid = host:<peerHostAuthority>/<fragment_id>, ClaimScope covering host:<peerHostAuthority>.
//
// Module identity is preserved in Payload["module_authority"] rather than in
// Observation.Source so that ClaimScope source matching works correctly.
//
// The envelopes map is keyed by fragment_id and carries per-fragment provenance
// metadata (confidence, observed_at). It may be nil when the caller has no
// envelope data (e.g., the partial-sync delta path).
func (w *Writer) WriteFragmentDelta(
	ctx context.Context,
	peerHostAuthority string,
	fragments []*commonpb.Fragment,
	envelopes map[string]*commonpb.FragmentEnvelope,
	taxonomy *types.Taxonomy,
) error {
	if len(fragments) == 0 {
		return nil
	}

	now := time.Now().UTC()

	var allObs []types.Observation
	var hostClaimScope *types.ClaimScope // non-nil when any host-scoped observation is produced

	for _, frag := range fragments {
		fragID := frag.GetFragmentId()

		// Parse kind: the substring of fragment_id before the first ':'.
		kind := fragID
		if idx := strings.Index(fragID, ":"); idx >= 0 {
			kind = fragID[:idx]
		}

		// Resolve confidence from envelope; default to high per PO ruling.
		confidence := types.ConfidenceHigh
		observedAt := now
		if envelopes != nil {
			if env, ok := envelopes[fragID]; ok && env != nil {
				if c := env.GetConfidence(); c != "" {
					confidence = resolveConfidence(c)
				}
				if ts := env.GetObservedAt(); ts != nil {
					if t := ts.AsTime(); !t.IsZero() {
						observedAt = t.UTC()
					}
				}
			}
		}

		// Build observation payload: decoded canonical fields merged with
		// fragment metadata. confidence is always persisted (PO ruling, AC A2).
		payload := buildPayload(frag, confidence)

		// Resolve EID, source, and ClaimScope via the shared resolution function.
		// This is the sole authority for eid construction (authority-boundary invariant).
		eid, src, cs, err := ResolveSubjectEID(kind, peerHostAuthority, fragID, payload, taxonomy)
		if err != nil {
			return fmt.Errorf("dnasync/writer: %w", err)
		}

		allObs = append(allObs, types.Observation{
			Source:     src,
			ObservedAt: observedAt,
			RecordedAt: now,
			Subject:    eid.String(),
			Kind:       types.ObservationKindState,
			Confidence: confidence,
			Payload:    payload,
		})

		// Track the ClaimScope template for host-scoped fragments.
		// All host-scoped observations from the same peer share one ClaimScope,
		// so we only need the first non-nil result.
		if cs != nil && hostClaimScope == nil {
			hostClaimScope = cs
		}
	}

	if len(allObs) == 0 {
		return nil
	}

	batch := interfaces.ObservationBatch{
		// Source is the reporting steward's own identity for the entire batch,
		// regardless of per-fragment Observation.Source values (ADR-022 §4).
		Source:       peerHostAuthority,
		Observations: allObs,
	}

	// Host-scoped fragments get a ClaimScope: "peerHostAuthority has reported
	// its complete current fragment set under host:<peerHostAuthority>". This
	// lets #2874's retraction logic drop fragments this steward no longer reports.
	// Cluster-scoped fragments (bare cluster-kind and cluster-scoped VMs) deliberately
	// omit a ClaimScope: a single node's view is not the complete picture for a
	// shared multi-observer entity.
	if hostClaimScope != nil {
		hostClaimScope.AsOf = now
		batch.ClaimScopes = []types.ClaimScope{*hostClaimScope}
	}

	return w.provider.ReportObservations(ctx, batch)
}

// buildPayload constructs the observation payload for a fragment.
// It includes the decoded canonical fields (best-effort), the fragment hash,
// the fragment_id, and the confidence (persisted per PO ruling).
func buildPayload(frag *commonpb.Fragment, confidence types.Confidence) map[string]interface{} {
	payload := make(map[string]interface{})

	// Decode canonical bytes into state fields. This is best-effort; if the
	// bytes are malformed or use an unknown encoding the payload still carries
	// the mandatory fragment metadata below.
	if cb := frag.GetCanonicalBytes(); len(cb) > 0 {
		if fields, err := decodeCanonicalFragment(cb); err == nil {
			for k, v := range fields {
				payload[k] = v
			}
		}
		// Derive fragment hash from canonical bytes (never copy the asserted value).
		sum := sha256.Sum256(cb)
		payload["fragment_hash"] = hex.EncodeToString(sum[:])
	}

	// Always set these — they are the non-negotiable provenance fields.
	payload["fragment_id"] = frag.GetFragmentId()
	payload["confidence"] = string(confidence)
	// Preserve module identity in the payload. This keeps module attribution
	// visible in entity attributes without coupling Observation.Source to the
	// module identity (which would break ClaimScope source matching — see the
	// comment in WriteFragmentDelta above the host-scoped observation).
	if auth := frag.GetAuthority(); auth != "" {
		payload["module_authority"] = auth
	}

	return payload
}

// resolveConfidence converts a string from FragmentEnvelope into a typed
// Confidence value, defaulting to high for unrecognised strings.
func resolveConfidence(s string) types.Confidence {
	switch types.Confidence(s) {
	case types.ConfidenceHigh, types.ConfidenceMedium, types.ConfidenceLow:
		return types.Confidence(s)
	default:
		return types.ConfidenceHigh
	}
}
