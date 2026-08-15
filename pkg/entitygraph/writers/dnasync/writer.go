// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package dnasync implements the DNA-sync → entity-graph internal writer
// (ADR-022 §9, ADR-023 §2). It translates fragment deltas received from
// stewards into entity-graph observations, scoped per peer authority.
//
// Authority-boundary rule (SE threat #1 — authority confusion): for host-scoped
// entities the eid authority segment is built entirely from the mTLS-verified
// peerHostAuthority argument — no field the steward supplies in fragment data
// (fragment_id, authority, payload) can reach it, so authority confusion there is
// structurally unrepresentable rather than detected-and-rejected.
//
// Cluster-scoped entities are the exception, because a cluster is shared by several
// reporting peers and so cannot be named after any one of them. The trust basis
// differs per branch and is stated in full on ResolveSubjectEID (resolve.go): the
// cluster-scoped VM branch accepts a payload-supplied cluster name only when a
// caller-supplied ClusterMembership verifier confirms the peer belongs to that
// cluster (fail closed — a nil verifier denies every claim), while the bare
// cluster-kind branch takes its name from the fragment_id ungated, because those
// fragments are the evidence cluster membership is itself derived from.
//
// EID construction is handled by ResolveSubjectEID (resolve.go), which covers
// three branches: cluster-scoped VMs (vm kind with a verified ha_role.cluster_name),
// bare cluster-kind fragments, and host-scoped fragments.
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
	provider   interfaces.EntityGraphProvider
	membership ClusterMembership
}

// Option configures a Writer at construction time.
type Option func(*Writer)

// WithClusterMembership supplies the controller-side verifier that decides whether
// a steward-asserted ha_role.cluster_name may become an eid authority segment for
// that peer (see ClusterMembership in resolve.go).
//
// A Writer built without it — or with a nil verifier — denies every cluster-scoped
// VM claim and records those fragments under host:<peerHostAuthority> instead. That
// is the fail-closed default on purpose: cluster-scoped observations carry no
// ClaimScope and can never be retracted, so an unverified claim must not be able to
// create one.
func WithClusterMembership(m ClusterMembership) Option {
	return func(w *Writer) { w.membership = m }
}

// New returns a Writer backed by provider. provider must not be nil.
func New(provider interfaces.EntityGraphProvider, opts ...Option) (*Writer, error) {
	if provider == nil {
		return nil, fmt.Errorf("dnasync/writer: provider must not be nil")
	}
	w := &Writer{provider: provider}
	for _, opt := range opts {
		if opt != nil {
			opt(w)
		}
	}
	return w, nil
}

// WriteFragmentDelta ingests a set of fragment deltas from a single peer into
// the entity graph as ObservationKindState observations.
//
// EID construction is delegated to ResolveSubjectEID (resolve.go), which handles
// three branches:
//   - Cluster-scoped VM (vm kind whose payload ha_role.cluster_name is confirmed for
//     this peer by the Writer's ClusterMembership verifier):
//     eid = cluster:<clusterName>/vm:<vmName>, no ClaimScope. An unverified claim
//     resolves host-scoped instead.
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
	var hostClaimScope *types.ClaimScope   // non-nil when any host-scoped observation is produced
	var edgeClaimScopes []types.ClaimScope // per-(source,edgeType) scopes from edge declarations

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
		// This is the sole authority for eid construction (authority-boundary rule),
		// and w.membership is the only channel by which steward-supplied payload data
		// can influence an authority segment.
		eid, src, cs, err := ResolveSubjectEID(kind, peerHostAuthority, fragID, payload, taxonomy, w.membership)
		if err != nil {
			return fmt.Errorf("dnasync/writer: %w", err)
		}

		// Decode edge declarations. This strips __entitygraph_edges from payload
		// so the key is absent when the entity observation below is stored.
		eObs, eCS := decodeEdgeDeclarations(peerHostAuthority, eid, observedAt, now, payload, taxonomy, w.membership)
		allObs = append(allObs, eObs...)
		edgeClaimScopes = append(edgeClaimScopes, eCS...)

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
	for i := range edgeClaimScopes {
		edgeClaimScopes[i].AsOf = now
		batch.ClaimScopes = append(batch.ClaimScopes, edgeClaimScopes[i])
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
