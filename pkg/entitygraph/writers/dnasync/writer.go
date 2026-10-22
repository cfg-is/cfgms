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
//
// # Entry points
//
// The package has three write entry points, and the difference between them is what
// each one claims about completeness:
//
//   - WriteFragmentDelta (writer.go) ingests a steward's fragment set as
//     ObservationKindState. The caller asserts the set is COMPLETE, so the batch
//     carries a host-scoped ClaimScope (plus edge scopes) and any prior subject or
//     edge missing from it is retracted.
//   - WriteFragmentsPartial (writer.go) ingests the same observations for a SUBSET
//     of the peer's fragments, such as a partial delta sync. It carries NO
//     ClaimScope and is additive only, so unchanged fragments are not retracted.
//   - WriteDriftDiffs (driftdiff.go) ingests managed-resource drift-diff records as
//     ObservationKindDriftDiff (ADR-022 §6). A drift-diff batch is a PARTIAL statement
//     covering only the resources that drifted this cycle, so it carries NO ClaimScope
//     and is additive only. Entity absence remains decided solely by the fragment set.
package dnasync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// maxEdgesPerBatch bounds the edge declarations one WriteFragmentDelta call
// accepts across all its fragments. maxEdgesPerFragment bounds one fragment, but
// a steward can send many fragments in a call. 4096 is 16 maximal fragments; a
// fleet-realistic call (one cluster fragment plus a few dozen VM fragments with a
// handful of edges each) is a small fraction of it. Fragments are taken in order;
// the first one that would take the total over the limit and every one after it
// lose their declarations.
const maxEdgesPerBatch = 4096

// maxEdgesPerSubject bounds the edges one peer may keep stored from one subject
// across all its deltas. maxEdgesPerFragment and maxEdgesPerBatch bound a single
// delta only; a declaration of a type replaces that peer's earlier edges of the
// same type from the subject, so the stored total can grow only through new edge
// types, and edge types are producer-supplied. A fragment whose declarations
// would take the subject past this total loses them (its entity observation is
// still written), which freezes that subject's existing edges.
const maxEdgesPerSubject = 1024

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
//
// WriteFragmentDelta is the COMPLETE-set entry point: the caller asserts that
// fragments is every fragment the peer currently reports, so the batch carries a
// host-scoped ClaimScope (and per-(source, edge type) scopes for edge declarations)
// and anything previously written under those scopes but absent here is retracted.
// Callers that hold only a subset must use WriteFragmentsPartial.
func (w *Writer) WriteFragmentDelta(
	ctx context.Context,
	peerHostAuthority string,
	fragments []*commonpb.Fragment,
	envelopes map[string]*commonpb.FragmentEnvelope,
	taxonomy *types.Taxonomy,
) error {
	return w.writeFragments(ctx, peerHostAuthority, fragments, envelopes, taxonomy, true)
}

// WriteFragmentsPartial ingests a subset of a peer's fragments, such as the
// fragments a partial delta sync asked for while every other stored fragment is
// unchanged. It builds observations, EIDs, tenant binding and edge caps exactly as
// WriteFragmentDelta does, but the batch carries NO ClaimScope: it is additive only
// and makes no statement about fragments or edges absent from it, so nothing
// unchanged is retracted.
func (w *Writer) WriteFragmentsPartial(
	ctx context.Context,
	peerHostAuthority string,
	fragments []*commonpb.Fragment,
	envelopes map[string]*commonpb.FragmentEnvelope,
	taxonomy *types.Taxonomy,
) error {
	return w.writeFragments(ctx, peerHostAuthority, fragments, envelopes, taxonomy, false)
}

// writeFragments is the shared implementation. complete reports whether fragments
// is the peer's complete current set; only then are claim scopes attached.
func (w *Writer) writeFragments(
	ctx context.Context,
	peerHostAuthority string,
	fragments []*commonpb.Fragment,
	envelopes map[string]*commonpb.FragmentEnvelope,
	taxonomy *types.Taxonomy,
	complete bool,
) error {
	if len(fragments) == 0 {
		return nil
	}

	now := time.Now().UTC()

	var allObs []types.Observation
	var hostClaimScope *types.ClaimScope   // non-nil when any host-scoped observation is produced
	var edgeClaimScopes []types.ClaimScope // per-(source,edgeType) scopes from edge declarations
	batchEdges := 0                        // edge observations accepted so far
	droppedEdgeFragments := 0              // fragments whose declarations maxEdgesPerBatch dropped
	subjectCapFragments := 0               // fragments whose declarations maxEdgesPerSubject dropped
	lastSubjectCapFragID := ""
	lastDroppedFragID := ""

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

		// Validate osquery-authority host:* fragments before storage.
		// The signed module wrapper proves the code path is trusted, not that the
		// hardware/OS state it reports is sane (threat model: steward host may be
		// compromised). Validation is independent of module-wrapper trust.
		if frag.GetAuthority() == "osquery" {
			if err := validateOsqueryCanonicalBytes(fragID, frag.GetCanonicalBytes()); err != nil {
				return fmt.Errorf("dnasync/writer: ingest validation: %w", err)
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
		if batchEdges+len(eObs) > maxEdgesPerBatch {
			// The batch is over its edge budget: this fragment and every later one
			// lose their declarations (their entity observations are still written).
			batchEdges = maxEdgesPerBatch
			if len(eObs) > 0 {
				droppedEdgeFragments++
				lastDroppedFragID = fragID
			}
			eObs, eCS = nil, nil
		}
		if len(eObs) > 0 && !w.withinSubjectCap(ctx, peerHostAuthority, eid, eObs) {
			subjectCapFragments++
			lastSubjectCapFragID = fragID
			eObs, eCS = nil, nil
		}
		batchEdges += len(eObs)
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

	if droppedEdgeFragments > 0 {
		slog.Warn("dnasync: edge declarations dropped, batch edge limit reached",
			"peer", logging.SanitizeLogValue(peerHostAuthority),
			"dropped_fragments", droppedEdgeFragments,
			"last_dropped_fragment_id", logging.SanitizeLogValue(lastDroppedFragID),
			"limit", maxEdgesPerBatch,
		)
	}

	if subjectCapFragments > 0 {
		slog.Warn("dnasync: edge declarations dropped, per-subject edge limit reached",
			"peer", logging.SanitizeLogValue(peerHostAuthority),
			"dropped_fragments", subjectCapFragments,
			"last_dropped_fragment_id", logging.SanitizeLogValue(lastSubjectCapFragID),
			"limit", maxEdgesPerSubject,
		)
	}

	if len(allObs) == 0 {
		return nil
	}

	batch := interfaces.ObservationBatch{
		// Source is the reporting steward's own identity for the entire batch,
		// regardless of per-fragment Observation.Source values (ADR-022 §4).
		Source:       peerHostAuthority,
		Observations: allObs,
		// AuthenticatedPeer is the same mTLS-verified peerHostAuthority — never
		// a tenant the caller chooses. The provider resolves owning_tenant from
		// it independently and overwrites whatever a fragment's payload
		// claims, closing the tenant-spoofing gap a compromised steward would
		// otherwise have (Issue #4319).
		AuthenticatedPeer: peerHostAuthority,
	}

	// A complete write (WriteFragmentDelta) gives host-scoped fragments a
	// ClaimScope: "peerHostAuthority has reported its complete current fragment set
	// under host:<peerHostAuthority>". This lets #2874's retraction logic drop
	// fragments this steward no longer reports. A partial write
	// (WriteFragmentsPartial) claims nothing about completeness and attaches no
	// scope, host or edge, so unchanged fragments are never retracted.
	// Cluster-scoped fragments (bare cluster-kind and cluster-scoped VMs) deliberately
	// omit a ClaimScope: a single node's view is not the complete picture for a
	// shared multi-observer entity.
	if complete {
		if hostClaimScope != nil {
			hostClaimScope.AsOf = now
			batch.ClaimScopes = []types.ClaimScope{*hostClaimScope}
		}
		for i := range edgeClaimScopes {
			edgeClaimScopes[i].AsOf = now
			batch.ClaimScopes = append(batch.ClaimScopes, edgeClaimScopes[i])
		}
	}

	return w.provider.ReportObservations(ctx, batch)
}

// withinSubjectCap reports whether declaring eObs keeps the edges peer holds from
// eid within maxEdgesPerSubject. Stored edges of the types being declared are
// not counted: this declaration's claim scope retracts them. A failed read
// counts as over the cap, so the declarations are dropped rather than trusted.
func (w *Writer) withinSubjectCap(ctx context.Context, peer string, eid types.EID, eObs []types.Observation) bool {
	declared := make(map[string]struct{}, len(eObs))
	for _, o := range eObs {
		if idx := strings.Index(o.Subject, "|"); idx >= 0 {
			declared[o.Subject[:idx]] = struct{}{}
		}
	}
	total := len(eObs)
	filter := interfaces.EdgeFilter{FromEID: &eid, Source: peer, Limit: interfaces.MaxEdgePageSize}
	for total <= maxEdgesPerSubject {
		views, err := w.provider.GetEdges(ctx, filter)
		if err != nil {
			return false
		}
		for _, v := range views {
			if _, replaced := declared[v.Edge.Type]; !replaced {
				total++
			}
		}
		if len(views) < interfaces.MaxEdgePageSize {
			break
		}
		filter.After = views[len(views)-1].Cursor
	}
	return total <= maxEdgesPerSubject
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

	// A steward's fragment can decode a tenant_path/owning_tenant field just as
	// easily as any other attribute — strip it unconditionally, the same way
	// fragment_hash above is derived rather than copied. owning_tenant is the
	// entity graph's sole access-control axis, so it must never reach storage
	// as a value the reporting peer supplied: the provider derives it
	// independently from the mTLS-verified peer identity via
	// ObservationBatch.AuthenticatedPeer (Issue #4319), and overwrites this
	// deletion's absence regardless.
	delete(payload, "tenant_path")
	delete(payload, "owning_tenant")

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
