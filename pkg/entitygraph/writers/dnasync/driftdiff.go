// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// WriteDriftDiffs writes a batch of drift-diff records as ObservationKindDriftDiff
// observations into the entity graph (ADR-022 §6, Issue #3373).
//
// Each record's subject EID is resolved via ResolveSubjectEID (resolve.go) using
// the mTLS-verified peerHostAuthority, so eid authority construction follows the
// same trust boundary as WriteFragmentDelta. Drift-diff records do not carry
// fragment payload (e.g. ha_role), so the cluster-scoped VM branch of
// ResolveSubjectEID requires payload to fire; without it, clustered-VM drift-diffs
// resolve host-scoped (same as any other host-scoped entity).
//
// # Why only host:<peer> subjects are written
//
// A drift-diff is a per-host statement: "the resource this steward manages on THIS
// host differs from its desired state". Nothing else it can name is a statement it
// is entitled to make. ResolveSubjectEID has one branch that does not derive the
// authority segment from peerHostAuthority and is deliberately not membership-gated:
// bare cluster-kind (any kind whose taxonomy AuthorityClasses omits "host" —
// cluster, group, tenant, directory). That branch needs no payload, so a steward
// sending fragment_id "cluster:<name>" resolves to eid cluster:<name> regardless of
// which host it runs on. ResolveSubjectEID's contract states the mitigation:
// consumers must treat cluster:<name> as source-attributed evidence per reporting
// peer, never as authoritative.
//
// The drift projection is not such a consumer. eg_drift_projection is keyed by
// subject alone (providers/*/schema.go) and upserts last-writer-wins, so — unlike
// eg_entity_current, which is keyed (subject, source) and merges by precedence — a
// forged cluster subject REPLACES the row that the cluster's real members reported,
// including with all fields matching:true. ListDrifted resolves the tenant through
// eg_entity_index, so the forged row surfaces inside the victim tenant's view. That
// is the same "one drift record from a compromised steward would be enough to hide
// arbitrary change" outcome guarded against below for ClaimScope, arriving through
// the projection key instead.
//
// So this writer refuses to be that consumer: a record whose resolved EID is not
// host:<peerHostAuthority> is dropped, and every subject written is one the
// mTLS-verified peer identity built. This is the fail-closed direction, and it
// keeps the source dimension the projection lacks irrelevant here — the subject
// itself already carries the reporting peer.
//
// # Why this batch carries no ClaimScope
//
// ResolveSubjectEID returns a host-scoped ClaimScope ("host:<peer>" authority prefix)
// for every host-scoped subject, and WriteFragmentDelta attaches it. It may do so
// because a fragment delta is a COMPLETE statement: the peer has reported its whole
// current fragment set, so any prior subject missing from the batch is genuinely gone
// and the provider's retraction pass is correct to drop it.
//
// A drift-diff batch is the opposite: it is a PARTIAL statement covering only the
// resources that drifted this cycle. claimScopeKey (providers/sqlite/claimscope.go)
// is source+entityType+authorityPrefix, so a host-scoped drift-diff ClaimScope is
// byte-identical to the fragment writer's — attaching it would make processClaimScopes
// retract every entity of that host absent from this partial batch, blanking the
// controller's view of the host. One drift record from a compromised steward would be
// enough to hide arbitrary change, and on the delta path the retraction would land in
// the transaction immediately after the fragment write that had just populated it.
//
// So drift-diff observations are additive only. They are never the basis for
// retraction, and entity absence continues to be decided solely by the fragment set,
// which is the only complete statement the steward makes.
//
// Write failures are returned to the caller; the caller decides whether to treat
// them as fatal or log-and-continue (mirroring WriteFragmentDelta's caller policy).
func (w *Writer) WriteDriftDiffs(
	ctx context.Context,
	peerHostAuthority string,
	records []*commonpb.DriftDiffRecord,
	taxonomy *types.Taxonomy,
) error {
	if len(records) == 0 {
		return nil
	}

	now := time.Now().UTC()
	var allObs []types.Observation

	for _, rec := range records {
		if rec == nil {
			continue
		}
		fragID := rec.FragmentID
		if fragID == "" {
			continue
		}

		// Parse kind: the substring of fragment_id before the first ':'.
		kind := fragID
		if idx := strings.Index(fragID, ":"); idx >= 0 {
			kind = fragID[:idx]
		}

		// Resolve EID and source via the shared resolution function. The ClaimScope it
		// returns is deliberately discarded — see "Why this batch carries no ClaimScope"
		// above.
		//
		// Payload is nil: a drift-diff record carries the compared field set, not the
		// fragment payload, so the cluster-scoped VM branch (which reads
		// ha_role.cluster_name out of that payload) cannot fire and resolution falls
		// through to the host-scoped branch. That is the fail-closed direction — the
		// EID authority is then the mTLS-verified peer, never a steward-supplied name.
		eid, src, _, err := ResolveSubjectEID(kind, peerHostAuthority, fragID, nil, taxonomy, w.membership)
		if err != nil {
			return fmt.Errorf("dnasync/driftdiff: %w", err)
		}

		// Host-scope gate. Only a subject whose authority segment the mTLS-verified
		// peer identity built may enter the source-less, last-writer-wins drift
		// projection — see "Why only host:<peer> subjects are written" above. A
		// non-host-scoped resolution (bare cluster-kind: cluster/group/tenant/directory
		// fragment_ids) is dropped rather than erroring the batch, so one crafted or
		// buggy record cannot black-hole the honest drift records riding with it.
		if eid.AuthorityType() != "host" || eid.AuthorityName() != peerHostAuthority {
			continue
		}

		fieldsPayload := buildDriftFieldsPayload(rec.Fields)
		payload := map[string]interface{}{
			"config_revision": rec.ConfigRevision,
			"fields":          fieldsPayload,
		}

		detectedAt := rec.DetectedAt
		if detectedAt.IsZero() {
			detectedAt = now
		}

		allObs = append(allObs, types.Observation{
			Source:     src,
			ObservedAt: detectedAt.UTC(),
			RecordedAt: now,
			Subject:    eid.String(),
			Kind:       types.ObservationKindDriftDiff,
			Confidence: types.ConfidenceHigh,
			Payload:    payload,
		})
	}

	if len(allObs) == 0 {
		return nil
	}

	// No ClaimScopes: a drift-diff batch is a partial statement and must never drive
	// retraction. See the doc comment above.
	batch := interfaces.ObservationBatch{
		Source:       peerHostAuthority,
		Observations: allObs,
	}

	return w.provider.ReportObservations(ctx, batch)
}

// DecodeDriftDiffBytes decodes a slice of JSON-encoded DriftDiffRecord bytes
// into a slice of *commonpb.DriftDiffRecord. Malformed records are skipped with
// a logged warning rather than failing the entire batch.
func DecodeDriftDiffBytes(raw [][]byte) []*commonpb.DriftDiffRecord {
	if len(raw) == 0 {
		return nil
	}
	out := make([]*commonpb.DriftDiffRecord, 0, len(raw))
	for _, b := range raw {
		if len(b) == 0 {
			continue
		}
		var rec commonpb.DriftDiffRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			continue
		}
		out = append(out, &rec)
	}
	return out
}

// buildDriftFieldsPayload converts a []*DriftDiffField into the []interface{} of
// maps that the provider's updateDriftProjectionFromObservation expects.
func buildDriftFieldsPayload(fields []*commonpb.DriftDiffField) []interface{} {
	out := make([]interface{}, 0, len(fields))
	for _, f := range fields {
		if f == nil {
			continue
		}
		out = append(out, map[string]interface{}{
			"attribute": f.Attribute,
			"desired":   f.Desired,
			"actual":    f.Actual,
			"matching":  f.Matching,
		})
	}
	return out
}
