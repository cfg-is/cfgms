// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dnasync

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// RetractFragments retracts the named fragments a peer previously reported, by
// writing one ObservationKindAbsence observation per id. It is the bulk lane's
// counterpart to WriteFragmentsPartial: the same EID resolution
// (ResolveSubjectEID, with the Writer's ClusterMembership), the same
// Observation.Source and the same AuthenticatedPeer binding, so an absence lands
// on exactly the (subject, source) pair the state observation did.
//
// Only the peer's own assertions are withdrawn. The entity projection is keyed by
// (subject, source), so another source's observation of the same EID survives and
// the entity stays visible from it. An id the peer never reported produces an
// absence for a pair that holds no assertion, which the provider treats as a
// no-op on the projection.
//
// No payload is available for a bare id, so a vm id always resolves host-scoped
// and a cluster-kind id resolves to the peer-only source (no module authority
// suffix); retraction cannot reach a cluster-scoped VM or a module-qualified
// cluster source, which carry no ClaimScope and are retracted only by their
// own producers.
func (w *Writer) RetractFragments(
	ctx context.Context,
	peerHostAuthority string,
	fragmentIDs []string,
	taxonomy *types.Taxonomy,
) error {
	if len(fragmentIDs) == 0 {
		return nil
	}

	now := time.Now().UTC()
	seen := make(map[string]struct{}, len(fragmentIDs))
	obs := make([]types.Observation, 0, len(fragmentIDs))
	for _, fragID := range fragmentIDs {
		if _, dup := seen[fragID]; dup {
			continue
		}
		seen[fragID] = struct{}{}

		kind := fragID
		if idx := strings.Index(fragID, ":"); idx >= 0 {
			kind = fragID[:idx]
		}
		eid, src, _, err := ResolveSubjectEID(kind, peerHostAuthority, fragID, map[string]interface{}{}, taxonomy, w.membership)
		if err != nil {
			return fmt.Errorf("dnasync/retract: %w", err)
		}
		obs = append(obs, types.Observation{
			Source:     src,
			ObservedAt: now,
			RecordedAt: now,
			Subject:    eid.String(),
			Kind:       types.ObservationKindAbsence,
			Confidence: types.ConfidenceHigh,
		})
	}

	return w.provider.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:            peerHostAuthority,
		Observations:      obs,
		AuthenticatedPeer: peerHostAuthority,
	})
}
