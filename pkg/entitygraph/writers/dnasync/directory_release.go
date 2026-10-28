// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// directoryReleaseSource attributes the retraction batch. Each retracted assertion
// itself carries the source that originally made it.
const directoryReleaseSource = "controller:directory-domain-release"

const (
	releasePageSize  = 200
	releaseBatchSize = 500
)

// RetractDirectoryDomain retracts every directory:<domain>/... entity owned by
// tenantID: each source's assertion is withdrawn, so the entities stop appearing in
// reads and a later owner of the same domain can write new ones (owner immutability
// only protects subjects that still have an owner). It returns how many entities it
// retracted. It is idempotent, and it never touches another tenant's entities or any
// subject outside the domain.
//
// The controller runs it when a domain's registry entry is released.
func RetractDirectoryDomain(ctx context.Context, p interfaces.EntityGraphProvider, tenantID, domain string) (int, error) {
	if p == nil || tenantID == "" {
		return 0, fmt.Errorf("dnasync/release: provider and tenant are required")
	}
	norm, ok := types.NormalizeDirectoryDomain(domain)
	if !ok {
		return 0, fmt.Errorf("dnasync/release: invalid domain")
	}
	prefix := "directory:" + norm + "/"

	// Collect every subject first: retracting while paging would shift the offsets.
	var subjects []string
	token := ""
	for {
		page, err := p.QueryEntities(ctx,
			interfaces.EntityFilter{TenantFilter: tenantID, SubjectPrefix: prefix},
			interfaces.PageToken{Token: token, PageSize: releasePageSize})
		if err != nil {
			return 0, fmt.Errorf("dnasync/release: list entities: %w", err)
		}
		for _, e := range page.Entities {
			subjects = append(subjects, e.Entity.EID.String())
		}
		if page.NextToken == "" {
			break
		}
		token = page.NextToken
	}

	now := time.Now().UTC()
	var batch []types.Observation
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := p.ReportObservations(ctx, interfaces.ObservationBatch{Source: directoryReleaseSource, Observations: batch})
		batch = batch[:0]
		if err != nil {
			return fmt.Errorf("dnasync/release: retract: %w", err)
		}
		return nil
	}
	for _, subject := range subjects {
		eid, err := types.ParseEID(subject)
		if err != nil {
			continue
		}
		view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: tenantID})
		if errors.Is(err, interfaces.ErrNotFound) || (err == nil && view == nil) {
			continue // already gone
		}
		if err != nil {
			return 0, fmt.Errorf("dnasync/release: read entity: %w", err)
		}
		for _, src := range view.Sources {
			batch = append(batch, types.Observation{
				Source: src.Source, ObservedAt: now, RecordedAt: now, Subject: subject,
				Kind: types.ObservationKindAbsence, Confidence: types.ConfidenceHigh,
				Payload: map[string]interface{}{},
			})
		}
		if len(batch) >= releaseBatchSize {
			if err := flush(); err != nil {
				return 0, err
			}
		}
	}
	if err := flush(); err != nil {
		return 0, err
	}
	return len(subjects), nil
}
