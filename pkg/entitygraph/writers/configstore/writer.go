// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package configstore implements the ConfigStore → desired-state entity-graph
// internal writer (ADR-022 §6). It is one of the three internal writers named
// in ADR-022 §9.
package configstore

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// ConfigRevision describes the desired state captured by a single config push.
// It is defined here (not imported from features/) to preserve the import
// direction rule: pkg/ must never import features/.
type ConfigRevision struct {
	// ConfigID is the configuration document identifier.
	ConfigID string
	// Revision is the version string that labels the desired-state observation.
	// The source written to the entity graph will be "config:<Revision>".
	Revision string
	// TenantID is the tenant this configuration targets.
	TenantID string
	// DesiredState carries the attribute payload recorded per entity. The key
	// "config_revision" is reserved; the writer injects it automatically.
	DesiredState map[string]interface{}
}

// Writer is the ConfigStore → desired-state entity-graph internal writer.
// It translates a config push event into ReportObservations calls, writing
// ObservationKindDesiredState observations sourced as "config:<revision>" for
// each addressed entity (ADR-022 §6).
type Writer struct {
	provider interfaces.EntityGraphProvider
}

// New returns a Writer backed by provider. provider must not be nil.
func New(provider interfaces.EntityGraphProvider) (*Writer, error) {
	if provider == nil {
		return nil, fmt.Errorf("configstore/writer: provider must not be nil")
	}
	return &Writer{provider: provider}, nil
}

// Ingest writes a desired-state observation for each EID in eids, sourced from
// "config:<rev.Revision>".
//
// Sparse population (AC3): EIDs not yet registered in the entity graph are
// written unconditionally. GetDesiredState queries the observation log directly,
// so the desired-state record is accessible even before the entity appears in
// the entity index.
//
// Idempotency (AC4): re-ingesting an identical revision for a known EID
// produces no new log row — the underlying provider's content-hash dedup
// mechanism silently skips bit-identical observations.
//
// If eids is empty the call is a no-op and returns nil.
func (w *Writer) Ingest(ctx context.Context, rev ConfigRevision, eids []types.EID) error {
	if len(eids) == 0 {
		return nil
	}

	now := time.Now().UTC()
	source := "config:" + rev.Revision

	// Build the shared payload. All targeted entities receive the same
	// desired-state record for this revision; config_revision is injected so
	// GetDesiredState can surface it via ConfigRevision on DesiredStateView.
	payload := make(map[string]interface{}, len(rev.DesiredState)+1)
	for k, v := range rev.DesiredState {
		payload[k] = v
	}
	payload["config_revision"] = rev.Revision

	observations := make([]types.Observation, len(eids))
	for i, eid := range eids {
		observations[i] = types.Observation{
			Source:     source,
			ObservedAt: now,
			RecordedAt: now,
			Subject:    eid.String(),
			Kind:       types.ObservationKindDesiredState,
			Confidence: types.ConfidenceHigh,
			Payload:    payload,
		}
	}

	return w.provider.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:       source,
		Observations: observations,
	})
}
