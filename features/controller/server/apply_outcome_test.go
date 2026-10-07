// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for apply-outcome entity-graph ingestion (Issue #3375, ADR-022 §6).
//
// The round-trip test covers the full path:
//
//	steward ApplyConfiguration result → Event.Details encoding → JSON round-trip
//	(simulating the proto wire) → controller ingestApplyOutcomes → entity-graph
//	read-back via GetHistory and GetTimeline.
package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestEGProvider opens a fresh SQLite entity-graph provider backed by a temp file.
func newApplyOutcomeTestEGProvider(t *testing.T) *egsqlite.SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := egsqlite.NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// simulateDetailsRoundTrip mirrors the proto wire encoding of Event.Details:
// each value is JSON-marshaled (interfaceMapToStringMap) then JSON-unmarshaled
// back (stringMapToInterfaceMap). This is the same transformation the gRPC
// control-plane provider applies on send/receive.
func simulateDetailsRoundTrip(t *testing.T, in map[string]interface{}) map[string]interface{} {
	t.Helper()
	// Marshal each value to a JSON string (send side).
	wire := make(map[string]string, len(in))
	for k, v := range in {
		switch s := v.(type) {
		case string:
			wire[k] = s
		default:
			b, err := json.Marshal(v)
			require.NoError(t, err, "marshal %q", k)
			wire[k] = string(b)
		}
	}
	// Unmarshal each string back to interface{} (receive side), matching the exact
	// logic in stringMapToInterfaceMap: plain strings are kept as strings; non-string
	// JSON values (arrays, objects, numbers, bools) are deserialized.
	out := make(map[string]interface{}, len(wire))
	for k, v := range wire {
		var parsed interface{}
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			if _, isString := parsed.(string); !isString {
				out[k] = parsed
				continue
			}
		}
		out[k] = v
	}
	return out
}

// newMinimalServer returns a Server configured with only the egProvider field set —
// sufficient for testing ingestApplyOutcomes without starting a full TCP stack.
func newMinimalServer(t *testing.T, p *egsqlite.SQLiteEntityGraphProvider) *Server {
	t.Helper()
	return &Server{
		egProvider: p,
		logger:     logging.ForModule("apply-outcome-test"),
	}
}

// TestIngestApplyOutcomes_RoundTrip is the required round-trip test:
// steward ApplyConfiguration result → Event.Details → JSON round-trip (proto simulation)
// → controller ingestApplyOutcomes → readable via GetHistory with status + error detail.
func TestIngestApplyOutcomes_RoundTrip(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	s := newMinimalServer(t, p)
	ctx := context.Background()

	const peerID = "steward-roundtrip"
	const configVersion = "v-rt-1"

	// Build ApplyOutcomes as the executor would (Issue #3375 §"Files In Scope").
	now := time.Now().UTC()
	outcomes := []controlplaneTypes.ApplyOutcomeRecord{
		{
			ResourceID: "file:/etc/hosts",
			ModuleName: "file",
			Status:     "applied",
			Error:      "",
			Timestamp:  now,
		},
		{
			ResourceID: "service:sshd",
			ModuleName: "service",
			Status:     "failed",
			Error:      "service unit not found",
			Timestamp:  now,
		},
	}

	// Encode apply_outcomes into Event.Details the same way client_transport.go does,
	// then simulate the proto wire round-trip (JSON serialization of non-string values).
	rawDetails := map[string]interface{}{
		"config_version": configVersion,
		"status":         "ERROR",
		"message":        "Configuration applied with errors",
		"apply_outcomes": outcomes,
	}
	details := simulateDetailsRoundTrip(t, rawDetails)

	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, configVersion, details))

	// Both resources must be readable from the entity graph.
	for _, rec := range []struct {
		resourceID string
		wantStatus string
		wantError  string
	}{
		{"file:/etc/hosts", "applied", ""},
		{"service:sshd", "failed", "service unit not found"},
	} {
		eid, err := egtypes.ParseEID("host:" + peerID + "/" + rec.resourceID)
		require.NoError(t, err)

		history, err := p.GetHistory(ctx, eid, eginterfaces.TimeRange{
			From: now.Add(-time.Minute),
			To:   now.Add(time.Minute),
		})
		require.NoError(t, err)
		require.NotEmpty(t, history,
			"entity graph must have at least one observation for %s", rec.resourceID)

		// Find the apply-outcome observation.
		var found bool
		for _, hr := range history {
			if hr.Observation.Kind != egtypes.ObservationKindApplyOutcome {
				continue
			}
			found = true
			gotStatus, _ := hr.Observation.Payload["status"].(string)
			assert.Equal(t, rec.wantStatus, gotStatus,
				"status must match for %s", rec.resourceID)
			if rec.wantError != "" {
				gotErr, _ := hr.Observation.Payload["error"].(string)
				assert.Equal(t, rec.wantError, gotErr,
					"error detail must be readable for %s", rec.resourceID)
			}
		}
		assert.True(t, found,
			"ObservationKindApplyOutcome must be present in history for %s", rec.resourceID)
	}
}

// TestGetTimeline_SurfacesApplyOutcomeEvent verifies that GetTimeline surfaces
// an "apply-outcome" event for a subject that has an ObservationKindApplyOutcome
// observation, confirming the provider-side event-kind branch (Issue #3375 AC).
func TestGetTimeline_SurfacesApplyOutcomeEvent(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	s := newMinimalServer(t, p)
	ctx := context.Background()

	const peerID = "steward-timeline"
	const resourceID = "vm:myvm"

	now := time.Now().UTC()
	details := simulateDetailsRoundTrip(t, map[string]interface{}{
		"config_version": "v-tl-1",
		"apply_outcomes": []controlplaneTypes.ApplyOutcomeRecord{
			{
				ResourceID: resourceID,
				ModuleName: "hyperv",
				Status:     "applied",
				Timestamp:  now,
			},
		},
	})

	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, "v-tl-1", details))

	eid, err := egtypes.ParseEID("host:" + peerID + "/" + resourceID)
	require.NoError(t, err)

	events, err := p.GetTimeline(ctx, []eginterfaces.EIDRef{eid}, eginterfaces.TimeRange{
		From: now.Add(-time.Minute),
		To:   now.Add(time.Minute),
	})
	require.NoError(t, err)

	var applyOutcomeEvents []*eginterfaces.TimelineEvent
	for _, ev := range events {
		if ev.Kind == "apply-outcome" {
			applyOutcomeEvents = append(applyOutcomeEvents, ev)
		}
	}
	require.NotEmpty(t, applyOutcomeEvents,
		"GetTimeline must surface at least one 'apply-outcome' event for an affected eid")

	ev := applyOutcomeEvents[0]
	assert.Equal(t, eid, ev.Subject)
	obsKind, _ := ev.Detail["observation_kind"].(string)
	assert.Equal(t, "apply-outcome", obsKind,
		"observation_kind in event detail must be 'apply-outcome'")
}

// TestIngestApplyOutcomes_PreservesEntityState verifies that ingesting an apply
// outcome for an entity the same steward already reports state for leaves that
// entity's kind, attributes, and owning tenant intact. The steward is the source
// for both records and the subject is identical, so an apply-outcome that folded
// into the entity-state projection would blank owning_tenant — the sole
// access-control axis — and make the entity vanish from its own tenant.
func TestIngestApplyOutcomes_PreservesEntityState(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	s := newMinimalServer(t, p)
	ctx := context.Background()

	const peerID = "steward-tenant"
	const resourceID = "vm:myvm"
	const tenant = "root/msp-a/client-1"
	now := time.Now().UTC()

	eid, err := egtypes.ParseEID("host:" + peerID + "/" + resourceID)
	require.NoError(t, err)

	// The steward's DNA sync reports the entity's state under its own identity.
	require.NoError(t, p.ReportObservations(ctx, eginterfaces.ObservationBatch{
		Source: peerID,
		Observations: []egtypes.Observation{{
			Source:     peerID,
			ObservedAt: now,
			RecordedAt: now,
			Subject:    eid.String(),
			Kind:       egtypes.ObservationKindState,
			Confidence: egtypes.ConfidenceHigh,
			Payload: map[string]interface{}{
				"entity_kind":   "vm",
				"hostname":      "myvm",
				"owning_tenant": tenant,
			},
		}},
	}))

	details := simulateDetailsRoundTrip(t, map[string]interface{}{
		"config_version": "v1",
		"apply_outcomes": []controlplaneTypes.ApplyOutcomeRecord{{
			ResourceID: resourceID,
			ModuleName: "hyperv",
			Status:     "failed",
			Error:      "apply failed",
			Timestamp:  now.Add(time.Second),
		}},
	})
	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, "v1", details))

	view, err := p.GetEntity(ctx, eid, eginterfaces.GetEntityOpts{TenantFilter: tenant})
	require.NoError(t, err, "entity must remain visible to its own tenant after apply-outcome ingest")
	assert.Equal(t, "vm", view.Entity.Kind)
	assert.Equal(t, tenant, view.Entity.OwningTenant)
	assert.Equal(t, "myvm", view.Entity.Attributes["hostname"])
	for _, key := range []string{"status", "error", "module_name", "config_version"} {
		_, present := view.Entity.Attributes[key]
		assert.False(t, present,
			"apply-outcome payload key %q must not contaminate entity attributes", key)
	}
}

// TestIngestApplyOutcomes_EmptyOutcomesIsNoop verifies that an empty or absent
// apply_outcomes list is a no-op — no observations written, no error returned.
func TestIngestApplyOutcomes_EmptyOutcomesIsNoop(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	s := newMinimalServer(t, p)
	ctx := context.Background()

	require.NoError(t, s.ingestApplyOutcomes(ctx, "steward-noop", "v1", map[string]interface{}{}))
	require.NoError(t, s.ingestApplyOutcomes(ctx, "steward-noop", "v1", map[string]interface{}{
		"apply_outcomes": []interface{}{},
	}))
}

// TestIngestApplyOutcomes_MissingResourceIDSkipped verifies that records with an
// empty resource_id are silently skipped — no error, honest records still written.
func TestIngestApplyOutcomes_MissingResourceIDSkipped(t *testing.T) {
	p := newApplyOutcomeTestEGProvider(t)
	s := newMinimalServer(t, p)
	ctx := context.Background()

	const peerID = "steward-skip-empty"
	now := time.Now().UTC()

	details := simulateDetailsRoundTrip(t, map[string]interface{}{
		"apply_outcomes": []controlplaneTypes.ApplyOutcomeRecord{
			{ResourceID: "", ModuleName: "file", Status: "applied", Timestamp: now},
			{ResourceID: "service:nginx", ModuleName: "service", Status: "applied", Timestamp: now},
		},
	})

	require.NoError(t, s.ingestApplyOutcomes(ctx, peerID, "v1", details))

	// The record with empty resource_id must be skipped; the honest one must land.
	eid, err := egtypes.ParseEID("host:" + peerID + "/service:nginx")
	require.NoError(t, err)
	history, err := p.GetHistory(ctx, eid, eginterfaces.TimeRange{
		From: now.Add(-time.Minute),
		To:   now.Add(time.Minute),
	})
	require.NoError(t, err)
	require.NotEmpty(t, history, "honest record must be written even when batch contains an empty resource_id")
}
