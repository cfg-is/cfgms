// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for WriteDriftDiffs and DecodeDriftDiffBytes (driftdiff.go, ADR-022 §6).
package dnasync_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	sqliteprovider "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
)

// TestWriteDriftDiffs_RoundTrip asserts that WriteDriftDiffs writes an
// ObservationKindDriftDiff observation readable via GetDriftState, with the
// correct config_revision and fields payload.
func TestWriteDriftDiffs_RoundTrip(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	taxonomy := types.DefaultTaxonomy()
	ctx := context.Background()

	peerID := "test-steward-drift-rt"
	rec := &commonpb.DriftDiffRecord{
		FragmentID:     "service:sshd",
		ConfigRevision: "v1.2.3",
		DetectedAt:     time.Now().UTC(),
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "enabled", Desired: true, Actual: false, Matching: false},
			{Attribute: "port", Desired: float64(22), Actual: float64(22), Matching: true},
		},
	}

	require.NoError(t, w.WriteDriftDiffs(ctx, peerID, []*commonpb.DriftDiffRecord{rec}, taxonomy))

	// The observation must be readable via GetDriftState.
	eid := mustParseEID(t, "host:"+peerID+"/service:sshd")
	state, err := p.GetDriftState(ctx, eid)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, "v1.2.3", state.ConfigRevision, "config_revision must match")
	assert.Equal(t, "detected", state.LifecycleStatus)
	assert.Len(t, state.Fields, 2)

	// Find the non-matching field.
	var enabledField *interfaces.DriftField
	for i := range state.Fields {
		if state.Fields[i].Attribute == "enabled" {
			f := state.Fields[i]
			enabledField = &f
		}
	}
	require.NotNil(t, enabledField, "enabled field must be present")
	assert.False(t, enabledField.Matching)
}

// TestWriteDriftDiffs_ConfigRevisionPersisted asserts that the desired config
// revision is persisted and readable (AC: writer_test.go WriteDriftDiffs case).
func TestWriteDriftDiffs_ConfigRevisionPersisted(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	taxonomy := types.DefaultTaxonomy()
	ctx := context.Background()

	const configRev = "cfg-rev-abc-123"
	peerID := "test-steward-cfg-rev"

	rec := &commonpb.DriftDiffRecord{
		FragmentID:     "file:etc-hosts",
		ConfigRevision: configRev,
		DetectedAt:     time.Now().UTC(),
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "content", Desired: "expected", Actual: "actual", Matching: false},
		},
	}

	require.NoError(t, w.WriteDriftDiffs(ctx, peerID, []*commonpb.DriftDiffRecord{rec}, taxonomy))

	eid := mustParseEID(t, "host:"+peerID+"/file:etc-hosts")
	state, err := p.GetDriftState(ctx, eid)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, configRev, state.ConfigRevision, "persisted config revision must match")
}

// TestWriteDriftDiffs_EmptyRecords verifies that an empty or nil record slice
// is a no-op.
func TestWriteDriftDiffs_EmptyRecords(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	taxonomy := types.DefaultTaxonomy()
	ctx := context.Background()

	require.NoError(t, w.WriteDriftDiffs(ctx, "steward-x", nil, taxonomy))
	require.NoError(t, w.WriteDriftDiffs(ctx, "steward-x", []*commonpb.DriftDiffRecord{}, taxonomy))
}

// TestWriteDriftDiffs_NilRecordSkipped verifies that nil entries in the records
// slice are silently skipped.
func TestWriteDriftDiffs_NilRecordSkipped(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	taxonomy := types.DefaultTaxonomy()
	ctx := context.Background()

	rec := &commonpb.DriftDiffRecord{
		FragmentID:     "service:nginx",
		ConfigRevision: "v1",
		DetectedAt:     time.Now().UTC(),
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "running", Desired: true, Actual: false, Matching: false},
		},
	}

	require.NoError(t, w.WriteDriftDiffs(ctx, "steward-nil", []*commonpb.DriftDiffRecord{nil, rec}, taxonomy))

	eid := mustParseEID(t, "host:steward-nil/service:nginx")
	state, err := p.GetDriftState(ctx, eid)
	require.NoError(t, err)
	require.NotNil(t, state)
}

// TestWriteDriftDiffs_MatchingFieldsIncluded asserts that matching fields are
// present in the persisted drift record alongside non-matching fields.
func TestWriteDriftDiffs_MatchingFieldsIncluded(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	taxonomy := types.DefaultTaxonomy()
	ctx := context.Background()

	peerID := "steward-matching"
	rec := &commonpb.DriftDiffRecord{
		FragmentID:     "service:httpd",
		ConfigRevision: "v2",
		DetectedAt:     time.Now().UTC(),
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "enabled", Desired: true, Actual: false, Matching: false},
			{Attribute: "port", Desired: float64(80), Actual: float64(80), Matching: true},
			{Attribute: "protocol", Desired: "tcp", Actual: "tcp", Matching: true},
		},
	}

	require.NoError(t, w.WriteDriftDiffs(ctx, peerID, []*commonpb.DriftDiffRecord{rec}, taxonomy))

	eid := mustParseEID(t, "host:"+peerID+"/service:httpd")
	state, err := p.GetDriftState(ctx, eid)
	require.NoError(t, err)
	require.Len(t, state.Fields, 3, "all three fields (including matching) must be present")

	matchCount := 0
	for _, f := range state.Fields {
		if f.Matching {
			matchCount++
		}
	}
	assert.Equal(t, 2, matchCount, "two matching fields must be recorded")
}

// TestDecodeDriftDiffBytes_RoundTrip verifies that JSON-encoded DriftDiffRecord
// bytes survive a round-trip through DecodeDriftDiffBytes.
func TestDecodeDriftDiffBytes_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	original := &commonpb.DriftDiffRecord{
		FragmentID:     "vm:test-vm",
		ConfigRevision: "v3",
		DetectedAt:     now,
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "cpu", Desired: float64(4), Actual: float64(2), Matching: false},
		},
	}
	b, err := json.Marshal(original)
	require.NoError(t, err)

	decoded := dnasync.DecodeDriftDiffBytes([][]byte{b})
	require.Len(t, decoded, 1)
	assert.Equal(t, "vm:test-vm", decoded[0].FragmentID)
	assert.Equal(t, "v3", decoded[0].ConfigRevision)
	require.Len(t, decoded[0].Fields, 1)
	assert.Equal(t, "cpu", decoded[0].Fields[0].Attribute)
	assert.False(t, decoded[0].Fields[0].Matching)
}

// TestDecodeDriftDiffBytes_MalformedSkipped verifies that malformed JSON entries
// are silently skipped and valid ones are still decoded.
func TestDecodeDriftDiffBytes_MalformedSkipped(t *testing.T) {
	valid := &commonpb.DriftDiffRecord{
		FragmentID:     "service:cron",
		ConfigRevision: "v1",
	}
	b, err := json.Marshal(valid)
	require.NoError(t, err)

	decoded := dnasync.DecodeDriftDiffBytes([][]byte{
		[]byte("not json"),
		b,
		[]byte("{broken"),
	})
	require.Len(t, decoded, 1, "only the valid record must be decoded")
	assert.Equal(t, "service:cron", decoded[0].FragmentID)
}

// TestDecodeDriftDiffBytes_Empty verifies that nil/empty input returns nil.
func TestDecodeDriftDiffBytes_Empty(t *testing.T) {
	assert.Nil(t, dnasync.DecodeDriftDiffBytes(nil))
	assert.Nil(t, dnasync.DecodeDriftDiffBytes([][]byte{}))
}

// TestWriteDriftDiffs_PartialBatchDoesNotRetractHostEntities is the security
// regression test for the drift-diff ClaimScope hazard.
//
// A fragment delta is a COMPLETE statement of a host's fragment set, so it carries a
// host-scoped ClaimScope and the provider retracts any prior subject missing from it.
// A drift-diff batch is a PARTIAL statement — only the resources that drifted this
// cycle — and claimScopeKey (source + entityType + authorityPrefix) is byte-identical
// between the two. If WriteDriftDiffs attached the ClaimScope that ResolveSubjectEID
// returns, one drift record naming one resource would retract every other entity of
// that host, blanking the controller's view and hiding malicious change.
//
// The assertion is on observable state, not on the batch shape: the fragment the
// drift-diff batch does NOT mention must still be readable afterwards.
func TestWriteDriftDiffs_PartialBatchDoesNotRetractHostEntities(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	taxonomy := types.DefaultTaxonomy()
	ctx := context.Background()

	const peerID = "steward-no-retract"

	// The steward reports its complete fragment set: two host-scoped entities.
	fragFile := makeHostFrag("file:/etc/hosts", "enforcing-module:file")
	fragSSHD := makeHostFrag("service:sshd", "enforcing-module:service")
	require.NoError(t, w.WriteFragmentDelta(ctx, peerID,
		[]*commonpb.Fragment{fragFile, fragSSHD}, nil, taxonomy))

	eidFile := mustParseEID(t, "host:"+peerID+"/file:/etc/hosts")
	eidSSHD := mustParseEID(t, "host:"+peerID+"/service:sshd")

	fileBefore, err := p.GetEntity(ctx, eidFile, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, fileBefore)

	// A drift-diff batch mentioning only ONE of the two resources.
	require.NoError(t, w.WriteDriftDiffs(ctx, peerID, []*commonpb.DriftDiffRecord{{
		FragmentID:     "service:sshd",
		ConfigRevision: "v1",
		DetectedAt:     time.Now().UTC(),
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "enabled", Desired: true, Actual: false, Matching: false},
		},
	}}, taxonomy))

	// The unmentioned entity must survive: a partial batch may never drive retraction.
	fileAfter, fileErr := p.GetEntity(ctx, eidFile, interfaces.GetEntityOpts{})
	require.NoError(t, fileErr,
		"file:/etc/hosts must not be retracted by a drift-diff batch that does not mention it")
	require.NotNil(t, fileAfter,
		"a partial drift-diff batch must never retract the host's other entities")

	// The mentioned entity is still intact too, and its drift state was recorded.
	sshdAfter, err := p.GetEntity(ctx, eidSSHD, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, sshdAfter)

	drift, err := p.GetDriftState(ctx, eidSSHD)
	require.NoError(t, err)
	require.NotNil(t, drift)
	assert.Equal(t, "v1", drift.ConfigRevision)
}

// TestWriteDriftDiffs_NonHostScopedSubjectsDropped is the security regression test
// for drift forgery via the projection key.
//
// eg_drift_projection is keyed by subject alone and upserts last-writer-wins, so a
// subject that is not derived from the mTLS-verified peer identity lets any steward
// REPLACE another host's — or another tenant's — drift row. ResolveSubjectEID's bare
// cluster-kind branch is deliberately not membership-gated and needs no payload, so
// every kind whose taxonomy AuthorityClasses omits "host" (cluster, group, tenant,
// directory) would resolve straight to that steward-supplied name.
//
// WriteDriftDiffs must therefore write only host:<peerHostAuthority> subjects.
func TestWriteDriftDiffs_NonHostScopedSubjectsDropped(t *testing.T) {
	p := newTestProvider(t)
	// Wire a real membership verifier that even affirms this peer's cluster
	// membership: a verified member still may not overwrite the shared cluster's
	// drift row, because the row carries no source dimension to attribute it to.
	w := newTestWriterWithMembership(t, p, map[string][]string{
		"victim-cluster": {"steward-attacker"},
	})
	taxonomy := types.DefaultTaxonomy()
	ctx := context.Background()

	const peerID = "steward-attacker"

	forged := []string{
		"cluster:victim-cluster",
		"group:domain-admins",
		"tenant:root-msp-a",
		"directory:corp-ad",
	}
	records := make([]*commonpb.DriftDiffRecord, 0, len(forged)+1)
	for _, fragID := range forged {
		records = append(records, &commonpb.DriftDiffRecord{
			FragmentID:     fragID,
			ConfigRevision: "forged-rev",
			DetectedAt:     time.Now().UTC(),
			Fields: []*commonpb.DriftDiffField{
				{Attribute: "everything", Desired: "ok", Actual: "ok", Matching: true},
			},
		})
	}
	// An honest host-scoped record rides in the same batch: dropping the forged
	// subjects must not discard the legitimate ones.
	records = append(records, &commonpb.DriftDiffRecord{
		FragmentID:     "service:sshd",
		ConfigRevision: "v9",
		DetectedAt:     time.Now().UTC(),
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "enabled", Desired: true, Actual: false, Matching: false},
		},
	})

	require.NoError(t, w.WriteDriftDiffs(ctx, peerID, records, taxonomy))

	for _, fragID := range forged {
		eid := mustParseEID(t, "cluster:"+strings.SplitN(fragID, ":", 2)[1])
		state, err := p.GetDriftState(ctx, eid)
		require.Error(t, err,
			"drift row for non-host-scoped subject %q must not exist", eid.String())
		assert.True(t, errors.Is(err, sqliteprovider.ErrNotFound),
			"expected ErrNotFound for %q, got %v", eid.String(), err)
		assert.Nil(t, state)
	}

	// No drift rows at all beyond the host-scoped one.
	drifted, err := p.ListDrifted(ctx, interfaces.DriftFilter{})
	require.NoError(t, err)
	require.Len(t, drifted, 1, "only the host-scoped record may be projected")
	assert.Equal(t, "host:"+peerID+"/service:sshd", drifted[0].EID.String())

	honest, err := p.GetDriftState(ctx, mustParseEID(t, "host:"+peerID+"/service:sshd"))
	require.NoError(t, err, "the host-scoped record in the same batch must still be written")
	require.NotNil(t, honest)
	assert.Equal(t, "v9", honest.ConfigRevision)
}

// TestWriteDriftDiffs_ForgedSubjectCannotOverwriteAnotherPeersRow asserts the
// concrete attack outcome: a compromised steward cannot suppress drift that another
// host reported, because every subject it can write is namespaced to its own
// mTLS-verified authority.
func TestWriteDriftDiffs_ForgedSubjectCannotOverwriteAnotherPeersRow(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	taxonomy := types.DefaultTaxonomy()
	ctx := context.Background()

	const victim = "steward-victim"
	const attacker = "steward-attacker"

	require.NoError(t, w.WriteDriftDiffs(ctx, victim, []*commonpb.DriftDiffRecord{{
		FragmentID:     "file:/etc/shadow",
		ConfigRevision: "v1",
		DetectedAt:     time.Now().UTC(),
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "content", Desired: "expected", Actual: "tampered", Matching: false},
		},
	}}, taxonomy))

	victimEID := mustParseEID(t, "host:"+victim+"/file:/etc/shadow")

	// The attacker replays the victim's subject verbatim, claiming everything matches.
	require.NoError(t, w.WriteDriftDiffs(ctx, attacker, []*commonpb.DriftDiffRecord{{
		FragmentID:     "file:/etc/shadow",
		ConfigRevision: "attacker-rev",
		DetectedAt:     time.Now().UTC().Add(time.Minute),
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "content", Desired: "expected", Actual: "expected", Matching: true},
		},
	}}, taxonomy))

	state, err := p.GetDriftState(ctx, victimEID)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, "v1", state.ConfigRevision,
		"the victim's drift row must be untouched by another peer's report")
	require.Len(t, state.Fields, 1)
	assert.False(t, state.Fields[0].Matching,
		"a foreign peer must not be able to mark the victim's drift as resolved")

	// The attacker's own report landed under its own authority.
	own, err := p.GetDriftState(ctx, mustParseEID(t, "host:"+attacker+"/file:/etc/shadow"))
	require.NoError(t, err)
	assert.Equal(t, "attacker-rev", own.ConfigRevision)
}

// TestWriteDriftDiffs_DoesNotSuppressLaterFragmentRetraction asserts the converse:
// omitting the ClaimScope from drift-diff batches must not disturb the fragment
// writer's retraction contract. A fragment delta that drops a resource still retracts
// it, even after a drift-diff batch named that resource.
func TestWriteDriftDiffs_DoesNotSuppressLaterFragmentRetraction(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	taxonomy := types.DefaultTaxonomy()
	ctx := context.Background()

	const peerID = "steward-retract-still-works"

	fragFile := makeHostFrag("file:/etc/hosts", "enforcing-module:file")
	fragSSHD := makeHostFrag("service:sshd", "enforcing-module:service")
	require.NoError(t, w.WriteFragmentDelta(ctx, peerID,
		[]*commonpb.Fragment{fragFile, fragSSHD}, nil, taxonomy))

	require.NoError(t, w.WriteDriftDiffs(ctx, peerID, []*commonpb.DriftDiffRecord{{
		FragmentID:     "file:/etc/hosts",
		ConfigRevision: "v1",
		DetectedAt:     time.Now().UTC(),
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "content", Desired: "a", Actual: "b", Matching: false},
		},
	}}, taxonomy))

	// The steward's next complete fragment report drops file:/etc/hosts.
	require.NoError(t, w.WriteFragmentDelta(ctx, peerID,
		[]*commonpb.Fragment{fragSSHD}, nil, taxonomy))

	eidFile := mustParseEID(t, "host:"+peerID+"/file:/etc/hosts")
	view, err := p.GetEntity(ctx, eidFile, interfaces.GetEntityOpts{})
	retracted := view == nil || errors.Is(err, sqliteprovider.ErrNotFound)
	assert.True(t, retracted,
		"the fragment set remains the sole basis for retraction; got view=%v err=%v", view, err)
}
