// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/service"
	stewardDNA "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// extractFragmentsFromDetails — Issue #3330
//
// These tests cover the wire-format round-trip between the steward's
// marshalFragmentsToJSONString output and the controller's fragment decoder.
// The steward encodes a []*commonpb.Fragment as a protojson JSON array string.
// The control-plane transport (stringMapToInterfaceMap) JSON-parses that string
// into []interface{}. extractFragmentsFromDetails re-marshals and protojson-
// decodes each element.
// ---------------------------------------------------------------------------

// protoJSONFragmentArray marshals fragments to the same JSON array string that
// the steward's marshalFragmentsToJSONString produces.
func protoJSONFragmentArray(t *testing.T, frags []*commonpb.Fragment) string {
	t.Helper()
	opts := protojson.MarshalOptions{EmitUnpopulated: false}
	out := make([]byte, 0, 128)
	out = append(out, '[')
	for i, f := range frags {
		if i > 0 {
			out = append(out, ',')
		}
		b, err := opts.Marshal(f)
		require.NoError(t, err)
		out = append(out, b...)
	}
	out = append(out, ']')
	return string(out)
}

// simulateTransportDecode applies the same JSON-parse step that
// stringMapToInterfaceMap uses: if the JSON-decoded value is not a plain string,
// the parsed value is returned. For a JSON array this always produces []interface{}.
func simulateTransportDecode(t *testing.T, jsonStr string) interface{} {
	t.Helper()
	var parsed interface{}
	require.NoError(t, json.Unmarshal([]byte(jsonStr), &parsed))
	return parsed
}

// TestExtractFragmentsFromDetails_ValidFragment verifies the end-to-end
// wire-format round-trip: a fragment marshalled by the steward's protojson
// encoder arrives at extractFragmentsFromDetails via the transport envelope
// and is faithfully reconstructed with all fields intact. (Issue #3330)
func TestExtractFragmentsFromDetails_ValidFragment(t *testing.T) {
	canonical := []byte(`{"os":"linux","hostname":"host-a"}`)
	frag := &commonpb.Fragment{
		FragmentId:     "host:os",
		Authority:      "gatherer",
		CanonicalBytes: canonical,
		FragmentHash:   "abc123hash",
	}

	jsonStr := protoJSONFragmentArray(t, []*commonpb.Fragment{frag})
	raw := simulateTransportDecode(t, jsonStr)

	frags, err := extractFragmentsFromDetails(raw)
	require.NoError(t, err)
	require.Len(t, frags, 1, "one fragment must be decoded")
	assert.Equal(t, "host:os", frags[0].GetFragmentId())
	assert.Equal(t, "gatherer", frags[0].GetAuthority())
	assert.Equal(t, "abc123hash", frags[0].GetFragmentHash())
	assert.Equal(t, canonical, frags[0].GetCanonicalBytes(),
		"canonical bytes must survive the protojson round-trip without corruption")
}

// TestExtractFragmentsFromDetails_MultipleFragments verifies that a JSON array
// carrying several fragments is fully decoded with each fragment's ID preserved
// in order. (Issue #3330)
func TestExtractFragmentsFromDetails_MultipleFragments(t *testing.T) {
	frags := []*commonpb.Fragment{
		{FragmentId: "host:os", Authority: "gatherer", FragmentHash: "h1"},
		{FragmentId: "host:cpu", Authority: "gatherer", FragmentHash: "h2"},
		{FragmentId: "host:bios", Authority: "gatherer", FragmentHash: "h3"},
	}

	jsonStr := protoJSONFragmentArray(t, frags)
	raw := simulateTransportDecode(t, jsonStr)

	got, err := extractFragmentsFromDetails(raw)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "host:os", got[0].GetFragmentId())
	assert.Equal(t, "host:cpu", got[1].GetFragmentId())
	assert.Equal(t, "host:bios", got[2].GetFragmentId())
}

// TestExtractFragmentsFromDetails_MalformedElementSkipped verifies that a
// malformed JSON element in the array is silently skipped while valid fragments
// in the same array are decoded normally. A compromised steward must not be able
// to blank the valid fragment set by injecting one bad entry. (Issue #3330)
func TestExtractFragmentsFromDetails_MalformedElementSkipped(t *testing.T) {
	goodFrag := &commonpb.Fragment{
		FragmentId: "host:os",
		Authority:  "gatherer",
		FragmentHash: "goodhash",
	}
	opts := protojson.MarshalOptions{EmitUnpopulated: false}
	goodBytes, err := opts.Marshal(goodFrag)
	require.NoError(t, err)

	// Build a mixed array: one valid fragment, one structurally invalid element.
	mixedJSON := "[" + string(goodBytes) + `,{"not":"a fragment","bad":true}]`
	raw := simulateTransportDecode(t, mixedJSON)

	got, err := extractFragmentsFromDetails(raw)
	require.NoError(t, err, "a malformed element must not cause the whole extraction to fail")
	require.Len(t, got, 1, "only the valid fragment must survive")
	assert.Equal(t, "host:os", got[0].GetFragmentId())
}

// TestExtractFragmentsFromDetails_EmptyArray verifies that an empty JSON array
// produces an empty (non-nil) fragment slice with no error. (Issue #3330)
func TestExtractFragmentsFromDetails_EmptyArray(t *testing.T) {
	raw := simulateTransportDecode(t, "[]")

	got, err := extractFragmentsFromDetails(raw)
	require.NoError(t, err)
	assert.Empty(t, got, "empty JSON array must produce an empty fragment slice")
}

// TestExtractFragmentsFromDetails_NonArrayInput verifies that passing a
// non-array value (e.g. a plain string or object) returns an error, so the
// caller's fallback path in handleDNAEvent is exercised when the payload is
// malformed. (Issue #3330)
func TestExtractFragmentsFromDetails_NonArrayInput(t *testing.T) {
	_, err := extractFragmentsFromDetails("not-an-array")
	assert.Error(t, err, "a non-array input must return an error")

	_, err = extractFragmentsFromDetails(map[string]interface{}{"key": "val"})
	assert.Error(t, err, "a JSON object must return an error")
}

// ---------------------------------------------------------------------------
// End-to-end: fragment delta → handleDNAEvent → SyncDNA
// ---------------------------------------------------------------------------

// TestHandleDNAEvent_WireFormatRoundTripBuildsFragments verifies the complete
// steward→controller DNA change-notification path introduced in Issue #3330:
//
//  1. The steward protojson-encodes a []*commonpb.Fragment into a JSON array string.
//  2. The control-plane transport envelope round-trips that string through
//     encoding/json (simulated here by simulateTransportDecode).
//  3. handleDNAEvent decodes the payload via extractFragmentsFromDetails and
//     calls controllerService.SyncDNA with DNA.Fragments populated.
//  4. SyncDNA stores the fragment in the registered steward's in-memory DNA;
//     the test reads it back with GetStewardInfo and asserts fragment integrity.
//
// Uses only real CFGMS components — no mocks. service.NewControllerService is
// the production constructor; the steward is registered as production code does it.
func TestHandleDNAEvent_WireFormatRoundTripBuildsFragments(t *testing.T) {
	const stewardID = "steward-dna-e2e-3330"

	// Real ControllerService — no storage backend (in-memory only).
	logger := logging.NewLogger("error")
	svc := service.NewControllerService(logger)
	require.NoError(t, svc.RegisterSteward(stewardID, "root", "localhost:0", "connected"))

	srv := &Server{
		logger:            logger,
		controllerService: svc,
	}

	// Build a real host:os fragment: NewFragment canonicalizes and hashes the
	// payload, which is required for the SyncDNA integrity check (hostname + os
	// are required identity fields for configTypeFullOSDevice).
	frag, err := stewardDNA.NewFragment(
		"host:os", "gatherer",
		stewardDNA.MapState{"os": "linux", "hostname": "host-e2e-3330"},
	)
	require.NoError(t, err)

	// Simulate the steward's marshalFragmentsToJSONString: protojson-encode the
	// fragment into a JSON array string.
	jsonStr := protoJSONFragmentArray(t, []*commonpb.Fragment{frag})

	// Simulate the transport envelope's stringMapToInterfaceMap: JSON-parse the
	// string so it arrives as []interface{} at the controller (not a raw string).
	raw := simulateTransportDecode(t, jsonStr)

	event := &types.Event{
		ID:        "evt-e2e-3330",
		Type:      types.EventDNAChanged,
		StewardID: stewardID,
		TenantID:  "root",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"dna":      raw,      // decoded fragment array — same shape stringMapToInterfaceMap produces
			"dna_hash": "testhash",
			"is_delta": true,
		},
	}

	require.NoError(t, srv.handleDNAEvent(context.Background(), event),
		"handleDNAEvent must succeed for a valid fragment payload")

	// Read back the steward's in-memory DNA and verify the fragment is present.
	info, ok := svc.GetStewardInfo(stewardID)
	require.True(t, ok, "steward must still be registered after handleDNAEvent")
	require.NotNil(t, info.DNA, "steward DNA must be set after SyncDNA")
	require.Len(t, info.DNA.Fragments, 1,
		"SyncDNA must have stored the decoded fragment in the steward's DNA record")
	assert.Equal(t, "host:os", info.DNA.Fragments[0].GetFragmentId())
	assert.Equal(t, "gatherer", info.DNA.Fragments[0].GetAuthority())
	assert.Equal(t, frag.GetFragmentHash(), info.DNA.Fragments[0].GetFragmentHash(),
		"fragment hash must survive the full protojson round-trip")
}
