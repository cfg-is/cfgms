// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestFragment_RoundTrip verifies that Fragment marshals and unmarshals correctly.
func TestFragment_RoundTrip(t *testing.T) {
	original := &Fragment{
		FragmentId:     "service:sshd",
		Authority:      "service",
		CanonicalBytes: []byte(`{"name":"sshd","state":"running"}`),
		FragmentHash:   "abc123def456",
	}

	data, err := proto.Marshal(original)
	require.NoError(t, err, "Fragment marshal must not fail")

	got := &Fragment{}
	err = proto.Unmarshal(data, got)
	require.NoError(t, err, "Fragment unmarshal must not fail")

	assert.Equal(t, original.FragmentId, got.FragmentId)
	assert.Equal(t, original.Authority, got.Authority)
	assert.Equal(t, original.CanonicalBytes, got.CanonicalBytes)
	assert.Equal(t, original.FragmentHash, got.FragmentHash)
}

// TestFragmentEnvelope_RoundTrip verifies that FragmentEnvelope marshals and unmarshals correctly.
func TestFragmentEnvelope_RoundTrip(t *testing.T) {
	ts := timestamppb.Now()
	original := &FragmentEnvelope{
		Source:     "service@v1.2.0",
		ObservedAt: ts,
		Confidence: "high",
	}

	data, err := proto.Marshal(original)
	require.NoError(t, err, "FragmentEnvelope marshal must not fail")

	got := &FragmentEnvelope{}
	err = proto.Unmarshal(data, got)
	require.NoError(t, err, "FragmentEnvelope unmarshal must not fail")

	assert.Equal(t, original.Source, got.Source)
	assert.Equal(t, original.ObservedAt.AsTime(), got.ObservedAt.AsTime())
	assert.Equal(t, original.Confidence, got.Confidence)
}

// TestManifestEntry_RoundTrip verifies that ManifestEntry marshals and unmarshals correctly.
func TestManifestEntry_RoundTrip(t *testing.T) {
	original := &ManifestEntry{
		FragmentId:   "host:cpu",
		FragmentHash: "sha256:deadbeef",
	}

	data, err := proto.Marshal(original)
	require.NoError(t, err, "ManifestEntry marshal must not fail")

	got := &ManifestEntry{}
	err = proto.Unmarshal(data, got)
	require.NoError(t, err, "ManifestEntry unmarshal must not fail")

	assert.Equal(t, original.FragmentId, got.FragmentId)
	assert.Equal(t, original.FragmentHash, got.FragmentHash)
}

// TestDNA_FragmentFields_RoundTrip verifies the new ADR-017 fields on DNA
// marshal and unmarshal correctly alongside the legacy attributes field.
func TestDNA_FragmentFields_RoundTrip(t *testing.T) {
	ts := timestamppb.Now()
	original := &DNA{
		Id: "steward-01",
		// legacy field intentionally populated to prove backward-compatible coexistence
		Attributes:  map[string]string{"os": "linux"},
		LastUpdated: ts,
		Fragments: []*Fragment{
			{
				FragmentId:     "service:sshd",
				Authority:      "service",
				CanonicalBytes: []byte(`{"state":"running"}`),
				FragmentHash:   "hash-sshd",
			},
		},
		Envelopes: map[string]*FragmentEnvelope{
			"service:sshd": {
				Source:     "service@v1.0",
				ObservedAt: ts,
				Confidence: "high",
			},
		},
		AggregateRoot: "root-hash-abc",
		Manifest: []*ManifestEntry{
			{FragmentId: "service:sshd", FragmentHash: "hash-sshd"},
		},
	}

	data, err := proto.Marshal(original)
	require.NoError(t, err)

	got := &DNA{}
	err = proto.Unmarshal(data, got)
	require.NoError(t, err)

	assert.Equal(t, original.Id, got.Id)
	assert.Equal(t, original.Attributes, got.Attributes)
	require.Len(t, got.Fragments, 1)
	assert.Equal(t, "service:sshd", got.Fragments[0].FragmentId)
	assert.Equal(t, "service", got.Fragments[0].Authority)
	assert.Equal(t, []byte(`{"state":"running"}`), got.Fragments[0].CanonicalBytes)
	assert.Equal(t, "hash-sshd", got.Fragments[0].FragmentHash)
	assert.Equal(t, original.AggregateRoot, got.AggregateRoot)
	require.Len(t, got.Manifest, 1)
	assert.Equal(t, "service:sshd", got.Manifest[0].FragmentId)
	env, ok := got.Envelopes["service:sshd"]
	require.True(t, ok)
	assert.Equal(t, "service@v1.0", env.Source)
	assert.Equal(t, "high", env.Confidence)
}

// TestFragment_StructuralEnvelopeExclusion is the security assertion (AC: structural
// check) that Fragment contains EXACTLY the four hash-input fields and no envelope
// fields.  This ensures future hash-computation code cannot accidentally walk into
// envelope data by ranging over Fragment's own fields (ADR-017 Amendment A1.1).
//
// It also confirms the authority field contract (ADR-017 §1 / SE security note):
//   - authority is a plain string (SCALAR_TYPE), NOT a message type — it is never
//     eid-shaped.  "service" or "osquery" are the expected values.
//   - It is distinct from the eid's authority_segment ("host:<peerID>"), which is
//     constructed server-side from the mTLS peer in S7 and never read from this field.
func TestFragment_StructuralEnvelopeExclusion(t *testing.T) {
	desc := (&Fragment{}).ProtoReflect().Descriptor()
	fields := desc.Fields()

	// Exactly four fields — no envelope sneaking in.
	assert.Equal(t, 4, fields.Len(), "Fragment must have exactly 4 fields: fragment_id, authority, canonical_bytes, fragment_hash")

	expectedFields := map[string]bool{
		"fragment_id":     false,
		"authority":       false,
		"canonical_bytes": false,
		"fragment_hash":   false,
	}
	for i := range fields.Len() {
		f := fields.Get(i)
		name := string(f.Name())
		_, expected := expectedFields[name]
		assert.True(t, expected, "unexpected field on Fragment: %q — envelope fields must NOT be nested inside Fragment (ADR-017 A1.1)", name)
		expectedFields[name] = true
	}
	for name, seen := range expectedFields {
		assert.True(t, seen, "expected field %q not found on Fragment", name)
	}

	// authority must be a plain string scalar (SCALAR_TYPE), never a message
	// type.  Confirms it is NOT eid-shaped — it is the *role* that won
	// resolution ("service", "osquery"), not an entity address.
	authorityField := fields.ByName("authority")
	require.NotNil(t, authorityField, "Fragment must have an authority field")
	assert.Equal(t, protoreflect.StringKind, authorityField.Kind(),
		"Fragment.authority must be string (not a message/eid type) — it is the module identity or 'osquery', never an eid")
	assert.Equal(t, protoreflect.Optional, authorityField.Cardinality(),
		"Fragment.authority must be a scalar field (not repeated/message)")
}

// TestFragment_NoEnvelopeFieldByName asserts there is no field named "envelope",
// "source", "observed_at", or "confidence" on Fragment — these live exclusively
// on FragmentEnvelope, which is keyed by fragment_id in DNA.envelopes (A1.1).
func TestFragment_NoEnvelopeFieldByName(t *testing.T) {
	desc := (&Fragment{}).ProtoReflect().Descriptor()
	fields := desc.Fields()

	envelopeFieldNames := []string{"envelope", "source", "observed_at", "confidence"}
	for _, name := range envelopeFieldNames {
		f := fields.ByName(protoreflect.Name(name))
		assert.Nil(t, f, "Fragment must NOT have envelope field %q (ADR-017 A1.1: envelope excluded from Fragment hash)", name)
	}
}
