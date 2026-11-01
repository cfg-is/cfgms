// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types_test

import (
	"encoding/json"
	"testing"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEID_RoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantAuth string
		wantName string
		wantLID  string
	}{
		{
			name:     "bare authority",
			input:    "host:a1b2c3",
			wantAuth: "host",
			wantName: "a1b2c3",
			wantLID:  "",
		},
		{
			name:     "authority with service local id",
			input:    "host:a1b2c3/service:sshd",
			wantAuth: "host",
			wantName: "a1b2c3",
			wantLID:  "service:sshd",
		},
		{
			name:     "authority with file local id containing slash",
			input:    "host:a1b2/file:/etc/hosts",
			wantAuth: "host",
			wantName: "a1b2",
			wantLID:  "file:/etc/hosts",
		},
		{
			name:     "cluster authority",
			input:    "cluster:hv-east-guid",
			wantAuth: "cluster",
			wantName: "hv-east-guid",
			wantLID:  "",
		},
		{
			name:     "directory authority with local id",
			input:    "directory:inst-42/user:alice",
			wantAuth: "directory",
			wantName: "inst-42",
			wantLID:  "user:alice",
		},
		{
			name:     "m365 authority",
			input:    "m365:tenant-guid",
			wantAuth: "m365",
			wantName: "tenant-guid",
			wantLID:  "",
		},
		{
			name:     "cfgms authority",
			input:    "cfgms:deploy-1",
			wantAuth: "cfgms",
			wantName: "deploy-1",
			wantLID:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eid, err := types.ParseEID(tc.input)
			require.NoError(t, err)

			assert.Equal(t, tc.wantAuth, eid.AuthorityType())
			assert.Equal(t, tc.wantName, eid.AuthorityName())
			assert.Equal(t, tc.wantLID, eid.LocalID())
			assert.Equal(t, tc.input, eid.String(), "round-trip must match input")
		})
	}
}

func TestNewEID_RoundTrip(t *testing.T) {
	eid, err := types.NewEID("host", "a1b2c3", "service:sshd")
	require.NoError(t, err)
	assert.Equal(t, "host:a1b2c3/service:sshd", eid.String())

	eid2, err := types.NewEID("host", "a1b2c3", "")
	require.NoError(t, err)
	assert.Equal(t, "host:a1b2c3", eid2.String())
	assert.False(t, eid2.HasLocalID())

	eid3, err := types.NewEID("host", "a1b2", "file:/etc/hosts")
	require.NoError(t, err)
	assert.Equal(t, "host:a1b2/file:/etc/hosts", eid3.String())
	assert.True(t, eid3.HasLocalID())
}

// TestEID_JSONRoundTrip guards against EID losing its identity across JSON
// encoding. EID's fields are unexported (authorityType/authorityName/localID);
// without MarshalJSON/UnmarshalJSON, encoding/json serializes it as "{}" and
// every REST response field of type EID (Entity.EID, Edge.From/To,
// Neighborhood.Root, StateDiff.Subject, DriftState.EID, ...) would silently
// discard the entity identifier.
func TestEID_JSONRoundTrip(t *testing.T) {
	cases := []string{
		"host:a1b2c3",
		"host:a1b2c3/service:sshd",
		"host:a1b2/file:/etc/hosts",
		"cluster:hv-east-guid",
		"directory:inst-42/user:alice",
	}

	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			eid, err := types.ParseEID(input)
			require.NoError(t, err)

			b, err := json.Marshal(eid)
			require.NoError(t, err)
			assert.JSONEq(t, `"`+input+`"`, string(b), "EID must marshal to its canonical string form, not an opaque object")

			var decoded types.EID
			require.NoError(t, json.Unmarshal(b, &decoded))
			assert.Equal(t, eid, decoded)
			assert.Equal(t, input, decoded.String())
		})
	}
}

// TestEID_JSONRoundTrip_Embedded proves the struct-field case that the REST
// handlers actually rely on: an EID nested inside another struct must survive
// a JSON encode/decode cycle, not collapse to an empty object.
func TestEID_JSONRoundTrip_Embedded(t *testing.T) {
	type wrapper struct {
		Subject types.EID
	}

	eid, err := types.ParseEID("host:CFG-70-02")
	require.NoError(t, err)

	b, err := json.Marshal(wrapper{Subject: eid})
	require.NoError(t, err)
	assert.JSONEq(t, `{"Subject":"host:CFG-70-02"}`, string(b))

	var decoded wrapper
	require.NoError(t, json.Unmarshal(b, &decoded))
	assert.Equal(t, "host:CFG-70-02", decoded.Subject.String())
}

func TestEID_JSONUnmarshal_RejectsMalformed(t *testing.T) {
	var eid types.EID
	err := json.Unmarshal([]byte(`"bogus:a1b2c3"`), &eid)
	assert.Error(t, err, "unmarshaling an unregistered authority type must fail, not silently zero out")
}

func TestParseEID_RejectMalformed(t *testing.T) {
	// Note: "slash in authority name" cannot be tested via ParseEID because the
	// format splits unambiguously at the first '/'. A slash would end the authority
	// segment, not embed in the authority name. NewEID rejects slash-in-name
	// directly (see TestNewEID_RejectMalformed).
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "unregistered authority type",
			input: "bogus:a1b2c3",
		},
		{
			name:  "empty authority type",
			input: ":a1b2c3",
		},
		{
			name:  "empty authority name",
			input: "host:",
		},
		{
			name:  "missing colon in authority segment",
			input: "hosta1b2c3",
		},
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "only slash",
			input: "/",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := types.ParseEID(tc.input)
			assert.Error(t, err, "expected error for input %q", tc.input)
		})
	}
}

func TestNewEID_RejectMalformed(t *testing.T) {
	_, err := types.NewEID("host", "a1/b2", "")
	assert.Error(t, err, "authority name with slash must be rejected")

	_, err = types.NewEID("bogus", "a1b2c3", "")
	assert.Error(t, err, "unregistered authority type must be rejected")

	_, err = types.NewEID("host", "", "")
	assert.Error(t, err, "empty authority name must be rejected")

	_, err = types.NewEID("", "a1b2c3", "")
	assert.Error(t, err, "empty authority type must be rejected")
}

func TestEID_AuthoritySegment(t *testing.T) {
	eid, err := types.ParseEID("host:a1b2c3/service:sshd")
	require.NoError(t, err)
	assert.Equal(t, "host:a1b2c3", eid.AuthoritySegment())
}

func TestEID_IsZero(t *testing.T) {
	var zero types.EID
	assert.True(t, zero.IsZero())

	eid, err := types.ParseEID("host:a1b2c3")
	require.NoError(t, err)
	assert.False(t, eid.IsZero())
}
