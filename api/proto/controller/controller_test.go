// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package controller

import (
	"testing"

	common "github.com/cfgis/cfgms/api/proto/common"
	sdna "github.com/cfgis/cfgms/features/steward/dna"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRegisterRequest_Validation(t *testing.T) {
	osFragment, err := sdna.NewFragment("host:test", "test", sdna.MapState{"os": "linux"})
	require.NoError(t, err)

	tests := []struct {
		name    string
		req     *RegisterRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: &RegisterRequest{
				Version: "1.0.0",
				InitialDna: &common.DNA{
					Id:          "550e8400-e29b-41d4-a716-446655440000",
					Fragments:   []*common.Fragment{osFragment},
					LastUpdated: timestamppb.Now(),
				},
				Credentials: &common.Credentials{
					TenantId: "test-tenant",
					ClientId: "test-client",
				},
			},
			wantErr: false,
		},
		{
			name: "missing version",
			req: &RegisterRequest{
				InitialDna: &common.DNA{
					Id:          "550e8400-e29b-41d4-a716-446655440001",
					LastUpdated: timestamppb.Now(),
				},
				Credentials: &common.Credentials{
					TenantId: "test-tenant",
					ClientId: "test-client",
				},
			},
			wantErr: true,
		},
		{
			name: "missing DNA",
			req: &RegisterRequest{
				Version: "1.0.0",
				Credentials: &common.Credentials{
					TenantId: "test-tenant",
					ClientId: "test-client",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestHeartbeatRequest_DnaAggregateRoot_RoundTrip verifies that the new
// dna_aggregate_root field (ADR-017 §6 / Issue #2901) marshals and unmarshals
// correctly alongside the existing fields.
func TestHeartbeatRequest_DnaAggregateRoot_RoundTrip(t *testing.T) {
	original := &HeartbeatRequest{
		StewardId:        "steward-01",
		Status:           "healthy",
		Metrics:          map[string]string{"cpu": "0.15"},
		DnaAggregateRoot: "sha256:aabbccddeeff",
	}

	data, err := proto.Marshal(original)
	require.NoError(t, err)

	got := &HeartbeatRequest{}
	err = proto.Unmarshal(data, got)
	require.NoError(t, err)

	assert.Equal(t, original.StewardId, got.StewardId)
	assert.Equal(t, original.Status, got.Status)
	assert.Equal(t, original.Metrics, got.Metrics)
	assert.Equal(t, original.DnaAggregateRoot, got.DnaAggregateRoot)
}

// TestHeartbeatRequest_DnaAggregateRoot_BackwardCompatibility verifies that a
// HeartbeatRequest without dna_aggregate_root (pre-ADR-017 wire) still
// deserialises correctly — the field defaults to empty string (proto3 zero value).
func TestHeartbeatRequest_DnaAggregateRoot_BackwardCompatibility(t *testing.T) {
	legacy := &HeartbeatRequest{
		StewardId: "steward-legacy",
		Status:    "healthy",
	}

	data, err := proto.Marshal(legacy)
	require.NoError(t, err)

	got := &HeartbeatRequest{}
	err = proto.Unmarshal(data, got)
	require.NoError(t, err)

	assert.Equal(t, "steward-legacy", got.StewardId)
	assert.Equal(t, "", got.DnaAggregateRoot, "missing dna_aggregate_root must default to empty string")
}
