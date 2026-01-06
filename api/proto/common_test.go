// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDNA_Validation(t *testing.T) {
	tests := []struct {
		name    string
		dna     *DNA
		wantErr bool
	}{
		{
			name: "valid DNA",
			dna: &DNA{
				Id: "test-id",
				Attributes: map[string]string{
					"os":      "linux",
					"version": "1.0.0",
				},
				LastUpdated: timestamppb.New(time.Now()),
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			dna: &DNA{
				Attributes: map[string]string{
					"os": "linux",
				},
				LastUpdated: timestamppb.New(time.Now()),
			},
			wantErr: true,
		},
		{
			name: "missing timestamp",
			dna: &DNA{
				Id: "test-id",
				Attributes: map[string]string{
					"os": "linux",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dna.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
