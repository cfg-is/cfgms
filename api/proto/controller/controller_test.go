// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package controller

import (
	"testing"

	common "github.com/cfgis/cfgms/api/proto/common"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRegisterRequest_Validation(t *testing.T) {
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
					Id: "550e8400-e29b-41d4-a716-446655440000",
					Attributes: map[string]string{
						"os": "linux",
					},
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
