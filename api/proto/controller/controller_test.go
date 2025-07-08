package controller

import (
	"testing"

	common "github.com/cfgis/cfgms/api/proto"

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
					Id: "test-steward",
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
					Id:          "test-steward",
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
