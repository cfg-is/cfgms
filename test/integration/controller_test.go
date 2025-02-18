package integration

import (
	"testing"

	"cfgms/api/proto/common"
	"cfgms/api/proto/controller"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestControllerRegistration(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	tests := []struct {
		name    string
		req     *controller.RegisterRequest
		wantErr bool
	}{
		{
			name: "successful registration",
			req: &controller.RegisterRequest{
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := env.controller.AcceptRegistration(env.ctx, tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, resp.StewardId)
			assert.Equal(t, common.Status_OK, resp.Status.Code)
		})
	}
}
