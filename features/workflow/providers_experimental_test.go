// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build experimental

package workflow

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// TestExperimentalBuildProvidersReturnSimulatedSuccess verifies that in the experimental build
// all four builtin providers return a successful simulated response.
func TestExperimentalBuildProvidersReturnSimulatedSuccess(t *testing.T) {
	cases := []struct {
		provider string
		service  string
	}{
		{"microsoft", "users"},
		{"google", "admin"},
		{"salesforce", "sobjects"},
		{"connectwise", "manage"},
	}

	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			logger := logging.NewNoopLogger()
			registry := NewProviderRegistry(logger, nil)

			config := &APIConfig{
				Provider:  tc.provider,
				Service:   tc.service,
				Operation: "list",
			}

			response, err := registry.ExecuteOperation(context.Background(), config)
			require.NoError(t, err)
			assert.True(t, response.Success, "expected Success=true for provider %q", tc.provider)
			assert.Equal(t, 200, response.StatusCode)
			assert.NotNil(t, response.Data)
		})
	}
}
