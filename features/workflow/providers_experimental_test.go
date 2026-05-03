// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build experimental

package workflow

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
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
			logger := pkgtesting.NewMockLogger(true)
			registry := NewProviderRegistry(logger)

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
