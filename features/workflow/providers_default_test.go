// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build !experimental

package workflow

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// TestDefaultBuildProvidersReturnErrNotImplemented verifies that all four builtin providers
// return ErrProviderNotImplemented in the default (non-experimental) build.
func TestDefaultBuildProvidersReturnErrNotImplemented(t *testing.T) {
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

			_, err := registry.ExecuteOperation(context.Background(), config)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrProviderNotImplemented),
				"expected ErrProviderNotImplemented for provider %q, got: %v", tc.provider, err)
		})
	}
}
