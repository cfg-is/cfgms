// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package drift_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/dna/drift"
)

func TestDefaultDetectorConfig_ReturnsNonNil(t *testing.T) {
	config := drift.DefaultDetectorConfig()
	require.NotNil(t, config)
}

func TestNewDetector_NilConfigAndLogger(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, d)
}
