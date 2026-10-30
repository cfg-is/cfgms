// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tests

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/extended/activedirectory"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestWindowsActiveDirectoryIntegration tests the AD module on actual Windows AD systems
func TestWindowsActiveDirectoryIntegration(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Integration test requires Windows platform")
	}

	logger := logging.NewNoopLogger()
	module := activedirectory.New(logger)

	ctx := context.Background()

	t.Run("SystemAccessVerification", func(t *testing.T) {
		// This will test actual system access to AD
		_, err := module.Get(ctx, "status")
		if err != nil {
			t.Logf("System AD access test failed (expected in non-AD environment): %v", err)
			t.Skip("Requires AD environment")
		}
	})

	// Per-object inventory: one object per user / group under the reserved
	// per-object key, each with an objectGUID id and an attrs map.
	for _, kind := range []string{"directory_user", "directory_group"} {
		kind := kind
		t.Run("Inventory_"+kind, func(t *testing.T) {
			result, err := module.Get(ctx, kind)
			if err != nil {
				t.Logf("Inventory read failed (expected without a domain controller): %v", err)
				t.Skip("Requires AD environment")
			}

			objects, ok := result.AsMap()[modules.PerObjectKey].([]interface{})
			assert.True(t, ok, "inventory must be returned under %s", modules.PerObjectKey)
			for _, entry := range objects {
				obj, ok := entry.(map[string]interface{})
				assert.True(t, ok)
				assert.NotEmpty(t, obj["id"])
				attrs, ok := obj["attrs"].(map[string]interface{})
				assert.True(t, ok)
				assert.Contains(t, attrs, "member_of")
				assert.Equal(t, false, attrs["managed"])
			}
		})
	}

	t.Run("RemovedOperationsRejected", func(t *testing.T) {
		for _, op := range []string{"query:user:Administrator", "list:user", "dna_collection"} {
			_, err := module.Get(ctx, op)
			assert.Error(t, err, "operation %q was removed", op)
		}
	})
}

// TestActiveDirectoryConfiguration tests module configuration scenarios
func TestActiveDirectoryConfiguration(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := activedirectory.New(logger)

	ctx := context.Background()

	// Create test configuration
	testConfig := &activedirectory.ADModuleConfig{
		OperationType:       "read",
		ObjectTypes:         []string{"user", "group"},
		PageSize:            50,
		RequestTimeout:      15 * time.Second,
		EnableDNACollection: true,
	}

	// Test configuration application
	err := module.Set(ctx, "config", testConfig)

	// On non-AD systems, expect failure during verification
	if err != nil {
		assert.Contains(t, err.Error(), "failed to verify system AD access")
		t.Logf("Configuration test failed as expected in non-AD environment: %v", err)
	}
}

// TestActiveDirectoryPerformance benchmarks AD operations
func TestActiveDirectoryPerformance(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Performance test requires Windows platform")
	}

	logger := logging.NewNoopLogger()
	module := activedirectory.New(logger)

	ctx := context.Background()

	// Benchmark status queries
	start := time.Now()
	_, err := module.Get(ctx, "status")
	duration := time.Since(start)

	if err != nil {
		t.Skip("Performance test requires AD environment")
	}

	t.Logf("Status query completed in %v", duration)
	assert.Less(t, duration, 5*time.Second, "Status query should complete within 5 seconds")
}
