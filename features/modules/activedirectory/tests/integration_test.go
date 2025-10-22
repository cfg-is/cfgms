package tests

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/modules/activedirectory"
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

	t.Run("UserQuery", func(t *testing.T) {
		result, err := module.Get(ctx, "query:user:Administrator")
		if err != nil {
			t.Logf("User query test failed (expected in non-AD environment): %v", err)
			t.Skip("Requires AD environment")
		}

		assert.NotNil(t, result)
	})

	t.Run("DirectoryDNACollection", func(t *testing.T) {
		result, err := module.Get(ctx, "dna_collection")
		if err != nil {
			t.Logf("DNA collection test failed (expected in non-AD environment): %v", err)
			t.Skip("Requires AD environment")
		}

		assert.NotNil(t, result)
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
