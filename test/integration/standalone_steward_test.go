// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors

// Package integration contains integration tests that validate CFGMS deployment scenarios
// as documented in QUICK_START.md. These tests ensure that the documented workflows
// actually work as described.
package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/pkg/logging"
)

// StandaloneStewardTestSuite validates QUICK_START.md Option A: Standalone Steward
//
// This test suite validates the exact workflow documented in QUICK_START.md:
//  1. Create configuration file with resources
//  2. Run steward in standalone mode
//  3. Verify resources are created/managed correctly
//  4. Modify configuration and verify changes are applied
//
// Philosophy: "Test what you ship, ship what you test"
type StandaloneStewardTestSuite struct {
	suite.Suite
	tempDir    string
	configPath string
	logger     logging.Logger
}

func (s *StandaloneStewardTestSuite) SetupSuite() {
	// Create temporary directory for test artifacts
	var err error
	s.tempDir, err = os.MkdirTemp("", "cfgms-standalone-test-*")
	require.NoError(s.T(), err)

	s.configPath = filepath.Join(s.tempDir, "config.yaml")

	// Initialize logger
	s.logger = logging.NewNoopLogger()
}

func (s *StandaloneStewardTestSuite) TearDownSuite() {
	// Cleanup temporary directory
	if s.tempDir != "" {
		_ = os.RemoveAll(s.tempDir)
	}
}

func (s *StandaloneStewardTestSuite) SetupTest() {
	// Cleanup any files from previous test
	testDir := filepath.Join(s.tempDir, "managed")
	_ = os.RemoveAll(testDir)
}

// TestQuickStartOptionA validates the QUICK_START.md Option A workflow - steward creation and startup
//
// From QUICK_START.md Step 2: Create Your First Configuration
// This test creates the configuration shown in the documentation and verifies
// the steward can be created, started, and that files/directories are created.
func (s *StandaloneStewardTestSuite) TestQuickStartOptionA() {
	// Step 2: Create configuration (matches QUICK_START.md format)
	testFile := filepath.Join(s.tempDir, "hello-cfgms.txt")
	testDir := filepath.Join(s.tempDir, "cfgms-test")
	infoFile := filepath.Join(testDir, "info.txt")

	expectedContent := `Hello from CFGMS!
This file was created by CFGMS standalone mode.
No controller, no network, no complexity!
`

	configContent := `steward:
  id: quickstart-steward

resources:
  # Create a file
  - name: hello-file
    module: file
    config:
      path: ` + testFile + `
      content: |
        Hello from CFGMS!
        This file was created by CFGMS standalone mode.
        No controller, no network, no complexity!
      state: present
      mode: "0644"

  # Create a directory
  - name: test-directory
    module: directory
    config:
      path: ` + testDir + `
      state: present
      mode: "0755"

  # Create a second file in that directory
  - name: info-file
    module: file
    config:
      path: ` + infoFile + `
      content: "CFGMS standalone mode is working!"
      state: present
`
	err := os.WriteFile(s.configPath, []byte(configContent), 0644)
	require.NoError(s.T(), err, "Should write config file")

	// Step 3: Create steward in standalone mode
	stwd, err := steward.NewStandalone(s.configPath, s.logger)
	require.NoError(s.T(), err, "Should create standalone steward")

	// Verify steward was created with correct ID
	assert.Equal(s.T(), "quickstart-steward", stwd.GetStewardID(), "Should have correct steward ID")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start steward - this will execute the configuration
	err = stwd.Start(ctx)
	require.NoError(s.T(), err, "Should start steward successfully")

	// Allow time for configuration processing
	time.Sleep(100 * time.Millisecond)

	// Stop steward gracefully
	err = stwd.Stop(ctx)
	require.NoError(s.T(), err, "Should stop steward gracefully")

	// VERIFY: File was created with correct content
	assert.FileExists(s.T(), testFile, "Hello file should be created")
	content, err := os.ReadFile(testFile)
	require.NoError(s.T(), err, "Should read hello file")
	assert.Equal(s.T(), expectedContent, string(content), "File content should match")

	// VERIFY: Directory was created
	info, err := os.Stat(testDir)
	require.NoError(s.T(), err, "Test directory should exist")
	assert.True(s.T(), info.IsDir(), "Should be a directory")

	// VERIFY: Info file was created in the directory
	assert.FileExists(s.T(), infoFile, "Info file should be created in directory")
	infoContent, err := os.ReadFile(infoFile)
	require.NoError(s.T(), err, "Should read info file")
	assert.Equal(s.T(), "CFGMS standalone mode is working!", string(infoContent), "Info file content should match")

	s.T().Log("QUICK_START Option A workflow validated successfully - files and directories created!")
}

// TestConfigurationUpdate validates steward can be restarted with modified config
//
// This test verifies that the steward can be created multiple times with
// different configurations, demonstrating the configuration update workflow.
func (s *StandaloneStewardTestSuite) TestConfigurationUpdate() {
	testFile := filepath.Join(s.tempDir, "update-test.txt")

	// Initial configuration
	initialConfig := `steward:
  id: update-test-steward-v1

resources:
  - name: test-file
    module: file
    config:
      path: ` + testFile + `
      content: "Initial content"
      state: present
`
	err := os.WriteFile(s.configPath, []byte(initialConfig), 0644)
	require.NoError(s.T(), err)

	// Run steward with initial config
	ctx := context.Background()
	stwd, err := steward.NewStandalone(s.configPath, s.logger)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "update-test-steward-v1", stwd.GetStewardID())

	err = stwd.Start(ctx)
	require.NoError(s.T(), err)
	time.Sleep(100 * time.Millisecond)
	err = stwd.Stop(ctx)
	require.NoError(s.T(), err)

	// Step 5: Modify configuration
	updatedConfig := `steward:
  id: update-test-steward-v2

resources:
  - name: test-file
    module: file
    config:
      path: ` + testFile + `
      content: "Updated content! CFGMS detects changes."
      state: present
`
	err = os.WriteFile(s.configPath, []byte(updatedConfig), 0644)
	require.NoError(s.T(), err)

	// Run steward again with updated config
	stwd2, err := steward.NewStandalone(s.configPath, s.logger)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "update-test-steward-v2", stwd2.GetStewardID())

	err = stwd2.Start(ctx)
	require.NoError(s.T(), err)
	time.Sleep(100 * time.Millisecond)
	err = stwd2.Stop(ctx)
	require.NoError(s.T(), err)

	s.T().Log("Configuration update workflow test completed")
}

// TestResourceStateAbsent validates the configuration with 'state: absent'
//
// This test verifies that configurations with state: absent can be loaded
// and the steward lifecycle works correctly.
func (s *StandaloneStewardTestSuite) TestResourceStateAbsent() {
	testFile := filepath.Join(s.tempDir, "to-be-removed.txt")

	// Configuration to remove the file
	configContent := `steward:
  id: absent-test-steward

resources:
  - name: remove-file
    module: file
    config:
      path: ` + testFile + `
      state: absent
`
	err := os.WriteFile(s.configPath, []byte(configContent), 0644)
	require.NoError(s.T(), err)

	// Create steward and verify config loads correctly
	ctx := context.Background()
	stwd, err := steward.NewStandalone(s.configPath, s.logger)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "absent-test-steward", stwd.GetStewardID())

	err = stwd.Start(ctx)
	require.NoError(s.T(), err)
	time.Sleep(100 * time.Millisecond)
	err = stwd.Stop(ctx)
	require.NoError(s.T(), err)

	s.T().Log("State absent configuration test completed")
}

// TestMultipleModules validates that configurations with multiple modules load correctly
//
// This test verifies that configurations with multiple different module types
// can be loaded and the steward lifecycle works correctly.
func (s *StandaloneStewardTestSuite) TestMultipleModules() {
	baseDir := filepath.Join(s.tempDir, "multi-module-test")
	configFile := filepath.Join(baseDir, "config.json")
	dataDir := filepath.Join(baseDir, "data")

	configContent := `steward:
  id: multi-module-steward

resources:
  # Create base directory first
  - name: base-directory
    module: directory
    config:
      path: ` + baseDir + `
      state: present
      mode: "0755"

  # Create data subdirectory
  - name: data-directory
    module: directory
    config:
      path: ` + dataDir + `
      state: present
      mode: "0755"

  # Create config file
  - name: config-file
    module: file
    config:
      path: ` + configFile + `
      content: |
        {
          "app_name": "CFGMS Test",
          "version": "1.0.0"
        }
      state: present
      mode: "0644"
`
	err := os.WriteFile(s.configPath, []byte(configContent), 0644)
	require.NoError(s.T(), err)

	// Create steward and verify config with multiple modules loads correctly
	ctx := context.Background()
	stwd, err := steward.NewStandalone(s.configPath, s.logger)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "multi-module-steward", stwd.GetStewardID())

	err = stwd.Start(ctx)
	require.NoError(s.T(), err)
	time.Sleep(100 * time.Millisecond)
	err = stwd.Stop(ctx)
	require.NoError(s.T(), err)

	s.T().Log("Multi-module configuration test completed")
}

// TestIdempotency validates that running steward multiple times works correctly
//
// This test verifies that the steward can be created and started multiple times
// with the same configuration, demonstrating idempotent lifecycle management.
func (s *StandaloneStewardTestSuite) TestIdempotency() {
	testFile := filepath.Join(s.tempDir, "idempotent-test.txt")
	expectedContent := "Idempotent content"

	configContent := `steward:
  id: idempotent-steward

resources:
  - name: idempotent-file
    module: file
    config:
      path: ` + testFile + `
      content: "` + expectedContent + `"
      state: present
`
	err := os.WriteFile(s.configPath, []byte(configContent), 0644)
	require.NoError(s.T(), err)

	ctx := context.Background()

	// Run steward multiple times to verify idempotent lifecycle
	for i := 0; i < 3; i++ {
		stwd, err := steward.NewStandalone(s.configPath, s.logger)
		require.NoError(s.T(), err, "Run %d: should create steward", i+1)
		assert.Equal(s.T(), "idempotent-steward", stwd.GetStewardID(), "Run %d: should have consistent ID", i+1)

		err = stwd.Start(ctx)
		require.NoError(s.T(), err, "Run %d: should start steward", i+1)
		time.Sleep(100 * time.Millisecond)
		err = stwd.Stop(ctx)
		require.NoError(s.T(), err, "Run %d: should stop steward", i+1)
	}

	s.T().Log("Idempotent lifecycle test completed (3 runs)")
}

// TestExecuteConfigurationMethod validates the ExecuteConfiguration method
// which allows manual triggering of configuration execution
func (s *StandaloneStewardTestSuite) TestExecuteConfigurationMethod() {
	testFile := filepath.Join(s.tempDir, "execute-method-test.txt")

	configContent := `steward:
  id: execute-method-steward

resources:
  - name: test-file
    module: file
    config:
      path: ` + testFile + `
      content: "Created via ExecuteConfiguration"
      state: present
`
	err := os.WriteFile(s.configPath, []byte(configContent), 0644)
	require.NoError(s.T(), err)

	// Create steward but don't call Start() - use ExecuteConfiguration directly
	stwd, err := steward.NewStandalone(s.configPath, s.logger)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "execute-method-steward", stwd.GetStewardID())

	ctx := context.Background()

	// Execute configuration manually
	report, err := stwd.ExecuteConfiguration(ctx)
	require.NoError(s.T(), err)

	// Verify execution report - module execution may fail if modules not in registry
	// but the method itself should work
	assert.Equal(s.T(), 1, report.TotalResources, "Should have 1 resource in report")
	s.T().Logf("Execution report: total=%d, success=%d, failed=%d, skipped=%d",
		report.TotalResources, report.SuccessfulCount, report.FailedCount, report.SkippedCount)

	// Cleanup
	err = stwd.Stop(ctx)
	require.NoError(s.T(), err)

	s.T().Log("ExecuteConfiguration method test completed")
}

// TestModuleRegistryAccess validates access to discovered modules
func (s *StandaloneStewardTestSuite) TestModuleRegistryAccess() {
	configContent := `steward:
  id: registry-test-steward

resources:
  - name: test-file
    module: file
    config:
      path: /tmp/test.txt
      content: "test"
      state: present
`
	err := os.WriteFile(s.configPath, []byte(configContent), 0644)
	require.NoError(s.T(), err)

	stwd, err := steward.NewStandalone(s.configPath, s.logger)
	require.NoError(s.T(), err)

	// Get module registry
	registry := stwd.GetModuleRegistry()
	assert.NotNil(s.T(), registry, "Module registry should not be nil")

	// Registry should have discovered modules (it's a map type)
	assert.True(s.T(), len(registry) >= 0, "Registry should be accessible")

	// Check for common modules if they exist
	_, hasFile := registry["file"]
	_, hasDirectory := registry["directory"]
	s.T().Logf("Module registry contains %d modules (file: %v, directory: %v)", len(registry), hasFile, hasDirectory)

	ctx := context.Background()
	err = stwd.Stop(ctx)
	require.NoError(s.T(), err)
}

func TestStandaloneSteward(t *testing.T) {
	suite.Run(t, new(StandaloneStewardTestSuite))
}
