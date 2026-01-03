// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package testutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// StewardTestConfig contains configuration for setting up a test steward environment.
type StewardTestConfig struct {
	// ControllerAddr is the address of the controller to connect to
	ControllerAddr string

	// StewardID is the unique identifier for the steward
	StewardID string

	// LogLevel is the logging level for the steward
	LogLevel string

	// UseTemporaryDir indicates whether to use a temporary directory for data
	UseTemporaryDir bool

	// DataDir is the directory to use for steward data (ignored if UseTemporaryDir is true)
	DataDir string
}

// DefaultStewardTestConfig returns a StewardTestConfig with reasonable defaults.
func DefaultStewardTestConfig() *StewardTestConfig {
	return &StewardTestConfig{
		ControllerAddr:  "127.0.0.1:8080",
		StewardID:       "test-steward",
		LogLevel:        "info",
		UseTemporaryDir: true,
	}
}

// SetupTestEnvironment creates a test environment with certificates and data directories.
// This is a generic utility that can be used by any test that needs certificates and directories.
func SetupTestEnvironment(t *testing.T, config *StewardTestConfig) (certDir string, dataDir string, cleanup func()) {
	// Setup certificates
	certDir, certCleanup := SetupTestCerts(t)

	// Create data directory
	var dataDirCleanup func()

	if config.UseTemporaryDir {
		tempDir, err := os.MkdirTemp("", "cfgms-test-steward-")
		require.NoError(t, err)
		dataDir = tempDir
		dataDirCleanup = func() {
			if err := os.RemoveAll(tempDir); err != nil {
				// Log error but continue cleanup
				_ = err // Explicitly ignore cleanup errors
			}
		}
	} else {
		dataDir = config.DataDir
		if dataDir != "" {
			err := os.MkdirAll(dataDir, 0755)
			require.NoError(t, err)
		}
		dataDirCleanup = func() {}
	}

	// Create cleanup function
	cleanup = func() {
		certCleanup()
		dataDirCleanup()
	}

	return certDir, dataDir, cleanup
}
