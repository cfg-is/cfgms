// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package modules

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAllModules discovers and tests all module directories
func TestAllModules(t *testing.T) {
	// Get the current test file's directory
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	// Get the modules directory path (we're already in the modules directory)
	modulesDir := currentDir

	// Read all entries in the modules directory
	entries, err := os.ReadDir(modulesDir)
	if err != nil {
		t.Fatalf("Failed to read modules directory: %v", err)
	}

	// Process each entry
	for _, entry := range entries {
		// Skip if not a directory
		if !entry.IsDir() {
			continue
		}

		// Skip the tests directory
		if entry.Name() == "tests" {
			continue
		}

		// Get the full path to the module directory
		modulePath := filepath.Join(modulesDir, entry.Name())

		// Check if this directory contains a module.yaml file
		moduleYamlPath := filepath.Join(modulePath, "module.yaml")
		if _, err := os.Stat(moduleYamlPath); os.IsNotExist(err) {
			continue // Skip directories without module.yaml
		}

		// Run tests for this module
		t.Run(entry.Name(), func(t *testing.T) {
			// Create a test suite for this module
			suite := &ModuleTestSuite{
				ModulePath: modulePath,
				// These values will be overridden by the module's own test file
				NewModule:   nil,
				ResourceID:  "",
				ValidConfig: "",
			}

			// Run the module structure tests
			suite.testModuleStructure(t)
		})
	}
}
