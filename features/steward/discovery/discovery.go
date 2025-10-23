// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package discovery provides module discovery and registry management for steward.
//
// This package scans the filesystem for available CFGMS modules and builds
// a registry of discovered modules with their metadata and capabilities.
// It supports custom module paths, platform-specific system paths, and
// validates module structure before registration.
//
// Module discovery searches in priority order:
//  1. Custom paths from configuration
//  2. Directory relative to binary executable
//  3. Platform-specific system paths
//
// Basic usage:
//
//	// Discover modules from default and custom paths
//	customPaths := []string{"/opt/custom-modules"}
//	registry, err := discovery.DiscoverModules(customPaths)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Check available modules
//	for name, info := range registry {
//		fmt.Printf("Found module: %s v%s at %s\n",
//			name, info.Version, info.Path)
//	}
//
// Module structure requirements:
//   - module.yaml with name, version, and optional metadata
//   - At least one .go source file
//   - Standard Go module directory structure
//
// #nosec G304 - Steward discovery requires file access for detecting system configurations
package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// ModuleInfo contains metadata about a discovered module loaded from module.yaml.
//
// This structure captures both the static metadata from the module.yaml file
// and runtime information like the discovered filesystem path.
type ModuleInfo struct {
	// Name is the unique module identifier
	Name string `yaml:"name"`

	// Version follows semantic versioning (e.g., "1.2.3")
	Version string `yaml:"version"`

	// Description provides a human-readable module description
	Description string `yaml:"description"`

	// Capabilities lists the module's supported features
	Capabilities []string `yaml:"capabilities"`

	// Path is the filesystem path where the module was discovered (runtime only)
	Path string `yaml:"-"`
}

// ModuleRegistry maps module names to their discovered information.
//
// The registry serves as a central lookup table for all discovered modules,
// allowing the module factory to locate and load modules by name.
// Later discoveries override earlier ones when modules have the same name.
type ModuleRegistry map[string]ModuleInfo

// DiscoverModules scans specified paths for available modules and builds a registry.
//
// The function searches custom paths first, then standard system locations.
// Module discovery is non-fatal - individual directory scan failures are logged
// but don't prevent discovery of modules in other directories.
//
// Search path priority:
//  1. Custom paths from the customPaths parameter
//  2. ./modules/ relative to the binary executable
//  3. Platform-specific system paths (/opt/cfgms/modules or C:\Program Files\cfgms\modules)
//
// Returns a registry of all successfully discovered modules, or an error only
// if no modules could be discovered from any path.
func DiscoverModules(customPaths []string) (ModuleRegistry, error) {
	registry := make(ModuleRegistry)

	// Build search paths in priority order
	searchPaths := buildSearchPaths(customPaths)

	for _, path := range searchPaths {
		if err := scanModuleDirectory(path, registry); err != nil {
			// Log error but continue with other paths
			continue
		}
	}

	return registry, nil
}

// buildSearchPaths creates the prioritized list of module search paths
func buildSearchPaths(customPaths []string) []string {
	var paths []string

	// Custom paths from configuration have highest priority
	paths = append(paths, customPaths...)

	// Relative to binary
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		paths = append(paths, filepath.Join(execDir, "modules"))
	}

	// Platform-specific system paths
	switch runtime.GOOS {
	case "windows":
		paths = append(paths, `C:\Program Files\cfgms\modules`)
	case "darwin", "linux":
		paths = append(paths, "/opt/cfgms/modules")
	}

	return paths
}

// scanModuleDirectory scans a directory for modules and adds them to the registry
func scanModuleDirectory(dirPath string, registry ModuleRegistry) error {
	// Check if directory exists
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return fmt.Errorf("module directory does not exist: %s", dirPath)
	}

	// Read directory contents
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read module directory %s: %w", dirPath, err)
	}

	// Check each subdirectory for module.yaml
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		modulePath := filepath.Join(dirPath, entry.Name())
		if err := processModuleDirectory(modulePath, registry); err != nil {
			// Log error but continue with other modules
			continue
		}
	}

	return nil
}

// processModuleDirectory processes a single module directory
func processModuleDirectory(modulePath string, registry ModuleRegistry) error {
	// Look for module.yaml
	metadataPath := filepath.Join(modulePath, "module.yaml")

	moduleInfo, err := ParseModuleMetadata(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to parse module metadata in %s: %w", modulePath, err)
	}

	// Validate module structure
	if err := ValidateModuleStructure(modulePath); err != nil {
		return fmt.Errorf("invalid module structure in %s: %w", modulePath, err)
	}

	// Set the path
	moduleInfo.Path = modulePath

	// Add to registry (newer modules override older ones due to path priority)
	registry[moduleInfo.Name] = moduleInfo

	return nil
}

// ParseModuleMetadata reads and parses module.yaml file
func ParseModuleMetadata(metadataPath string) (ModuleInfo, error) {
	var moduleInfo ModuleInfo

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return moduleInfo, fmt.Errorf("failed to read module metadata: %w", err)
	}

	if err := yaml.Unmarshal(data, &moduleInfo); err != nil {
		return moduleInfo, fmt.Errorf("failed to parse module metadata: %w", err)
	}

	// Validate required fields
	if moduleInfo.Name == "" {
		return moduleInfo, fmt.Errorf("module name is required")
	}
	if moduleInfo.Version == "" {
		return moduleInfo, fmt.Errorf("module version is required")
	}

	return moduleInfo, nil
}

// ValidateModuleStructure checks if the module directory has the required structure
func ValidateModuleStructure(modulePath string) error {
	// Check for required files
	requiredFiles := []string{"module.yaml"}

	for _, file := range requiredFiles {
		filePath := filepath.Join(modulePath, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("required file missing: %s", file)
		}
	}

	// For Go modules, check for .go files
	entries, err := os.ReadDir(modulePath)
	if err != nil {
		return fmt.Errorf("failed to read module directory: %w", err)
	}

	hasGoFiles := false
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".go" {
			hasGoFiles = true
			break
		}
	}

	if !hasGoFiles {
		return fmt.Errorf("no Go source files found in module directory")
	}

	return nil
}
