// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package directory

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// createConfigFromYAML creates a directoryConfig from YAML string
func createConfigFromYAML(yamlData string) modules.ConfigState {
	var config directoryConfig
	if err := yaml.Unmarshal([]byte(yamlData), &config); err != nil {
		return nil
	}
	return &config
}

// testDirConfigYAML returns a directory config YAML string appropriate for the platform.
// On Windows, omits permissions since NTFS does not support Unix permission bits.
func testDirConfigYAML(basePath, path, owner, group string, extraFields string) string {
	cfg := "allowed_base_path: " + basePath
	cfg += "\npath: " + path
	if platformSupportsPermissions() {
		cfg += "\npermissions: 0755"
	}
	if owner != "" {
		cfg += "\nowner: " + owner
	}
	if group != "" {
		cfg += "\ngroup: " + group
	}
	if extraFields != "" {
		cfg += "\n" + extraFields
	}
	return cfg
}

// TestDirectoryConfig_Validate_AllowedBasePath tests AllowedBasePath validation in validate()
func TestDirectoryConfig_Validate_AllowedBasePath(t *testing.T) {
	tempDir := t.TempDir()
	validPath := filepath.Join(tempDir, "target")

	tests := []struct {
		name    string
		config  directoryConfig
		wantErr error
	}{
		{
			name:    "empty AllowedBasePath returns ErrAllowedBasePathRequired",
			config:  directoryConfig{AllowedBasePath: "", Path: validPath},
			wantErr: ErrAllowedBasePathRequired,
		},
		{
			name:    "relative AllowedBasePath returns ErrAllowedBasePathRequired",
			config:  directoryConfig{AllowedBasePath: "relative/path", Path: validPath},
			wantErr: ErrAllowedBasePathRequired,
		},
		{
			name:   "absolute AllowedBasePath passes the base check",
			config: directoryConfig{AllowedBasePath: tempDir, Path: validPath},
			// No ErrAllowedBasePathRequired — may return other errors for permissions/state
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("validate() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			// For the valid case we allow any error except ErrAllowedBasePathRequired
			if errors.Is(err, ErrAllowedBasePathRequired) {
				t.Errorf("validate() returned ErrAllowedBasePathRequired unexpectedly")
			}
		})
	}
}

// TestDirectoryModule_Set_EmptyAllowedBasePath verifies Set fails before any OS call when
// AllowedBasePath is empty.
func TestDirectoryModule_Set_EmptyAllowedBasePath(t *testing.T) {
	tempDir := t.TempDir()
	targetPath := filepath.Join(tempDir, "should-not-exist")

	m := New()
	cfg := createConfigFromYAML("allowed_base_path: \npath: " + targetPath)
	err := m.Set(context.Background(), targetPath, cfg)
	if !errors.Is(err, ErrAllowedBasePathRequired) {
		t.Errorf("Set() with empty AllowedBasePath = %v, want ErrAllowedBasePathRequired", err)
	}

	// The directory must NOT have been created
	if _, statErr := os.Stat(targetPath); !os.IsNotExist(statErr) {
		t.Error("Set() with empty AllowedBasePath must not create any directory")
	}
}

// TestDirectoryModule_Get_BeforeSet verifies Get returns ErrAllowedBasePathRequired when
// configuredBasePath has never been populated (i.e., Configure was never called).
// The execution engine calls Configure(desiredState) before Get() for Configurable modules,
// so this error only fires if Configure is bypassed or returns an error.
func TestDirectoryModule_Get_BeforeSet(t *testing.T) {
	m := New()
	_, err := m.Get(context.Background(), "/some/path")
	if !errors.Is(err, ErrAllowedBasePathRequired) {
		t.Errorf("Get() before Configure() = %v, want errors.Is(err, ErrAllowedBasePathRequired) true", err)
	}
}

// TestDirectoryModule_Set_PathTraversal verifies that ../path traversal in dirConfig.Path is rejected.
func TestDirectoryModule_Set_PathTraversal(t *testing.T) {
	base := t.TempDir()
	// Path attempts to escape the base directory
	traversalPath := filepath.Join(base, "subdir", "..", "..", "escape")

	m := New()
	cfg := createConfigFromYAML(testDirConfigYAML(base, traversalPath, "", "", ""))
	err := m.Set(context.Background(), traversalPath, cfg)
	if err == nil {
		t.Error("Set() with path traversal should return an error")
	}
}

// TestDirectoryModule_ValidEndToEnd verifies a full create+get cycle within t.TempDir().
func TestDirectoryModule_ValidEndToEnd(t *testing.T) {
	base := t.TempDir()
	targetPath := filepath.Join(base, "mydir")

	m := New()
	cfg := createConfigFromYAML(testDirConfigYAML(base, targetPath, "", "", ""))
	if err := m.Set(context.Background(), targetPath, cfg); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := m.Get(context.Background(), targetPath)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got == nil {
		t.Fatal("Get() returned nil")
	}

	gotMap := got.AsMap()
	if gotMap["path"] != targetPath {
		t.Errorf("Get() path = %v, want %v", gotMap["path"], targetPath)
	}
}

func TestDirectoryModule(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "directory-module-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to cleanup temp dir %s: %v", tempDir, err)
		}
	}()

	// Get current user and group for ownership tests
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v", err)
	}

	// Get the primary group for the current user
	currentGroup, err := user.LookupGroupId(currentUser.Gid)
	if err != nil {
		t.Fatalf("Failed to get current group: %v", err)
	}

	tests := []struct {
		name       string
		resourceID string
		configData string
		setup      func() error
		cleanup    func() error
		wantErr    bool
	}{
		{
			name:       "Create new directory",
			resourceID: filepath.Join(tempDir, "newdir"),
			configData: testDirConfigYAML(tempDir, filepath.Join(tempDir, "newdir"), "", "", ""),
			wantErr:    false,
		},
		{
			name:       "Create directory with ownership",
			resourceID: filepath.Join(tempDir, "owned-dir"),
			configData: testDirConfigYAML(tempDir, filepath.Join(tempDir, "owned-dir"), currentUser.Username, currentGroup.Name, ""),
			wantErr:    false,
		},
		{
			name:       "Invalid path",
			resourceID: "",
			configData: testDirConfigYAML(tempDir, "", "", "", ""),
			wantErr:    true,
		},
		{
			name:       "Invalid permissions",
			resourceID: filepath.Join(tempDir, "invalid-perms"),
			configData: "allowed_base_path: " + tempDir + "\npath: " + filepath.Join(tempDir, "invalid-perms") + "\npermissions: 9999",
			wantErr:    true,
		},
		{
			name:       "Invalid owner",
			resourceID: filepath.Join(tempDir, "invalid-owner"),
			configData: testDirConfigYAML(tempDir, filepath.Join(tempDir, "invalid-owner"), "nonexistentuser", "", ""),
			wantErr:    true,
		},
		{
			name:       "Invalid group",
			resourceID: filepath.Join(tempDir, "invalid-group"),
			configData: testDirConfigYAML(tempDir, filepath.Join(tempDir, "invalid-group"), "", "nonexistentgroup", ""),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each subtest gets its own module instance to prevent state leakage via
			// configuredBasePath across subtests.
			module := New()

			// Skip ownership tests on Windows (chown not supported)
			if runtime.GOOS == "windows" && tt.name == "Create directory with ownership" {
				t.Skip("Skipping ownership test on Windows - chown not supported")
			}

			if tt.setup != nil {
				if err := tt.setup(); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}

			if tt.cleanup != nil {
				defer func() {
					if err := tt.cleanup(); err != nil {
						t.Errorf("Cleanup failed: %v", err)
					}
				}()
			}

			// Create ConfigState from YAML
			configState := createConfigFromYAML(tt.configData)
			if configState == nil {
				if tt.wantErr {
					// Treat unparseable YAML as an expected error (the YAML itself is the bad input)
					return
				}
				t.Errorf("Failed to create config from YAML: %s", tt.configData)
				return
			}

			// Test Set
			err := module.Set(context.Background(), tt.resourceID, configState)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Test Get
			if !tt.wantErr {
				config, err := module.Get(context.Background(), tt.resourceID)
				if err != nil {
					t.Errorf("Get() error = %v", err)
					return
				}
				if config == nil {
					t.Error("Get() returned nil config")
				}
			}
		})
	}
}

func TestDirectoryModule_EdgeCases(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "directory-module-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to cleanup temp dir %s: %v", tempDir, err)
		}
	}()

	// Test with existing file (not directory)
	// Each scenario gets its own module instance to prevent configuredBasePath state
	// leakage between test cases (same isolation pattern as TestDirectoryModule).
	t.Run("path is existing file not directory", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "testfile")
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
		configData := testDirConfigYAML(tempDir, filePath, "", "", "")
		configState := createConfigFromYAML(configData)
		err := New().Set(context.Background(), filePath, configState)
		if err != ErrNotADirectory {
			t.Errorf("Set() with existing file error = %v, want %v", err, ErrNotADirectory)
		}
	})

	// Test with non-existent parent directory and recursive=false
	t.Run("non-existent parent recursive=false", func(t *testing.T) {
		nonExistentPath := filepath.Join(tempDir, "nonexistent", "dir")
		configData := testDirConfigYAML(tempDir, nonExistentPath, "", "", "recursive: false")
		configState := createConfigFromYAML(configData)
		err := New().Set(context.Background(), nonExistentPath, configState)
		if err == nil {
			t.Error("Set() with non-existent parent and recursive=false should fail")
		}
	})

	// Test with non-existent parent directory and recursive=true
	t.Run("non-existent parent recursive=true", func(t *testing.T) {
		nonExistentPath := filepath.Join(tempDir, "nonexistent", "dir")
		configData := testDirConfigYAML(tempDir, nonExistentPath, "", "", "recursive: true")
		configState := createConfigFromYAML(configData)
		err := New().Set(context.Background(), nonExistentPath, configState)
		if err != nil {
			t.Errorf("Set() with non-existent parent and recursive=true error = %v", err)
		}
	})
}

func TestDirectoryModule_PermissionsRejectedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tempDir := t.TempDir()
	module := New()

	dirPath := filepath.Join(tempDir, "testdir")
	configData := "allowed_base_path: " + tempDir + "\npath: " + dirPath + "\npermissions: 0755"
	configState := createConfigFromYAML(configData)

	err := module.Set(context.Background(), dirPath, configState)
	if err == nil {
		t.Error("Set() with Unix permissions on Windows should fail")
	}
}
