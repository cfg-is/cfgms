// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package directory

import (
	"context"
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
			configData: `path: ` + filepath.Join(tempDir, "newdir") + `
permissions: 0755`,
			wantErr: false,
		},
		{
			name:       "Create directory with ownership",
			resourceID: filepath.Join(tempDir, "owned-dir"),
			configData: `path: ` + filepath.Join(tempDir, "owned-dir") + `
permissions: 0750
owner: ` + currentUser.Username + `
group: ` + currentGroup.Name,
			wantErr: false,
		},
		{
			name:       "Invalid path",
			resourceID: "",
			configData: `path: ""
permissions: 0755`,
			wantErr: true,
		},
		{
			name:       "Invalid permissions",
			resourceID: filepath.Join(tempDir, "invalid-perms"),
			configData: `path: ` + filepath.Join(tempDir, "invalid-perms") + `
permissions: 9999`,
			wantErr: true,
		},
		{
			name:       "Invalid owner",
			resourceID: filepath.Join(tempDir, "invalid-owner"),
			configData: `path: ` + filepath.Join(tempDir, "invalid-owner") + `
permissions: 0755
owner: nonexistentuser`,
			wantErr: true,
		},
		{
			name:       "Invalid group",
			resourceID: filepath.Join(tempDir, "invalid-group"),
			configData: `path: ` + filepath.Join(tempDir, "invalid-group") + `
permissions: 0755
group: nonexistentgroup`,
			wantErr: true,
		},
	}

	module := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			if configState == nil && !tt.wantErr {
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

	module := New()

	// Test with existing file (not directory)
	filePath := filepath.Join(tempDir, "testfile")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	configData := `path: ` + filePath + `
permissions: 0755`

	// Should fail because path exists but is not a directory
	configState := createConfigFromYAML(configData)
	err = module.Set(context.Background(), filePath, configState)
	if err != ErrNotADirectory {
		t.Errorf("Set() with existing file error = %v, want %v", err, ErrNotADirectory)
	}

	// Test with non-existent parent directory and recursive=false
	nonExistentPath := filepath.Join(tempDir, "nonexistent", "dir")
	configData = `path: ` + nonExistentPath + `
permissions: 0755
recursive: false`

	configState = createConfigFromYAML(configData)
	err = module.Set(context.Background(), nonExistentPath, configState)
	if err == nil {
		t.Error("Set() with non-existent parent and recursive=false should fail")
	}

	// Test with non-existent parent directory and recursive=true
	configData = `path: ` + nonExistentPath + `
permissions: 0755
recursive: true`

	configState = createConfigFromYAML(configData)
	err = module.Set(context.Background(), nonExistentPath, configState)
	if err != nil {
		t.Errorf("Set() with non-existent parent and recursive=true error = %v", err)
	}
}
