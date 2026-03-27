// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package file

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

// createConfigFromYAML creates a FileConfig from YAML string
func createConfigFromYAML(yamlData string) modules.ConfigState {
	var config FileConfig
	if err := yaml.Unmarshal([]byte(yamlData), &config); err != nil {
		return nil
	}
	return &config
}

// getTestUser returns a test user for the current platform
func getTestUser(t *testing.T) (string, string) {
	switch runtime.GOOS {
	case "linux", "darwin":
		// Try to use the current user for testing
		currentUser, err := user.Current()
		if err != nil {
			t.Fatalf("Failed to get current user: %v", err)
		}
		// Get the primary group name
		group, err := user.LookupGroupId(currentUser.Gid)
		if err != nil {
			t.Logf("Failed to get group name: %v", err)
			return currentUser.Username, ""
		}
		return currentUser.Username, group.Name
	case "windows":
		// Windows uses SIDs, but we'll use the username for testing
		currentUser, err := user.Current()
		if err != nil {
			t.Fatalf("Failed to get current user: %v", err)
		}
		return currentUser.Username, "Users" // Common Windows group
	default:
		t.Skipf("Unsupported platform: %s", runtime.GOOS)
		return "", ""
	}
}

// testFileConfigYAML returns a file config YAML string appropriate for the platform.
// On Windows, omits permissions since NTFS does not support Unix permission bits.
func testFileConfigYAML(content, owner, group string) string {
	cfg := `content: "` + content + `"`
	if platformSupportsPermissions() {
		cfg += "\npermissions: 420"
	}
	if owner != "" {
		cfg += "\nowner: " + owner
	}
	if group != "" {
		cfg += "\ngroup: " + group
	}
	return cfg
}

func TestFileModule(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "test content"

	// Get test user and group
	testUser, testGroup := getTestUser(t)

	tests := []struct {
		name       string
		configData string
		setup      func() error
		cleanup    func() error
		wantErr    bool
	}{
		{
			name:       "Create new file",
			configData: testFileConfigYAML(testContent, "", ""),
			cleanup: func() error {
				return os.Remove(testFile)
			},
			wantErr: false,
		},
		{
			name:       "Create file with ownership",
			configData: testFileConfigYAML(testContent, testUser, testGroup),
			cleanup: func() error {
				return os.Remove(testFile)
			},
			wantErr: false,
		},
		{
			name: "Invalid content (empty)",
			configData: `content: ""
permissions: 420`,
			// On Windows, permissions error fires before content validation
			wantErr: true,
		},
		{
			name: "Invalid permissions",
			configData: `content: "` + testContent + `"
permissions: 9999`,
			wantErr: true,
		},
		{
			name:       "Invalid owner",
			configData: testFileConfigYAML(testContent, "nonexistentuser", ""),
			wantErr:    true,
		},
		{
			name:       "Invalid group",
			configData: testFileConfigYAML(testContent, "", "nonexistentgroup"),
			// Windows doesn't have Unix groups, so this won't error on Windows
			wantErr: runtime.GOOS != "windows",
		},
	}

	module := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			if configState == nil && !tt.wantErr {
				t.Errorf("configState is nil but test should not expect error")
				return
			}

			err := module.Set(context.Background(), testFile, configState)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Test Get
			if !tt.wantErr {
				config, err := module.Get(context.Background(), testFile)
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

func TestFileModule_EdgeCases(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	module := New()

	// Test with empty resource ID
	configData := testFileConfigYAML("test content", "", "")
	configState := createConfigFromYAML(configData)

	err := module.Set(context.Background(), "", configState)
	if err == nil {
		t.Error("Set() with empty resource ID should fail")
	}

	// Test Get with non-existent file - should return State: "absent"
	state, err := module.Get(context.Background(), filepath.Join(tempDir, "nonexistent.txt"))
	if err != nil {
		t.Errorf("Get() with non-existent file should not error: %v", err)
	}
	if fileState, ok := state.(*FileConfig); !ok || fileState.State != "absent" {
		t.Error("Get() with non-existent file should return State: 'absent'")
	}

	// Test file creation and verification
	verifyConfig := `content: "test content for verification"`
	if platformSupportsPermissions() {
		verifyConfig += "\npermissions: 493"
	}
	configState = createConfigFromYAML(verifyConfig)

	err = module.Set(context.Background(), testFile, configState)
	if err != nil {
		t.Errorf("Set() failed: %v", err)
	}

	// Verify file exists and has correct content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Errorf("Failed to read created file: %v", err)
	}

	if string(content) != "test content for verification" {
		t.Errorf("File content mismatch: got %q, want %q", string(content), "test content for verification")
	}

	// Verify permissions (Unix only - Windows uses ACLs)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(testFile)
		if err != nil {
			t.Errorf("Failed to stat file: %v", err)
		}

		expectedPerms := os.FileMode(0755)
		if info.Mode().Perm() != expectedPerms {
			t.Errorf("File permissions mismatch: got %v, want %v", info.Mode().Perm(), expectedPerms)
		}
	}
}

func TestFileModule_PermissionsRejectedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	module := New()

	configData := `content: "test content"
permissions: 420`
	configState := createConfigFromYAML(configData)

	err := module.Set(context.Background(), testFile, configState)
	if err == nil {
		t.Error("Set() with Unix permissions on Windows should fail")
	}
}
