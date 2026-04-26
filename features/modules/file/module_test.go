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
// basePath is the AllowedBasePath that constrains all OS calls; it must be an absolute path.
// On Windows, omits permissions since NTFS does not support Unix permission bits.
func testFileConfigYAML(content, owner, group, basePath string) string {
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
	if basePath != "" {
		cfg += "\nallowed_base_path: " + basePath
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
			configData: testFileConfigYAML(testContent, "", "", tempDir),
			cleanup: func() error {
				return os.Remove(testFile)
			},
			wantErr: false,
		},
		{
			name:       "Create file with ownership",
			configData: testFileConfigYAML(testContent, testUser, testGroup, tempDir),
			cleanup: func() error {
				return os.Remove(testFile)
			},
			wantErr: false,
		},
		{
			name: "Invalid content (empty)",
			configData: "content: \"\"\npermissions: 420\nallowed_base_path: " + tempDir,
			// On Windows, permissions error fires before content validation
			wantErr: true,
		},
		{
			name:       "Invalid permissions",
			configData: "content: \"" + testContent + "\"\npermissions: 9999\nallowed_base_path: " + tempDir,
			wantErr:    true,
		},
		{
			name:       "Invalid owner",
			configData: testFileConfigYAML(testContent, "nonexistentuser", "", tempDir),
			wantErr:    true,
		},
		{
			name:       "Invalid group",
			configData: testFileConfigYAML(testContent, "", "nonexistentgroup", tempDir),
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
	configData := testFileConfigYAML("test content", "", "", tempDir)
	configState := createConfigFromYAML(configData)

	err := module.Set(context.Background(), "", configState)
	if err == nil {
		t.Error("Set() with empty resource ID should fail")
	}

	// Set up configuredBasePath by calling Set with absent state for a non-existent file.
	// os.Remove on a missing file returns ErrNotExist, which Set treats as success.
	absConfigState := createConfigFromYAML("state: absent\nallowed_base_path: " + tempDir)
	nonExistentFile := filepath.Join(tempDir, "nonexistent.txt")
	if err := module.Set(context.Background(), nonExistentFile, absConfigState); err != nil {
		t.Fatalf("Set() with absent state on non-existent file should not error: %v", err)
	}

	// Test Get with non-existent file - should return State: "absent"
	state, err := module.Get(context.Background(), nonExistentFile)
	if err != nil {
		t.Errorf("Get() with non-existent file should not error: %v", err)
	}
	if fileState, ok := state.(*FileConfig); !ok || fileState.State != "absent" {
		t.Error("Get() with non-existent file should return State: 'absent'")
	}

	// Test file creation and verification
	verifyConfig := "content: \"test content for verification\"\nallowed_base_path: " + tempDir
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

	configData := "content: \"test content\"\npermissions: 420\nallowed_base_path: " + tempDir
	configState := createConfigFromYAML(configData)

	err := module.Set(context.Background(), testFile, configState)
	if err == nil {
		t.Error("Set() with Unix permissions on Windows should fail")
	}
}

func TestFileModule_Security(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("Validate rejects empty AllowedBasePath", func(t *testing.T) {
		cfg := &FileConfig{
			State:           "present",
			Content:         "test",
			AllowedBasePath: "",
		}
		err := cfg.Validate()
		if err != ErrAllowedBasePathRequired {
			t.Errorf("Validate() with empty AllowedBasePath: got %v, want ErrAllowedBasePathRequired", err)
		}
	})

	t.Run("Validate rejects relative AllowedBasePath", func(t *testing.T) {
		cfg := &FileConfig{
			State:           "present",
			Content:         "test",
			AllowedBasePath: "relative/path",
		}
		err := cfg.Validate()
		if err != ErrAllowedBasePathRequired {
			t.Errorf("Validate() with relative AllowedBasePath: got %v, want ErrAllowedBasePathRequired", err)
		}
	})

	t.Run("Set rejects missing AllowedBasePath before any OS call", func(t *testing.T) {
		module := New()
		testFile := filepath.Join(tempDir, "should-not-be-created.txt")
		configState := createConfigFromYAML("content: \"test\"\nstate: present")
		err := module.Set(context.Background(), testFile, configState)
		if err != ErrAllowedBasePathRequired {
			t.Errorf("Set() with missing AllowedBasePath: got %v, want ErrAllowedBasePathRequired", err)
		}
		// File must not have been created
		if _, statErr := os.Stat(testFile); !os.IsNotExist(statErr) {
			t.Error("Set() with missing AllowedBasePath must not create any file")
		}
	})

	t.Run("Get before Set returns ErrAllowedBasePathRequired", func(t *testing.T) {
		module := New()
		testFile := filepath.Join(tempDir, "any.txt")
		_, err := module.Get(context.Background(), testFile)
		if err != ErrAllowedBasePathRequired {
			t.Errorf("Get() before Set(): got %v, want ErrAllowedBasePathRequired", err)
		}
	})

	t.Run("Path traversal rejected", func(t *testing.T) {
		module := New()
		// filepath.Join cleans the path but keeps the traversal semantics before ValidateAndCleanPath resolves it
		traversalPath := tempDir + "/../secret.txt"
		configState := createConfigFromYAML("content: \"evil\"\nallowed_base_path: " + tempDir)
		err := module.Set(context.Background(), traversalPath, configState)
		if err == nil {
			t.Error("Set() with path traversal should fail")
		}
	})

	t.Run("Valid path within base succeeds end-to-end", func(t *testing.T) {
		module := New()
		testFile := filepath.Join(tempDir, "valid.txt")
		configYAML := "content: \"valid content\"\nallowed_base_path: " + tempDir
		if platformSupportsPermissions() {
			configYAML += "\npermissions: 420"
		}
		configState := createConfigFromYAML(configYAML)

		if err := module.Set(context.Background(), testFile, configState); err != nil {
			t.Fatalf("Set() with valid path failed: %v", err)
		}

		state, err := module.Get(context.Background(), testFile)
		if err != nil {
			t.Fatalf("Get() with valid path failed: %v", err)
		}

		fileState, ok := state.(*FileConfig)
		if !ok {
			t.Fatal("Get() did not return *FileConfig")
		}
		if fileState.Content != "valid content" {
			t.Errorf("Content mismatch: got %q, want %q", fileState.Content, "valid content")
		}
	})
}
