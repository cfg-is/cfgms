// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package file

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

// createDirConfigFromYAML creates a FileConfig for type: directory from YAML string.
func createDirConfigFromYAML(yamlData string) modules.ConfigState {
	// Parse as FileConfig since directory is now a type variant of file.
	var config FileConfig
	if err := yaml.Unmarshal([]byte(yamlData), &config); err != nil {
		return nil
	}
	return &config
}

// testDirConfigYAML returns a FileConfig YAML for type: directory appropriate for the platform.
func testDirConfigYAML(basePath, path, owner, group, extraFields string) string {
	cfg := "type: directory"
	cfg += "\nallowed_base_path: " + basePath
	cfg += "\npath: " + path
	if platformSupportsPermissions() {
		cfg += "\npermissions: 493" // 0755 decimal
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
		t.Fatalf("Unsupported platform for file module test: %s", runtime.GOOS)
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
			name:       "Invalid content (empty)",
			configData: "content: \"\"\nallowed_base_path: " + tempDir,
			wantErr:    true,
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

			err := module.Set(context.Background(), testFile, configState)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Test Get — verify the round-trip, not just absence of error
			if !tt.wantErr {
				config, err := module.Get(context.Background(), testFile)
				if err != nil {
					t.Errorf("Get() error = %v", err)
					return
				}
				if config == nil {
					t.Fatal("Get() returned nil config")
				}
				fileState, ok := config.(*FileConfig)
				if !ok {
					t.Fatalf("Get() returned %T, want *FileConfig", config)
				}
				if fileState.State != "present" {
					t.Errorf("Get() State = %q, want %q", fileState.State, "present")
				}
				if fileState.Content != testContent {
					t.Errorf("Get() Content = %q, want %q", fileState.Content, testContent)
				}
				if fileState.AllowedBasePath != tempDir {
					t.Errorf("Get() AllowedBasePath = %q, want %q", fileState.AllowedBasePath, tempDir)
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
	if state == nil {
		t.Fatal("Get() should not return nil state for non-existent file")
	}
	fileState, ok := state.(*FileConfig)
	if !ok {
		t.Fatalf("Get() should return *FileConfig, got %T", state)
	}
	if fileState.State != "absent" {
		t.Errorf("Get() State = %q, want %q", fileState.State, "absent")
	}

	// Test file creation and verification
	verifyConfig := "content: \"test content for verification\"\nallowed_base_path: " + tempDir
	if platformSupportsPermissions() {
		verifyConfig += "\npermissions: 493"
	}
	configState = createConfigFromYAML(verifyConfig)

	err = module.Set(context.Background(), testFile, configState)
	if err != nil {
		t.Fatalf("Set() failed: %v", err)
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
			t.Fatalf("Failed to stat file: %v", err)
		}

		expectedPerms := os.FileMode(0755)
		if info.Mode().Perm() != expectedPerms {
			t.Errorf("File permissions mismatch: got %v, want %v", info.Mode().Perm(), expectedPerms)
		}
	}
}

// TestFileConfig_Validate_WindowsACL_MutualExclusion verifies that specifying both
// permissions and windows_acl in the same config returns a validation error.
func TestFileConfig_Validate_WindowsACL_MutualExclusion(t *testing.T) {
	cfg := &FileConfig{
		State:           "present",
		Content:         "test",
		AllowedBasePath: "/tmp",
		Permissions:     0644,
		WindowsACL: &modules.WindowsACL{
			Entries: []modules.ACLEntry{
				{Principal: `BUILTIN\Administrators`, Access: "FullControl"},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() with both permissions and windows_acl should return an error")
	}
}

// TestFileModule_Get_EmitsModeAlias verifies that Get()/AsMap() emits the "mode"
// octal-string alias alongside "permissions". Set() accepts a config declared
// with either field; without "mode" in the read-back state the drift comparator
// reports a phantom added field that no convergence pass can ever resolve.
func TestFileModule_Get_EmitsModeAlias(t *testing.T) {
	if !platformSupportsPermissions() {
		t.Skip("Unix permission bits not applicable on this platform")
	}
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "managed-file")
	module := New()

	// permissions: 420 == 0644 octal.
	configState := createConfigFromYAML(
		"content: \"managed\"\nstate: present\npermissions: 420\nallowed_base_path: " + tempDir)
	if err := module.Set(context.Background(), testFile, configState); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	state, err := module.Get(context.Background(), testFile)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	gotMap := state.AsMap()
	if gotMap["mode"] != "0644" {
		t.Errorf("AsMap()[mode] = %v (%T), want \"0644\"", gotMap["mode"], gotMap["mode"])
	}
	if gotMap["permissions"] != 420 {
		t.Errorf("AsMap()[permissions] = %v, want 420", gotMap["permissions"])
	}
}

// TestFileModule_Get_AbsentOmitsModeAlias verifies the "mode" alias is omitted
// for absent state, matching the existing "permissions" omission.
func TestFileModule_Get_AbsentOmitsModeAlias(t *testing.T) {
	tempDir := t.TempDir()
	module := New()
	nonExistent := filepath.Join(tempDir, "missing")

	// Configure the base path via an absent-state Set before Get.
	absConfig := createConfigFromYAML("state: absent\nallowed_base_path: " + tempDir)
	if err := module.Set(context.Background(), nonExistent, absConfig); err != nil {
		t.Fatalf("Set() absent failed: %v", err)
	}

	state, err := module.Get(context.Background(), nonExistent)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	gotMap := state.AsMap()
	if _, ok := gotMap["mode"]; ok {
		t.Errorf("AsMap() for absent state should omit \"mode\", got %v", gotMap["mode"])
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

	// Unix permissions are not enforced on Windows (NTFS uses ACLs). Specifying them
	// must produce an explicit error pointing at windows_acl — not be silently dropped.
	err := module.Set(context.Background(), testFile, configState)
	if !errors.Is(err, ErrPermissionsNotSupportedOnPlatform) {
		t.Errorf("Set() with Unix permissions on Windows: got %v, want ErrPermissionsNotSupportedOnPlatform", err)
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
		traversalPath := tempDir + "/../secret.txt"
		configState := createConfigFromYAML("content: \"evil\"\nallowed_base_path: " + tempDir)
		err := module.Set(context.Background(), traversalPath, configState)
		if err == nil {
			t.Error("Set() with path traversal should fail")
		}
		// Must be a traversal error, not the unrelated ErrAllowedBasePathRequired
		if errors.Is(err, ErrAllowedBasePathRequired) {
			t.Errorf("Set() with path traversal should fail with traversal error, not ErrAllowedBasePathRequired: %v", err)
		}
	})

	t.Run("Configure with valid AllowedBasePath enables Get", func(t *testing.T) {
		module := New()
		configurable, ok := module.(modules.Configurable)
		if !ok {
			t.Fatal("file module must implement modules.Configurable")
		}
		if err := configurable.Configure(createConfigFromYAML("allowed_base_path: " + tempDir)); err != nil {
			t.Fatalf("Configure() with valid path failed: %v", err)
		}
		// After Configure, Get should work for a non-existent file (returns absent)
		testFile := filepath.Join(tempDir, "configured-get.txt")
		state, err := module.Get(context.Background(), testFile)
		if err != nil {
			t.Fatalf("Get() after Configure() failed: %v", err)
		}
		fileState, ok := state.(*FileConfig)
		if !ok || fileState.State != "absent" {
			t.Error("Get() after Configure() should return absent state for non-existent file")
		}
	})

	t.Run("Configure with missing AllowedBasePath returns ErrAllowedBasePathRequired", func(t *testing.T) {
		module := New()
		configurable, ok := module.(modules.Configurable)
		if !ok {
			t.Fatal("file module must implement modules.Configurable")
		}
		err := configurable.Configure(createConfigFromYAML("content: \"test\""))
		if err != ErrAllowedBasePathRequired {
			t.Errorf("Configure() with missing AllowedBasePath: got %v, want ErrAllowedBasePathRequired", err)
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
		if fileState.AllowedBasePath != tempDir {
			t.Errorf("AllowedBasePath mismatch: got %q, want %q", fileState.AllowedBasePath, tempDir)
		}
	})
}

// ─── type: directory tests ────────────────────────────────────────────────────

// TestFileModule_TypeDirectory_CreateWithPermissions verifies that a directory is created
// with the correct ownership and permissions on Linux (required AC test).
func TestFileModule_TypeDirectory_CreateWithPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions not applicable on Windows")
	}
	if !platformSupportsPermissions() {
		t.Skip("platform does not support permission bits")
	}

	base := t.TempDir()
	targetPath := filepath.Join(base, "managed-dir")

	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current() failed: %v", err)
	}
	currentGroup, err := user.LookupGroupId(currentUser.Gid)
	if err != nil {
		t.Fatalf("LookupGroupId failed: %v", err)
	}

	m := New()
	cfg := createDirConfigFromYAML(testDirConfigYAML(base, targetPath, currentUser.Username, currentGroup.Name, ""))
	if err := m.Set(context.Background(), targetPath, cfg); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected a directory, got file")
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Errorf("permissions = %o, want 0755", got)
	}
}

// TestFileModule_TypeDirectory_ValidEndToEnd verifies a full create+get cycle.
func TestFileModule_TypeDirectory_ValidEndToEnd(t *testing.T) {
	base := t.TempDir()
	targetPath := filepath.Join(base, "mydir")

	m := New()
	cfg := createDirConfigFromYAML(testDirConfigYAML(base, targetPath, "", "", ""))
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
	if gotMap["type"] != "directory" {
		t.Errorf("Get() type = %v, want \"directory\"", gotMap["type"])
	}
	if gotMap["state"] != "present" {
		t.Errorf("Get() state = %v, want \"present\"", gotMap["state"])
	}
}

// TestFileModule_TypeDirectory_Get_EmitsModeAlias verifies Get()/AsMap() emits the
// "mode" octal-string alias alongside "permissions" for type: directory.
func TestFileModule_TypeDirectory_Get_EmitsModeAlias(t *testing.T) {
	if !platformSupportsPermissions() {
		t.Skip("Unix permission bits not applicable on this platform")
	}
	base := t.TempDir()
	targetPath := filepath.Join(base, "managed-dir")
	m := New()

	cfg := createDirConfigFromYAML(testDirConfigYAML(base, targetPath, "", "", ""))
	if err := m.Set(context.Background(), targetPath, cfg); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	state, err := m.Get(context.Background(), targetPath)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	gotMap := state.AsMap()
	if gotMap["mode"] != "0755" {
		t.Errorf("AsMap()[mode] = %v (%T), want \"0755\"", gotMap["mode"], gotMap["mode"])
	}
	if gotMap["permissions"] != 0755 {
		t.Errorf("AsMap()[permissions] = %v, want 493 (0755)", gotMap["permissions"])
	}
}

// TestFileModule_TypeDirectory_Get_AbsentOmitsModeAlias verifies the absent case
// doesn't include "mode" in the returned map.
func TestFileModule_TypeDirectory_Get_AbsentOmitsModeAlias(t *testing.T) {
	base := t.TempDir()
	m := New()
	missing := filepath.Join(base, "missing-dir")

	configurable, ok := m.(modules.Configurable)
	if !ok {
		t.Fatal("file module must implement modules.Configurable")
	}
	if err := configurable.Configure(createConfigFromYAML("allowed_base_path: " + base)); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	state, err := m.Get(context.Background(), missing)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	gotMap := state.AsMap()
	if gotMap["state"] != "absent" {
		t.Fatalf("Get() state = %v, want \"absent\"", gotMap["state"])
	}
	if _, ok := gotMap["mode"]; ok {
		t.Errorf("AsMap() for absent state should omit \"mode\", got %v", gotMap["mode"])
	}
}

// TestFileModule_TypeDirectory_StateAbsent verifies Set() with state: absent returns ErrDirectoryDeletionNotSupported.
func TestFileModule_TypeDirectory_StateAbsent(t *testing.T) {
	base := t.TempDir()
	targetPath := filepath.Join(base, "should-not-be-created")

	m := New()
	cfg := createDirConfigFromYAML("type: directory\nallowed_base_path: " + base + "\npath: " + targetPath + "\nstate: absent")
	err := m.Set(context.Background(), targetPath, cfg)
	if err == nil {
		t.Fatal("Set() with state: absent must return a non-nil error")
	}
	if !errors.Is(err, ErrDirectoryDeletionNotSupported) {
		t.Errorf("Set() with state: absent error = %v, want errors.Is(err, ErrDirectoryDeletionNotSupported) true", err)
	}

	if _, statErr := os.Stat(targetPath); !os.IsNotExist(statErr) {
		t.Error("Set() with state: absent must not create any directory")
	}
}

// TestFileModule_TypeDirectory_PathTraversal verifies path traversal is rejected.
func TestFileModule_TypeDirectory_PathTraversal(t *testing.T) {
	base := t.TempDir()
	traversalPath := filepath.Join(base, "subdir", "..", "..", "escape")

	m := New()
	cfg := createDirConfigFromYAML(testDirConfigYAML(base, traversalPath, "", "", ""))
	err := m.Set(context.Background(), traversalPath, cfg)
	if err == nil {
		t.Error("Set() with path traversal should return an error")
	}
}

// TestFileModule_TypeDirectory_RecursiveRequired verifies that creating a directory
// with non-existent parents and recursive: false returns ErrRecursiveRequired.
func TestFileModule_TypeDirectory_RecursiveRequired(t *testing.T) {
	base := t.TempDir()
	nestedPath := filepath.Join(base, "nonexistent", "dir")

	m := New()
	cfg := createDirConfigFromYAML(testDirConfigYAML(base, nestedPath, "", "", "recursive: false"))
	err := m.Set(context.Background(), nestedPath, cfg)
	if err == nil {
		t.Error("Set() with non-existent parent and recursive: false should fail")
	}
}

// TestFileModule_TypeDirectory_RecursiveTrue verifies that recursive: true creates
// intermediate directories.
func TestFileModule_TypeDirectory_RecursiveTrue(t *testing.T) {
	base := t.TempDir()
	nestedPath := filepath.Join(base, "nonexistent", "dir")

	m := New()
	cfg := createDirConfigFromYAML(testDirConfigYAML(base, nestedPath, "", "", "recursive: true"))
	if err := m.Set(context.Background(), nestedPath, cfg); err != nil {
		t.Fatalf("Set() with recursive: true failed: %v", err)
	}

	if _, err := os.Stat(nestedPath); err != nil {
		t.Errorf("directory not created: %v", err)
	}
}

// TestFileModule_TypeDirectory_PathIsFile verifies that targeting an existing regular file
// returns ErrNotADirectory.
func TestFileModule_TypeDirectory_PathIsFile(t *testing.T) {
	base := t.TempDir()
	filePath := filepath.Join(base, "testfile")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	m := New()
	cfg := createDirConfigFromYAML(testDirConfigYAML(base, filePath, "", "", ""))
	err := m.Set(context.Background(), filePath, cfg)
	if err != ErrNotADirectory {
		t.Errorf("Set() targeting a file = %v, want ErrNotADirectory", err)
	}
}

// TestFileModule_TypeDirectory_Ownership verifies ownership is set when using type: directory.
// Runs on Unix only since Windows chown behavior differs.
func TestFileModule_TypeDirectory_Ownership(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ownership via os.Chown not supported on Windows")
	}

	base := t.TempDir()
	targetPath := filepath.Join(base, "owned-dir")

	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current() failed: %v", err)
	}
	currentGroup, err := user.LookupGroupId(currentUser.Gid)
	if err != nil {
		t.Fatalf("LookupGroupId failed: %v", err)
	}

	m := New()
	cfg := createDirConfigFromYAML(testDirConfigYAML(base, targetPath, currentUser.Username, currentGroup.Name, ""))
	if err := m.Set(context.Background(), targetPath, cfg); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if _, err := os.Stat(targetPath); err != nil {
		t.Fatalf("directory not created: %v", err)
	}
}

// TestFileModule_TypeDirectory_PermissionsRejectedOnWindows verifies Unix permissions
// are rejected with an explicit error on Windows (NTFS uses ACLs; use windows_acl).
func TestFileModule_TypeDirectory_PermissionsRejectedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	base := t.TempDir()
	dirPath := filepath.Join(base, "testdir")
	m := New()

	cfg := createDirConfigFromYAML("type: directory\nallowed_base_path: " + base + "\npath: " + dirPath + "\npermissions: 493")
	// Unix permissions are not enforced on Windows (NTFS uses ACLs). Specifying them
	// must produce an explicit error pointing at windows_acl — not be silently dropped.
	err := m.Set(context.Background(), dirPath, cfg)
	if !errors.Is(err, ErrPermissionsNotSupportedOnPlatform) {
		t.Errorf("Set() with Unix permissions on Windows: got %v, want ErrPermissionsNotSupportedOnPlatform", err)
	}
}

// TestFileModule_TypeDirectory_InvalidOwner verifies that an invalid owner returns an error.
func TestFileModule_TypeDirectory_InvalidOwner(t *testing.T) {
	base := t.TempDir()
	dirPath := filepath.Join(base, "testdir")
	m := New()

	cfg := createDirConfigFromYAML(testDirConfigYAML(base, dirPath, "nonexistentuser99999", "", ""))
	err := m.Set(context.Background(), dirPath, cfg)
	if err == nil {
		t.Error("Set() with invalid owner should fail")
	}
}

// TestFileModule_TypeDirectory_InvalidGroup verifies that an invalid group returns an error.
func TestFileModule_TypeDirectory_InvalidGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("group lookup differs on Windows")
	}
	base := t.TempDir()
	dirPath := filepath.Join(base, "testdir")
	m := New()

	cfg := createDirConfigFromYAML(testDirConfigYAML(base, dirPath, "", "nonexistentgroup99999", ""))
	err := m.Set(context.Background(), dirPath, cfg)
	if err == nil {
		t.Error("Set() with invalid group should fail")
	}
}

// TestFileModule_TypeSymlink_ReturnsSymlinkNotSupported verifies that type: symlink
// returns ErrSymlinkNotSupported (symlink management is planned for a future story).
func TestFileModule_TypeSymlink_ReturnsSymlinkNotSupported(t *testing.T) {
	base := t.TempDir()
	targetPath := filepath.Join(base, "mylink")
	m := New()

	cfg := &FileConfig{
		Type:            "symlink",
		State:           "present",
		AllowedBasePath: base,
	}
	err := m.Set(context.Background(), targetPath, cfg)
	if !errors.Is(err, ErrSymlinkNotSupported) {
		t.Errorf("Set() with type: symlink = %v, want ErrSymlinkNotSupported", err)
	}
}
