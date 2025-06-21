package directory

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDirectoryModule(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "directory-module-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

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
		name        string
		resourceID  string
		configData  string
		setup       func() error
		cleanup     func() error
		wantErr     bool
		wantTestErr bool
	}{
		{
			name:       "Create new directory",
			resourceID: filepath.Join(tempDir, "newdir"),
			configData: `path: ` + filepath.Join(tempDir, "newdir") + `
permissions: 0755`,
			wantErr:     false,
			wantTestErr: false,
		},
		{
			name:       "Create directory with ownership",
			resourceID: filepath.Join(tempDir, "owned-dir"),
			configData: `path: ` + filepath.Join(tempDir, "owned-dir") + `
permissions: 0750
owner: ` + currentUser.Username + `
group: ` + currentGroup.Name,
			wantErr:     false,
			wantTestErr: false,
		},
		{
			name:       "Invalid path",
			resourceID: "",
			configData: `path: ""
permissions: 0755`,
			wantErr:     true,
			wantTestErr: true,
		},
		{
			name:       "Invalid permissions",
			resourceID: filepath.Join(tempDir, "invalid-perms"),
			configData: `path: ` + filepath.Join(tempDir, "invalid-perms") + `
permissions: 9999`,
			wantErr:     true,
			wantTestErr: true,
		},
		{
			name:       "Invalid owner",
			resourceID: filepath.Join(tempDir, "invalid-owner"),
			configData: `path: ` + filepath.Join(tempDir, "invalid-owner") + `
permissions: 0755
owner: nonexistentuser`,
			wantErr:     true,
			wantTestErr: true,
		},
		{
			name:       "Invalid group",
			resourceID: filepath.Join(tempDir, "invalid-group"),
			configData: `path: ` + filepath.Join(tempDir, "invalid-group") + `
permissions: 0755
group: nonexistentgroup`,
			wantErr:     true,
			wantTestErr: true,
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

			// Test Set
			err := module.Set(context.Background(), tt.resourceID, tt.configData)
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
				if config == "" {
					t.Error("Get() returned empty config")
				}
			}

			// Test Test
			matches, err := module.Test(context.Background(), tt.resourceID, tt.configData)
			if (err != nil) != tt.wantTestErr {
				t.Errorf("Test() error = %v, wantTestErr %v", err, tt.wantTestErr)
				return
			}
			if !tt.wantErr && !tt.wantTestErr && !matches {
				t.Error("Test() returned false for valid configuration")
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
	defer os.RemoveAll(tempDir)

	module := New()

	// Test with existing file (not directory)
	filePath := filepath.Join(tempDir, "testfile")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	configData := `path: ` + filePath + `
permissions: 0755`

	// Should fail because path exists but is not a directory
	err = module.Set(context.Background(), filePath, configData)
	if err != ErrNotADirectory {
		t.Errorf("Set() with existing file error = %v, want %v", err, ErrNotADirectory)
	}

	// Test with non-existent parent directory and recursive=false
	nonExistentPath := filepath.Join(tempDir, "nonexistent", "dir")
	configData = `path: ` + nonExistentPath + `
permissions: 0755
recursive: false`

	err = module.Set(context.Background(), nonExistentPath, configData)
	if err == nil {
		t.Error("Set() with non-existent parent and recursive=false should fail")
	}

	// Test with non-existent parent directory and recursive=true
	configData = `path: ` + nonExistentPath + `
permissions: 0755
recursive: true`

	err = module.Set(context.Background(), nonExistentPath, configData)
	if err != nil {
		t.Errorf("Set() with non-existent parent and recursive=true error = %v", err)
	}
}

// getTestUser returns a test user and group for the current platform
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
			t.Fatalf("Failed to get group name: %v", err)
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
