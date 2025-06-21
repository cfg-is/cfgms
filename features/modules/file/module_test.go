package file

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// platformSpecificTest checks if the current platform supports the test
func platformSpecificTest(t *testing.T, requiredOS string) bool {
	if runtime.GOOS != requiredOS {
		t.Skipf("Skipping test on %s, requires %s", runtime.GOOS, requiredOS)
		return false
	}
	return true
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

func TestFileModule(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "test content"
	defaultConfig := FileConfig{
		Content:     testContent,
		Permissions: 0644,
	}
	customPermConfig := FileConfig{
		Content:     testContent,
		Permissions: 0755,
	}

	// Get test user and group
	testUser, testGroup := getTestUser(t)
	ownerGroupConfig := FileConfig{
		Content:     testContent,
		Permissions: 0644,
		Owner:       testUser,
	}
	if testGroup != "" {
		ownerGroupConfig.Group = testGroup
	}

	tests := []struct {
		name       string
		resourceID string
		config     FileConfig
		wantErr    bool
		wantTest   bool
		setup      func(t *testing.T) error
		cleanup    func() error
		testFunc   func(m Module, ctx context.Context) error
		skipOS     string // Add skipOS field to control platform-specific tests
	}{
		{
			name:       "Get existing file",
			resourceID: testFile,
			config:     defaultConfig,
			setup: func(t *testing.T) error {
				return os.WriteFile(testFile, []byte(testContent), 0644)
			},
			cleanup: func() error {
				return os.Remove(testFile)
			},
			testFunc: func(m Module, ctx context.Context) error {
				_, err := m.Get(ctx, testFile)
				return err
			},
		},
		{
			name:       "Get non-existent file",
			resourceID: filepath.Join(tempDir, "nonexistent.txt"),
			config:     defaultConfig,
			wantErr:    true,
			testFunc: func(m Module, ctx context.Context) error {
				_, err := m.Get(ctx, filepath.Join(tempDir, "nonexistent.txt"))
				return err
			},
		},
		{
			name:       "Set new file",
			resourceID: testFile,
			config:     defaultConfig,
			cleanup: func() error {
				return os.Remove(testFile)
			},
			testFunc: func(m Module, ctx context.Context) error {
				return m.Set(ctx, testFile, defaultConfig)
			},
		},
		{
			name:       "Test matching content",
			resourceID: testFile,
			config:     defaultConfig,
			wantTest:   true,
			setup: func(t *testing.T) error {
				// Write file with exact same content and permissions as defaultConfig
				err := os.WriteFile(testFile, []byte(defaultConfig.Content), defaultConfig.Permissions)
				if err != nil {
					return err
				}
				// Verify the file was written correctly
				content, err := os.ReadFile(testFile)
				if err != nil {
					return err
				}
				if string(content) != defaultConfig.Content {
					return fmt.Errorf("content mismatch: got %q, want %q", string(content), defaultConfig.Content)
				}
				// Verify permissions
				info, err := os.Stat(testFile)
				if err != nil {
					return err
				}
				if info.Mode().Perm() != defaultConfig.Permissions {
					return fmt.Errorf("permissions mismatch: got %v, want %v", info.Mode().Perm(), defaultConfig.Permissions)
				}
				return nil
			},
			cleanup: func() error {
				// Ignore errors if file doesn't exist
				err := os.Remove(testFile)
				if err != nil && !os.IsNotExist(err) {
					return err
				}
				return nil
			},
			testFunc: func(m Module, ctx context.Context) error {
				got, err := m.Test(ctx, testFile, defaultConfig)
				if err != nil {
					return err
				}
				if !got {
					// Get current state for debugging
					current, err := m.Get(ctx, testFile)
					if err != nil {
						t.Logf("Failed to get current state: %v", err)
					} else {
						t.Logf("Current content: %q", current.Content)
						t.Logf("Expected content: %q", defaultConfig.Content)
						t.Logf("Current permissions: %v", current.Permissions)
						t.Logf("Expected permissions: %v", defaultConfig.Permissions)
					}
				}
				assert.True(t, got, "Test should return true for matching content")
				return nil
			},
		},
		{
			name:       "Test different content",
			resourceID: testFile,
			config: FileConfig{
				Content:     "different content",
				Permissions: 0644,
			},
			wantTest: false,
			setup: func(t *testing.T) error {
				return os.WriteFile(testFile, []byte(testContent), 0644)
			},
			cleanup: func() error {
				return os.Remove(testFile)
			},
			testFunc: func(m Module, ctx context.Context) error {
				got, err := m.Test(ctx, testFile, FileConfig{
					Content:     "different content",
					Permissions: 0644,
				})
				if err != nil {
					return err
				}
				assert.Equal(t, false, got, "Test should return false for different content")
				return nil
			},
		},
		{
			name:       "Get file with no read permission",
			resourceID: testFile,
			config:     defaultConfig,
			setup: func(t *testing.T) error {
				// Create file with no read permissions
				if err := os.WriteFile(testFile, []byte(testContent), 0000); err != nil {
					return err
				}
				return nil
			},
			cleanup: func() error {
				// Restore permissions for cleanup
				os.Chmod(testFile, 0644)
				return os.Remove(testFile)
			},
			wantErr: true,
			testFunc: func(m Module, ctx context.Context) error {
				_, err := m.Get(ctx, testFile)
				return err
			},
		},
		{
			name:       "Set file with no write permission",
			resourceID: testFile,
			config:     defaultConfig,
			setup: func(t *testing.T) error {
				// Create file with no write permissions
				if err := os.WriteFile(testFile, []byte("original"), 0444); err != nil {
					return err
				}
				return nil
			},
			cleanup: func() error {
				// Restore permissions for cleanup
				os.Chmod(testFile, 0644)
				return os.Remove(testFile)
			},
			wantErr: true,
			testFunc: func(m Module, ctx context.Context) error {
				return m.Set(ctx, testFile, defaultConfig)
			},
		},
		{
			name:       "Set file with custom permissions",
			resourceID: testFile,
			config:     customPermConfig,
			setup: func(t *testing.T) error {
				return nil
			},
			cleanup: func() error {
				return os.Remove(testFile)
			},
			testFunc: func(m Module, ctx context.Context) error {
				if err := m.Set(ctx, testFile, customPermConfig); err != nil {
					return err
				}
				info, err := os.Stat(testFile)
				if err != nil {
					return err
				}
				if info.Mode().Perm() != 0755 {
					return os.ErrInvalid
				}
				return nil
			},
		},
		{
			name:       "Get empty resource ID",
			resourceID: "",
			config:     defaultConfig,
			wantErr:    true,
			testFunc: func(m Module, ctx context.Context) error {
				_, err := m.Get(ctx, "")
				return err
			},
		},
		{
			name:       "Set empty config data",
			resourceID: testFile,
			config:     FileConfig{},
			wantErr:    true,
			testFunc: func(m Module, ctx context.Context) error {
				return m.Set(ctx, testFile, FileConfig{})
			},
		},
		{
			name:       "Test with empty resource ID",
			resourceID: "",
			config:     defaultConfig,
			wantErr:    true,
			testFunc: func(m Module, ctx context.Context) error {
				_, err := m.Test(ctx, "", defaultConfig)
				return err
			},
		},
		{
			name:       "Test with empty config data",
			resourceID: testFile,
			config:     FileConfig{},
			wantErr:    true,
			testFunc: func(m Module, ctx context.Context) error {
				_, err := m.Test(ctx, testFile, FileConfig{})
				return err
			},
		},
		{
			name:       "Set file with owner and group (Linux/Darwin)",
			resourceID: testFile,
			config:     ownerGroupConfig,
			skipOS:     "windows",
			setup: func(t *testing.T) error {
				return os.WriteFile(testFile, []byte(testContent), 0644)
			},
			cleanup: func() error {
				err := os.Remove(testFile)
				if err != nil && !os.IsNotExist(err) {
					return err
				}
				return nil
			},
			testFunc: func(m Module, ctx context.Context) error {
				return m.Set(ctx, testFile, ownerGroupConfig)
			},
		},
		{
			name:       "Set file with owner and group (Windows)",
			resourceID: testFile,
			config:     ownerGroupConfig,
			skipOS:     "linux",
			setup: func(t *testing.T) error {
				if runtime.GOOS != "windows" {
					t.Skip("Skipping Windows-specific test")
				}
				return os.WriteFile(testFile, []byte(testContent), 0644)
			},
			cleanup: func() error {
				err := os.Remove(testFile)
				if err != nil && !os.IsNotExist(err) {
					return err
				}
				return nil
			},
			testFunc: func(m Module, ctx context.Context) error {
				return m.Set(ctx, testFile, ownerGroupConfig)
			},
		},
		{
			name:       "Test owner and group changes",
			resourceID: testFile,
			config:     ownerGroupConfig,
			wantTest:   true,
			skipOS:     "windows",
			setup: func(t *testing.T) error {
				// Create file with default owner/group
				return os.WriteFile(testFile, []byte(testContent), 0644)
			},
			cleanup: func() error {
				err := os.Remove(testFile)
				if err != nil && !os.IsNotExist(err) {
					return err
				}
				return nil
			},
			testFunc: func(m Module, ctx context.Context) error {
				// Set the file with owner/group
				if err := m.Set(ctx, testFile, ownerGroupConfig); err != nil {
					return err
				}

				// Test if the changes were applied
				match, err := m.Test(ctx, testFile, ownerGroupConfig)
				if err != nil {
					return err
				}
				assert.True(t, match, "Test should return true after setting owner/group")
				return nil
			},
		},
		{
			name:       "Test invalid owner",
			resourceID: testFile,
			config: FileConfig{
				Content:     testContent,
				Permissions: 0644,
				Owner:       "nonexistentuser",
			},
			wantErr: true,
			skipOS:  "windows",
			setup: func(t *testing.T) error {
				return os.WriteFile(testFile, []byte(testContent), 0644)
			},
			cleanup: func() error {
				err := os.Remove(testFile)
				if err != nil && !os.IsNotExist(err) {
					return err
				}
				return nil
			},
			testFunc: func(m Module, ctx context.Context) error {
				return m.Set(ctx, testFile, FileConfig{
					Content:     testContent,
					Permissions: 0644,
					Owner:       "nonexistentuser",
				})
			},
		},
		{
			name:       "Test invalid group",
			resourceID: testFile,
			config: FileConfig{
				Content:     testContent,
				Permissions: 0644,
				Group:       "nonexistentgroup",
			},
			wantErr: true,
			skipOS:  "windows",
			setup: func(t *testing.T) error {
				return os.WriteFile(testFile, []byte(testContent), 0644)
			},
			cleanup: func() error {
				err := os.Remove(testFile)
				if err != nil && !os.IsNotExist(err) {
					return err
				}
				return nil
			},
			testFunc: func(m Module, ctx context.Context) error {
				return m.Set(ctx, testFile, FileConfig{
					Content:     testContent,
					Permissions: 0644,
					Group:       "nonexistentgroup",
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip if test is not supported on current platform
			if tt.skipOS != "" && runtime.GOOS == tt.skipOS {
				t.Skipf("Skipping test on %s", runtime.GOOS)
				return
			}

			// Create a new module instance for each test
			m := New()

			// Run setup if provided
			if tt.setup != nil {
				require.NoError(t, tt.setup(t), "Setup failed")
			}

			// Run cleanup after test
			if tt.cleanup != nil {
				defer func() {
					err := tt.cleanup()
					if err != nil && !os.IsNotExist(err) {
						t.Errorf("Cleanup failed: %v", err)
					}
				}()
			}

			// Run the test function
			err := tt.testFunc(m, context.Background())

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
