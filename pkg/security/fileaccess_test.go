// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAndCleanPath(t *testing.T) {
	// Create temporary directory for testing
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		basePath    string
		userPath    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid relative path",
			basePath:    tempDir,
			userPath:    "subdir/file.txt",
			expectError: false,
		},
		{
			name:        "valid absolute path within base",
			basePath:    tempDir,
			userPath:    filepath.Join(tempDir, "file.txt"),
			expectError: false,
		},
		{
			name:        "directory traversal attempt with ../",
			basePath:    tempDir,
			userPath:    "../../../etc/passwd",
			expectError: true,
			errorMsg:    "path traversal attempt detected",
		},
		{
			name:        "directory traversal with absolute path",
			basePath:    tempDir,
			userPath:    "/etc/passwd",
			expectError: true,
			errorMsg:    "path traversal attempt detected",
		},
		{
			name:        "path with . and .. elements",
			basePath:    tempDir,
			userPath:    "./subdir/../file.txt",
			expectError: false,
		},
		{
			name:        "empty base path",
			basePath:    "",
			userPath:    "file.txt",
			expectError: true,
			errorMsg:    "base path cannot be empty",
		},
		{
			name:        "empty user path",
			basePath:    tempDir,
			userPath:    "",
			expectError: true,
			errorMsg:    "user path cannot be empty",
		},
		{
			name:        "complex traversal attempt",
			basePath:    tempDir,
			userPath:    "subdir/../../outside/file.txt",
			expectError: true,
			errorMsg:    "path traversal attempt detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateAndCleanPath(tt.basePath, tt.userPath)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == "" {
					t.Errorf("Expected non-empty result")
				}
				// Verify result is absolute path
				if !filepath.IsAbs(result) {
					t.Errorf("Result should be absolute path, got %s", result)
				}
				// Verify result is within base directory
				absBase, _ := filepath.Abs(tt.basePath)
				if !strings.HasPrefix(result, absBase) {
					t.Errorf("Result %s is not within base directory %s", result, absBase)
				}
			}
		})
	}
}

func TestSecureWriteFile(t *testing.T) {
	tempDir := t.TempDir()
	testData := []byte("test content")

	t.Run("successful write", func(t *testing.T) {
		err := SecureWriteFile(tempDir, "test.txt", testData)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Verify file was written
		filePath := filepath.Join(tempDir, "test.txt")
		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("Failed to read written file: %v", err)
		}

		if string(content) != string(testData) {
			t.Errorf("File content mismatch. Expected %s, got %s", testData, content)
		}

		// Verify file permissions are 0600
		info, err := os.Stat(filePath)
		if err != nil {
			t.Fatalf("Failed to stat file: %v", err)
		}

		if info.Mode().Perm() != 0600 {
			t.Errorf("Expected file permissions 0600, got %o", info.Mode().Perm())
		}
	})

	t.Run("write with directory creation", func(t *testing.T) {
		err := SecureWriteFile(tempDir, "subdir/nested/test.txt", testData)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Verify directory was created with correct permissions
		dirPath := filepath.Join(tempDir, "subdir", "nested")
		info, err := os.Stat(dirPath)
		if err != nil {
			t.Fatalf("Failed to stat directory: %v", err)
		}

		if info.Mode().Perm() != 0750 {
			t.Errorf("Expected directory permissions 0750, got %o", info.Mode().Perm())
		}
	})

	t.Run("path traversal prevention", func(t *testing.T) {
		err := SecureWriteFile(tempDir, "../outside.txt", testData)
		if err == nil {
			t.Error("Expected error for path traversal attempt")
		}
		if !strings.Contains(err.Error(), "path traversal") {
			t.Errorf("Expected path traversal error, got %v", err)
		}
	})
}

func TestSecureReadFile(t *testing.T) {
	tempDir := t.TempDir()
	testData := []byte("test content")
	testFile := filepath.Join(tempDir, "test.txt")

	// Create test file
	err := os.WriteFile(testFile, testData, 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	t.Run("successful read", func(t *testing.T) {
		content, err := SecureReadFile(tempDir, "test.txt")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if string(content) != string(testData) {
			t.Errorf("Content mismatch. Expected %s, got %s", testData, content)
		}
	})

	t.Run("path traversal prevention", func(t *testing.T) {
		_, err := SecureReadFile(tempDir, "../../../etc/passwd")
		if err == nil {
			t.Error("Expected error for path traversal attempt")
		}
		if !strings.Contains(err.Error(), "path traversal") {
			t.Errorf("Expected path traversal error, got %v", err)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := SecureReadFile(tempDir, "nonexistent.txt")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
		// Should be a file system error, not a path validation error
		if strings.Contains(err.Error(), "path traversal") {
			t.Errorf("Unexpected path traversal error for valid path, got %v", err)
		}
	})
}

func TestSecureWriteFileWithPerms(t *testing.T) {
	tempDir := t.TempDir()
	testData := []byte("executable content")

	t.Run("write executable file", func(t *testing.T) {
		err := SecureWriteFileWithPerms(tempDir, "script.sh", testData, 0700)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		filePath := filepath.Join(tempDir, "script.sh")
		info, err := os.Stat(filePath)
		if err != nil {
			t.Fatalf("Failed to stat file: %v", err)
		}

		if info.Mode().Perm() != 0700 {
			t.Errorf("Expected file permissions 0700, got %o", info.Mode().Perm())
		}
	})
}

func TestIsPathWithinBase(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		basePath string
		userPath string
		expected bool
	}{
		{
			name:     "valid path within base",
			basePath: tempDir,
			userPath: "subdir/file.txt",
			expected: true,
		},
		{
			name:     "traversal attempt",
			basePath: tempDir,
			userPath: "../../../etc/passwd",
			expected: false,
		},
		{
			name:     "empty paths",
			basePath: "",
			userPath: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPathWithinBase(tt.basePath, tt.userPath)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
