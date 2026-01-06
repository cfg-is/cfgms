// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package security

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
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
			name:     "directory traversal with absolute path",
			basePath: tempDir,
			userPath: func() string {
				// On Windows, use a Windows absolute path; on Unix, use a Unix absolute path
				if runtime.GOOS == "windows" {
					return "C:\\Windows\\System32\\config\\sam"
				}
				return "/etc/passwd"
			}(),
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

		// Verify file permissions are 0600 (Unix only - Windows uses ACLs)
		if runtime.GOOS != "windows" {
			info, err := os.Stat(filePath)
			if err != nil {
				t.Fatalf("Failed to stat file: %v", err)
			}

			if info.Mode().Perm() != 0600 {
				t.Errorf("Expected file permissions 0600, got %o", info.Mode().Perm())
			}
		}
	})

	t.Run("write with directory creation", func(t *testing.T) {
		err := SecureWriteFile(tempDir, "subdir/nested/test.txt", testData)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Verify directory was created with correct permissions (Unix only - Windows uses ACLs)
		if runtime.GOOS != "windows" {
			dirPath := filepath.Join(tempDir, "subdir", "nested")
			info, err := os.Stat(dirPath)
			if err != nil {
				t.Fatalf("Failed to stat directory: %v", err)
			}

			if info.Mode().Perm() != 0750 {
				t.Errorf("Expected directory permissions 0750, got %o", info.Mode().Perm())
			}
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

		// Verify file permissions are 0700 (Unix only - Windows uses ACLs)
		if runtime.GOOS != "windows" {
			filePath := filepath.Join(tempDir, "script.sh")
			info, err := os.Stat(filePath)
			if err != nil {
				t.Fatalf("Failed to stat file: %v", err)
			}

			if info.Mode().Perm() != 0700 {
				t.Errorf("Expected file permissions 0700, got %o", info.Mode().Perm())
			}
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

// Story #253: Additional tests for 90%+ coverage

func TestSecureOpenFile(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("successful open for reading", func(t *testing.T) {
		// Create a test file first
		testData := []byte("test content")
		testFile := filepath.Join(tempDir, "test.txt")
		err := os.WriteFile(testFile, testData, 0600)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Open the file using SecureOpenFile
		file, err := SecureOpenFile(tempDir, "test.txt", os.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		defer func() { _ = file.Close() }()

		// Verify we can read from it
		content, err := io.ReadAll(file)
		if err != nil {
			t.Fatalf("Failed to read file: %v", err)
		}

		if string(content) != string(testData) {
			t.Errorf("Content mismatch. Expected %s, got %s", testData, content)
		}
	})

	t.Run("successful open for writing", func(t *testing.T) {
		file, err := SecureOpenFile(tempDir, "new.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		defer func() { _ = file.Close() }()

		// Write some data
		testData := []byte("new content")
		_, err = file.Write(testData)
		if err != nil {
			t.Fatalf("Failed to write: %v", err)
		}

		// Close and verify
		_ = file.Close()

		// Read back to verify
		content, err := os.ReadFile(filepath.Join(tempDir, "new.txt"))
		if err != nil {
			t.Fatalf("Failed to read back: %v", err)
		}

		if string(content) != string(testData) {
			t.Errorf("Content mismatch. Expected %s, got %s", testData, content)
		}
	})

	t.Run("path traversal prevention", func(t *testing.T) {
		file, err := SecureOpenFile(tempDir, "../../../etc/passwd", os.O_RDONLY, 0)
		if err == nil {
			_ = file.Close()
			t.Error("Expected error for path traversal attempt")
		}
		if !strings.Contains(err.Error(), "path traversal") {
			t.Errorf("Expected path traversal error, got %v", err)
		}
	})

	t.Run("nonexistent file with O_RDONLY fails", func(t *testing.T) {
		file, err := SecureOpenFile(tempDir, "nonexistent.txt", os.O_RDONLY, 0)
		if err == nil {
			_ = file.Close()
			t.Error("Expected error for nonexistent file")
		}
		// Should be a file system error from os.OpenFile
		if strings.Contains(err.Error(), "path validation") {
			t.Errorf("Should be file system error, not path validation, got %v", err)
		}
	})
}

func TestSecureMkdirAll(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("create single directory", func(t *testing.T) {
		dirPath := filepath.Join(tempDir, "testdir")
		err := SecureMkdirAll(dirPath)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Verify directory was created
		info, err := os.Stat(dirPath)
		if err != nil {
			t.Fatalf("Failed to stat directory: %v", err)
		}

		if !info.IsDir() {
			t.Error("Expected a directory")
		}

		// Verify permissions are 0750 (Unix only - Windows uses ACLs)
		if runtime.GOOS != "windows" {
			if info.Mode().Perm() != 0750 {
				t.Errorf("Expected directory permissions 0750, got %o", info.Mode().Perm())
			}
		}
	})

	t.Run("create nested directories", func(t *testing.T) {
		dirPath := filepath.Join(tempDir, "parent", "child", "grandchild")
		err := SecureMkdirAll(dirPath)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Verify all directories were created
		info, err := os.Stat(dirPath)
		if err != nil {
			t.Fatalf("Failed to stat directory: %v", err)
		}

		if !info.IsDir() {
			t.Error("Expected a directory")
		}

		// Verify parent directory also has correct permissions (Unix only - Windows uses ACLs)
		if runtime.GOOS != "windows" {
			parentInfo, err := os.Stat(filepath.Join(tempDir, "parent"))
			if err != nil {
				t.Fatalf("Failed to stat parent directory: %v", err)
			}

			if parentInfo.Mode().Perm() != 0750 {
				t.Errorf("Expected parent directory permissions 0750, got %o", parentInfo.Mode().Perm())
			}
		}
	})

	t.Run("idempotent - no error if directory exists", func(t *testing.T) {
		dirPath := filepath.Join(tempDir, "existing")

		// Create once
		err := SecureMkdirAll(dirPath)
		if err != nil {
			t.Fatalf("First creation failed: %v", err)
		}

		// Create again - should not error
		err = SecureMkdirAll(dirPath)
		if err != nil {
			t.Errorf("Expected no error for existing directory, got %v", err)
		}
	})
}
