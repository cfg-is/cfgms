// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// validContainerNames is a whitelist of allowed container names for security.
var validContainerNames = map[string]bool{
	"steward-standalone":    true,
	"controller-standalone": true,
	"steward":               true,
	"controller":            true,
}

// validateContainerName validates that a container name is in the allowed whitelist.
func validateContainerName(containerName string) error {
	if !validContainerNames[containerName] {
		return fmt.Errorf("invalid container name: %s (not in whitelist)", containerName)
	}
	return nil
}

// E2ETimeouts configures timeout values for different E2E test phases.
type E2ETimeouts struct {
	TransportConnect time.Duration
	ConfigSync       time.Duration
	StatusReport     time.Duration
	HTTP             time.Duration
}

// DefaultE2ETimeouts returns standard timeouts for local development.
func DefaultE2ETimeouts() E2ETimeouts {
	return E2ETimeouts{
		TransportConnect: 10 * time.Second,
		ConfigSync:       10 * time.Second,
		StatusReport:     30 * time.Second,
		HTTP:             10 * time.Second,
	}
}

// CIE2ETimeouts returns conservative timeouts for CI environments.
func CIE2ETimeouts() E2ETimeouts {
	return E2ETimeouts{
		TransportConnect: 20 * time.Second,
		ConfigSync:       20 * time.Second,
		StatusReport:     60 * time.Second,
		HTTP:             20 * time.Second,
	}
}

// ModuleTestHelper provides utilities for module execution E2E testing.
// Uses Docker exec for file system inspection and HTTP API for config delivery.
type ModuleTestHelper struct {
	httpClient *http.Client
	baseURL    string
	timeouts   E2ETimeouts
}

// NewModuleTestHelper creates a new module test helper with default timeouts.
func NewModuleTestHelper(baseURL string) *ModuleTestHelper {
	return NewModuleTestHelperWithTimeouts(baseURL, DefaultE2ETimeouts())
}

// NewModuleTestHelperWithTimeouts creates a new module test helper with custom timeouts.
func NewModuleTestHelperWithTimeouts(baseURL string, timeouts E2ETimeouts) *ModuleTestHelper {
	httpClient := &http.Client{
		Timeout: timeouts.HTTP,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test helper
		},
	}

	return &ModuleTestHelper{
		httpClient: httpClient,
		baseURL:    baseURL,
		timeouts:   timeouts,
	}
}

// GetStewardIDFromContainer extracts the steward ID from the container's log file.
func (h *ModuleTestHelper) GetStewardIDFromContainer(t *testing.T, containerName string) (string, error) {
	t.Helper()

	if err := validateContainerName(containerName); err != nil {
		return "", err
	}

	maxAttempts := 30
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		cmd := exec.Command("docker", "exec", containerName, "sh", "-c",
			"ls -t /tmp/cfgms/cfgms-*.log 2>/dev/null | head -1 | xargs cat 2>/dev/null | grep -o '\"steward_id\":\"[^\"]*\"' | tail -1 | cut -d'\"' -f4")

		output, err := cmd.CombinedOutput()
		stewardID := strings.TrimSpace(string(output))

		if err == nil && stewardID != "" {
			t.Logf("Extracted steward ID from container logs: %s (attempt %d/%d)", stewardID, attempt, maxAttempts)
			return stewardID, nil
		}

		if attempt%5 == 0 {
			t.Logf("Waiting for steward to register... (attempt %d/%d)", attempt, maxAttempts)
		}

		time.Sleep(1 * time.Second)
	}

	return "", fmt.Errorf("could not find steward_id in container logs after %d seconds", maxAttempts)
}

// FileInfo represents information about a file in the container.
type FileInfo struct {
	Path        string
	Content     string
	Permissions string
	Owner       string
	Group       string
	Exists      bool
}

// CheckFileInContainer checks if a file exists in the Docker container.
func (h *ModuleTestHelper) CheckFileInContainer(t *testing.T, containerName, filePath string) (*FileInfo, error) {
	t.Helper()

	if err := validateContainerName(containerName); err != nil {
		return nil, err
	}

	info := &FileInfo{Path: filePath, Exists: false}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "test", "-f", filePath)
	if err := cmd.Run(); err != nil {
		return info, nil
	}

	info.Exists = true

	cmd = exec.CommandContext(ctx, "docker", "exec", containerName, "cat", filePath)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		info.Content = ""
	} else {
		info.Content = stdout.String()
	}

	cmd = exec.CommandContext(ctx, "docker", "exec", containerName, "stat", "-c", "%a %U %G", filePath)
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	parts := strings.Fields(stdout.String())
	if len(parts) >= 3 {
		info.Permissions = parts[0]
		info.Owner = parts[1]
		info.Group = parts[2]
	}

	return info, nil
}

// DirectoryInfo represents information about a directory in the container.
type DirectoryInfo struct {
	Path        string
	Permissions string
	Owner       string
	Group       string
	Exists      bool
}

// CheckDirectoryInContainer checks if a directory exists in the Docker container.
func (h *ModuleTestHelper) CheckDirectoryInContainer(t *testing.T, containerName, dirPath string) (*DirectoryInfo, error) {
	t.Helper()

	if err := validateContainerName(containerName); err != nil {
		return nil, err
	}

	info := &DirectoryInfo{Path: dirPath, Exists: false}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "test", "-d", dirPath)
	if err := cmd.Run(); err != nil {
		return info, nil
	}

	info.Exists = true

	cmd = exec.CommandContext(ctx, "docker", "exec", containerName, "stat", "-c", "%a %U %G", dirPath)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to get directory stats: %w", err)
	}

	parts := strings.Fields(stdout.String())
	if len(parts) >= 3 {
		info.Permissions = parts[0]
		info.Owner = parts[1]
		info.Group = parts[2]
	}

	return info, nil
}

// ExecuteCommandInContainer executes a command in the Docker container and returns output.
func (h *ModuleTestHelper) ExecuteCommandInContainer(t *testing.T, containerName string, command ...string) (string, error) {
	t.Helper()

	if err := validateContainerName(containerName); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args := append([]string{"exec", containerName}, command...)
	cmd := exec.CommandContext(ctx, "docker", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String()
	if err != nil {
		return output, fmt.Errorf("command failed: %w (stderr: %s)", err, stderr.String())
	}

	return output, nil
}

// CleanupTestFiles removes test files from the container.
func (h *ModuleTestHelper) CleanupTestFiles(t *testing.T, containerName string, paths ...string) {
	t.Helper()

	if err := validateContainerName(containerName); err != nil {
		t.Errorf("Container validation failed: %v", err)
		return
	}

	for _, path := range paths {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "rm", "-rf", path)
		_ = cmd.Run()
		cancel()
	}
}

// SendConfiguration sends a configuration to the controller via HTTP test endpoint.
// The controller will push this config to the connected steward via gRPC transport.
func (h *ModuleTestHelper) SendConfiguration(t *testing.T, stewardID string, config map[string]interface{}) error {
	t.Helper()

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/test/stewards/%s/config", h.baseURL, stewardID)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(configJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send config: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Warning: failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("config upload failed with status %d", resp.StatusCode)
	}

	t.Logf("Configuration uploaded for steward %s", stewardID)
	return nil
}

// VerifyFileModule verifies a file module execution result.
func (h *ModuleTestHelper) VerifyFileModule(t *testing.T, containerName, filePath, expectedContent string, expectedPerms int) bool {
	t.Helper()

	fileInfo, err := h.CheckFileInContainer(t, containerName, filePath)
	if err != nil {
		t.Errorf("Failed to check file: %v", err)
		return false
	}

	if !fileInfo.Exists {
		t.Errorf("File does not exist: %s", filePath)
		return false
	}

	if fileInfo.Content != expectedContent {
		t.Errorf("File content mismatch\nExpected: %q\nGot: %q", expectedContent, fileInfo.Content)
		return false
	}

	expectedPermsStr := fmt.Sprintf("%o", expectedPerms)
	if fileInfo.Permissions != expectedPermsStr {
		t.Errorf("File permissions mismatch\nExpected: %s\nGot: %s", expectedPermsStr, fileInfo.Permissions)
		return false
	}

	t.Logf("File verified: %s (content: %d bytes, perms: %s)", filePath, len(fileInfo.Content), fileInfo.Permissions)
	return true
}

// VerifyDirectoryModule verifies a directory module execution result.
func (h *ModuleTestHelper) VerifyDirectoryModule(t *testing.T, containerName, dirPath string, expectedPerms int) bool {
	t.Helper()

	dirInfo, err := h.CheckDirectoryInContainer(t, containerName, dirPath)
	if err != nil {
		t.Errorf("Failed to check directory: %v", err)
		return false
	}

	if !dirInfo.Exists {
		t.Errorf("Directory does not exist: %s", dirPath)
		return false
	}

	expectedPermsStr := fmt.Sprintf("%o", expectedPerms)
	if dirInfo.Permissions != expectedPermsStr {
		t.Errorf("Directory permissions mismatch\nExpected: %s\nGot: %s", expectedPermsStr, dirInfo.Permissions)
		return false
	}

	t.Logf("Directory verified: %s (perms: %s)", dirPath, dirInfo.Permissions)
	return true
}

// CreateFileInContainer creates a file in the container using docker exec.
func (h *ModuleTestHelper) CreateFileInContainer(t *testing.T, containerName, filePath, content string, permissions int) error {
	t.Helper()

	if err := validateContainerName(containerName); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", containerName, "tee", filePath)
	cmd.Stdin = strings.NewReader(content)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}

	cmd = exec.CommandContext(ctx, "docker", "exec", containerName, "chmod", fmt.Sprintf("%o", permissions), filePath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	return nil
}

// CreateDirectoryInContainer creates a directory in the container using docker exec.
func (h *ModuleTestHelper) CreateDirectoryInContainer(t *testing.T, containerName, dirPath string, permissions int) error {
	t.Helper()

	if err := validateContainerName(containerName); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "mkdir", "-p", dirPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	cmd = exec.CommandContext(ctx, "docker", "exec", containerName, "chmod", fmt.Sprintf("%o", permissions), dirPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set directory permissions: %w", err)
	}

	return nil
}

// ExecuteScriptInContainer executes a script file in the container.
func (h *ModuleTestHelper) ExecuteScriptInContainer(t *testing.T, containerName, scriptPath string) (string, error) {
	t.Helper()

	if err := validateContainerName(containerName); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, scriptPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String()
	if err != nil {
		return output, fmt.Errorf("script execution failed: %w (stderr: %s)", err, stderr.String())
	}

	return output, nil
}

// GetAbsoluteTestPath returns the absolute path within the test workspace.
func GetAbsoluteTestPath(relativePath string) string {
	return filepath.Join("/test-workspace", relativePath)
}

// PercentToOctal converts a permission integer (e.g., 755) to octal value.
func PercentToOctal(perm int) int {
	str := strconv.Itoa(perm)
	octal, _ := strconv.ParseInt(str, 8, 32)
	return int(octal)
}
