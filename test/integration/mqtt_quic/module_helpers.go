package mqtt_quic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// ModuleTestHelper provides utilities for module execution testing
type ModuleTestHelper struct {
	httpClient *http.Client
	baseURL    string
	mqttClient mqtt.Client
	mqttAddr   string
}

// NewModuleTestHelper creates a new module test helper
func NewModuleTestHelper(baseURL, mqttAddr string) *ModuleTestHelper {
	testHelper := NewTestHelper(baseURL)
	return &ModuleTestHelper{
		httpClient: testHelper.httpClient,
		baseURL:    testHelper.baseURL,
		mqttAddr:   mqttAddr,
	}
}

// ConnectMQTT establishes an MQTT connection for message monitoring
func (h *ModuleTestHelper) ConnectMQTT(t *testing.T, clientID string) {
	t.Helper()

	opts := mqtt.NewClientOptions()
	opts.AddBroker(h.mqttAddr)
	opts.SetClientID(clientID)
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetAutoReconnect(true)

	h.mqttClient = mqtt.NewClient(opts)
	token := h.mqttClient.Connect()
	if !token.WaitTimeout(10 * time.Second) {
		t.Fatalf("MQTT connection timeout")
	}
	if token.Error() != nil {
		t.Fatalf("MQTT connection error: %v", token.Error())
	}

	t.Logf("MQTT test client connected: %s", clientID)
}

// DisconnectMQTT closes the MQTT connection
func (h *ModuleTestHelper) DisconnectMQTT(t *testing.T) {
	t.Helper()

	if h.mqttClient != nil && h.mqttClient.IsConnected() {
		h.mqttClient.Disconnect(250)
		t.Log("MQTT test client disconnected")
	}
}

// FileInfo represents information about a file in the container
type FileInfo struct {
	Path        string
	Content     string
	Permissions string
	Owner       string
	Group       string
	Exists      bool
}

// CheckFileInContainer checks if a file exists in the Docker container and returns its info
func (h *ModuleTestHelper) CheckFileInContainer(t *testing.T, containerName, filePath string) (*FileInfo, error) {
	t.Helper()

	info := &FileInfo{
		Path:   filePath,
		Exists: false,
	}

	// Check if file exists
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "test", "-f", filePath)
	if err := cmd.Run(); err != nil {
		// File doesn't exist
		return info, nil
	}

	info.Exists = true

	// Get file content
	cmd = exec.CommandContext(ctx, "docker", "exec", containerName, "cat", filePath)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to read file content: %w", err)
	}
	info.Content = stdout.String()

	// Get file permissions and ownership
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

// DirectoryInfo represents information about a directory in the container
type DirectoryInfo struct {
	Path        string
	Permissions string
	Owner       string
	Group       string
	Exists      bool
}

// CheckDirectoryInContainer checks if a directory exists in the Docker container
func (h *ModuleTestHelper) CheckDirectoryInContainer(t *testing.T, containerName, dirPath string) (*DirectoryInfo, error) {
	t.Helper()

	info := &DirectoryInfo{
		Path:   dirPath,
		Exists: false,
	}

	// Check if directory exists
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "test", "-d", dirPath)
	if err := cmd.Run(); err != nil {
		// Directory doesn't exist
		return info, nil
	}

	info.Exists = true

	// Get directory permissions and ownership
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

// ExecuteCommandInContainer executes a command in the Docker container and returns output
func (h *ModuleTestHelper) ExecuteCommandInContainer(t *testing.T, containerName string, command ...string) (string, error) {
	t.Helper()

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

// CleanupTestFiles removes test files from the container
func (h *ModuleTestHelper) CleanupTestFiles(t *testing.T, containerName string, paths ...string) {
	t.Helper()

	for _, path := range paths {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "rm", "-rf", path)
		_ = cmd.Run() // Ignore errors - file might not exist
		cancel()
	}
}

// ConfigStatusMessage represents a configuration status message from MQTT
type ConfigStatusMessage struct {
	StewardID     string                   `json:"steward_id"`
	ConfigVersion string                   `json:"config_version"`
	Status        string                   `json:"status"`
	Modules       map[string]ModuleStatus  `json:"modules"`
	Timestamp     time.Time                `json:"timestamp"`
}

// ModuleStatus represents the status of a single module
type ModuleStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// SubscribeToConfigStatus subscribes to configuration status messages
func (h *ModuleTestHelper) SubscribeToConfigStatus(t *testing.T, stewardID string, handler func(msg *ConfigStatusMessage)) {
	t.Helper()

	topic := fmt.Sprintf("cfgms/steward/%s/config-status", stewardID)

	token := h.mqttClient.Subscribe(topic, 1, func(client mqtt.Client, message mqtt.Message) {
		var status ConfigStatusMessage
		if err := json.Unmarshal(message.Payload(), &status); err != nil {
			t.Logf("Failed to parse config status: %v", err)
			return
		}

		handler(&status)
	})

	if !token.WaitTimeout(5 * time.Second) {
		t.Fatalf("Failed to subscribe to config status topic")
	}
	if token.Error() != nil {
		t.Fatalf("Config status subscription error: %v", token.Error())
	}

	t.Logf("Subscribed to config status: %s", topic)
}

// WaitForConfigStatus waits for a configuration status message matching the predicate
func (h *ModuleTestHelper) WaitForConfigStatus(t *testing.T, stewardID string, timeout time.Duration, predicate func(*ConfigStatusMessage) bool) *ConfigStatusMessage {
	t.Helper()

	resultChan := make(chan *ConfigStatusMessage, 1)

	h.SubscribeToConfigStatus(t, stewardID, func(msg *ConfigStatusMessage) {
		if predicate(msg) {
			select {
			case resultChan <- msg:
			default:
			}
		}
	})

	select {
	case msg := <-resultChan:
		return msg
	case <-time.After(timeout):
		t.Fatalf("Timeout waiting for config status")
		return nil
	}
}

// SendConfiguration sends a configuration to the controller via HTTP API
// Note: This is a simplified version - in reality, we'd use the actual config API
func (h *ModuleTestHelper) SendConfiguration(t *testing.T, stewardID string, config map[string]interface{}) error {
	t.Helper()

	// For now, we'll use a simplified approach where we trigger QUIC connection
	// which will fetch the configuration from the controller
	// In a full implementation, we'd POST to /api/v1/config/{stewardID}

	t.Logf("Configuration would be sent to steward %s", stewardID)
	return nil
}

// VerifyFileModule verifies a file module execution
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

	// Convert expected permissions to octal string for comparison
	expectedPermsStr := fmt.Sprintf("%o", expectedPerms)
	if fileInfo.Permissions != expectedPermsStr {
		t.Errorf("File permissions mismatch\nExpected: %s\nGot: %s", expectedPermsStr, fileInfo.Permissions)
		return false
	}

	t.Logf("✅ File verified: %s (content: %d bytes, perms: %s)", filePath, len(fileInfo.Content), fileInfo.Permissions)
	return true
}

// VerifyDirectoryModule verifies a directory module execution
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

	// Convert expected permissions to octal string for comparison
	expectedPermsStr := fmt.Sprintf("%o", expectedPerms)
	if dirInfo.Permissions != expectedPermsStr {
		t.Errorf("Directory permissions mismatch\nExpected: %s\nGot: %s", expectedPermsStr, dirInfo.Permissions)
		return false
	}

	t.Logf("✅ Directory verified: %s (perms: %s)", dirPath, dirInfo.Permissions)
	return true
}

// PercentToOctal converts a permission integer (e.g., 755) to octal
func PercentToOctal(perm int) int {
	// Permission is already in decimal representation of octal (e.g., 644, 755)
	// We need to convert it to actual octal value
	str := strconv.Itoa(perm)
	octal, _ := strconv.ParseInt(str, 8, 32)
	return int(octal)
}

// GetAbsoluteTestPath returns the absolute path within the test workspace
func GetAbsoluteTestPath(relativePath string) string {
	return filepath.Join("/test-workspace", relativePath)
}
