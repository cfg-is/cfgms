package patch

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"time"
)

// MockPatchManager implements PatchManager for testing purposes
type MockPatchManager struct {
	mu                      sync.RWMutex
	availablePatches        []PatchInfo
	installedPatches        []PatchInfo
	rebootRequired          bool
	lastPatchDate           time.Time
	patchingInProgress      bool
	simulateNetworkError    bool
	simulatePermissionError bool
}

// NewMockPatchManager creates a new mock patch manager with sample data
func NewMockPatchManager() *MockPatchManager {
	now := time.Now()
	return &MockPatchManager{
		availablePatches: []PatchInfo{
			{
				ID:             "SEC-2024-001",
				Title:          "Critical Security Update for OpenSSL",
				Description:    "Fixes CVE-2024-0001 and CVE-2024-0002",
				Severity:       "critical",
				Category:       "security",
				Size:           15728640, // 15MB
				ReleaseDate:    now.AddDate(0, 0, -7),
				Installed:      false,
				RebootRequired: false,
			},
			{
				ID:             "KER-2024-001",
				Title:          "Kernel Security Update",
				Description:    "Kernel security fixes and performance improvements",
				Severity:       "important",
				Category:       "security",
				Size:           104857600, // 100MB
				ReleaseDate:    now.AddDate(0, 0, -3),
				Installed:      false,
				RebootRequired: true,
			},
			{
				ID:             "BUG-2024-001",
				Title:          "System Library Bug Fixes",
				Description:    "Various bug fixes for system libraries",
				Severity:       "moderate",
				Category:       "bugfix",
				Size:           5242880, // 5MB
				ReleaseDate:    now.AddDate(0, 0, -10),
				Installed:      false,
				RebootRequired: false,
			},
		},
		installedPatches: []PatchInfo{
			{
				ID:             "SEC-2024-000",
				Title:          "Previous Security Update",
				Description:    "Previously installed security update",
				Severity:       "important",
				Category:       "security",
				Size:           10485760, // 10MB
				ReleaseDate:    now.AddDate(0, 0, -30),
				Installed:      true,
				RebootRequired: false,
			},
		},
		lastPatchDate:  now.AddDate(0, 0, -15),
		rebootRequired: false,
	}
}

// ListAvailablePatches returns available patches for the specified type
func (m *MockPatchManager) ListAvailablePatches(ctx context.Context, patchType string) ([]PatchInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.simulateNetworkError {
		return nil, ErrNetworkError
	}

	if m.simulatePermissionError {
		return nil, ErrPermissionDenied
	}

	return m.getAvailablePatchesInternal(patchType), nil
}

// getAvailablePatchesInternal is an internal method that doesn't acquire locks
func (m *MockPatchManager) getAvailablePatchesInternal(patchType string) []PatchInfo {
	var filtered []PatchInfo
	for _, patch := range m.availablePatches {
		if patchType == "all" ||
			(patchType == "security" && patch.Category == "security") ||
			(patchType == "critical" && patch.Severity == "critical") ||
			(patchType == "kernel" && strings.Contains(strings.ToLower(patch.Title), "kernel")) {
			filtered = append(filtered, patch)
		}
	}

	return filtered
}

// ListInstalledPatches returns currently installed patches
func (m *MockPatchManager) ListInstalledPatches(ctx context.Context) ([]PatchInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.simulateNetworkError {
		return nil, ErrNetworkError
	}

	return m.installedPatches, nil
}

// InstallPatches installs patches based on the configuration
func (m *MockPatchManager) InstallPatches(ctx context.Context, config *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.simulateNetworkError {
		return ErrNetworkError
	}

	if m.simulatePermissionError {
		return ErrPermissionDenied
	}

	if m.patchingInProgress {
		return ErrPatchingInProgress
	}

	if config.TestMode {
		// In test mode, just return without making changes
		return nil
	}

	// Set patching in progress
	m.patchingInProgress = true
	defer func() { m.patchingInProgress = false }()

	// Get patches to install based on configuration (internal call, already locked)
	availablePatches := m.getAvailablePatchesInternal(config.PatchType)

	// Filter patches based on include/exclude lists
	var patchesToInstall []PatchInfo
	for _, patch := range availablePatches {
		shouldInstall := true

		// Check exclude list
		for _, excludeID := range config.ExcludePatches {
			if patch.ID == excludeID {
				shouldInstall = false
				break
			}
		}

		// Check include list (if specified, only install patches in this list)
		if len(config.IncludePatches) > 0 {
			shouldInstall = false
			for _, includeID := range config.IncludePatches {
				if patch.ID == includeID {
					shouldInstall = true
					break
				}
			}
		}

		if shouldInstall {
			patchesToInstall = append(patchesToInstall, patch)
		}
	}

	// Simulate installation
	for _, patch := range patchesToInstall {
		// Mark as installed
		patch.Installed = true
		m.installedPatches = append(m.installedPatches, patch)

		// Remove from available patches
		for i, available := range m.availablePatches {
			if available.ID == patch.ID {
				m.availablePatches = append(m.availablePatches[:i], m.availablePatches[i+1:]...)
				break
			}
		}

		// Check if reboot is required
		if patch.RebootRequired {
			m.rebootRequired = true
		}
	}

	// Update last patch date
	m.lastPatchDate = time.Now()

	return nil
}

// CheckRebootRequired returns true if a reboot is required after patching
func (m *MockPatchManager) CheckRebootRequired(ctx context.Context) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.rebootRequired, nil
}

// GetLastPatchDate returns the date of the last successful patch operation
func (m *MockPatchManager) GetLastPatchDate(ctx context.Context) (time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.lastPatchDate, nil
}

// Name returns the name of the patch manager
func (m *MockPatchManager) Name() string {
	switch runtime.GOOS {
	case "linux":
		return "mock-apt"
	case "darwin":
		return "mock-softwareupdate"
	case "windows":
		return "mock-windowsupdate"
	default:
		return "mock-unknown"
	}
}

// IsValidPatchType checks if the given patch type is valid for this platform
func (m *MockPatchManager) IsValidPatchType(patchType string) bool {
	return validPatchTypes[patchType]
}

// SetSimulateNetworkError enables/disables network error simulation
func (m *MockPatchManager) SetSimulateNetworkError(simulate bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.simulateNetworkError = simulate
}

// SetSimulatePermissionError enables/disables permission error simulation
func (m *MockPatchManager) SetSimulatePermissionError(simulate bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.simulatePermissionError = simulate
}

// AddAvailablePatch adds a patch to the available patches list (for testing)
func (m *MockPatchManager) AddAvailablePatch(patch PatchInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.availablePatches = append(m.availablePatches, patch)
}

// SetAvailablePatches replaces the available patches list (for testing)
func (m *MockPatchManager) SetAvailablePatches(patches []PatchInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.availablePatches = patches
}

// SetRebootRequired sets the reboot required flag (for testing)
func (m *MockPatchManager) SetRebootRequired(required bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rebootRequired = required
}

// SimulateReboot simulates a system reboot (clears reboot required flag)
func (m *MockPatchManager) SimulateReboot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rebootRequired = false
}

// GetPatchingStatus returns whether patching is in progress
func (m *MockPatchManager) GetPatchingStatus() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.patchingInProgress
}

// Reset resets the mock to its initial state
func (m *MockPatchManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.availablePatches = []PatchInfo{
		{
			ID:             "SEC-2024-001",
			Title:          "Critical Security Update for OpenSSL",
			Description:    "Fixes CVE-2024-0001 and CVE-2024-0002",
			Severity:       "critical",
			Category:       "security",
			Size:           15728640,
			ReleaseDate:    now.AddDate(0, 0, -7),
			Installed:      false,
			RebootRequired: false,
		},
	}

	m.installedPatches = []PatchInfo{
		{
			ID:             "SEC-2024-000",
			Title:          "Previous Security Update",
			Description:    "Previously installed security update",
			Severity:       "important",
			Category:       "security",
			Size:           10485760,
			ReleaseDate:    now.AddDate(0, 0, -30),
			Installed:      true,
			RebootRequired: false,
		},
	}

	m.lastPatchDate = now.AddDate(0, 0, -15)
	m.rebootRequired = false
	m.patchingInProgress = false
	m.simulateNetworkError = false
	m.simulatePermissionError = false
}
