// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"time"
)

// InMemoryPatchManager is a real, self-contained implementation of PatchManager
// that keeps its patch repository and installed-patch database entirely in
// memory. It performs the same filtering, include/exclude resolution, install
// bookkeeping, and reboot-tracking logic that a platform manager performs
// against the OS, but against an in-memory store so tests can drive the patch
// module deterministically without root privileges or a live package feed.
//
// It is not a mock: every method executes genuine logic against real state and
// there is no call recording or pre-programmed return sequencing. Failure modes
// (an unreachable repository, an unprivileged process) are modelled as real
// backend states rather than injected responses.
type InMemoryPatchManager struct {
	mu                 sync.RWMutex
	availablePatches   []PatchInfo
	installedPatches   []PatchInfo
	rebootRequired     bool
	lastPatchDate      time.Time
	patchingInProgress bool

	// repositoryReachable models whether the in-memory repository can be
	// contacted. When false the manager genuinely has no feed to read and
	// returns ErrNetworkError, exactly as a platform manager would when the
	// upstream mirror is unreachable.
	repositoryReachable bool
	// hasInstallPrivilege models whether the current process may mutate the
	// installed-patch database. When false, install and enumeration operations
	// return ErrPermissionDenied, matching an unprivileged patch run.
	hasInstallPrivilege bool
}

// NewInMemoryPatchManager creates an in-memory patch manager seeded with a
// representative repository and installed-patch history.
func NewInMemoryPatchManager() *InMemoryPatchManager {
	now := time.Now()
	return &InMemoryPatchManager{
		repositoryReachable: true,
		hasInstallPrivilege: true,
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

// ListAvailablePatches returns available patches for the specified type.
func (m *InMemoryPatchManager) ListAvailablePatches(_ context.Context, patchType string) ([]PatchInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.repositoryReachable {
		return nil, ErrNetworkError
	}

	if !m.hasInstallPrivilege {
		return nil, ErrPermissionDenied
	}

	return m.getAvailablePatchesInternal(patchType), nil
}

// getAvailablePatchesInternal filters the in-memory repository. It does not
// acquire locks and must be called by a holder of m.mu.
func (m *InMemoryPatchManager) getAvailablePatchesInternal(patchType string) []PatchInfo {
	var filtered []PatchInfo
	for _, patch := range m.availablePatches {
		if patchType == "all" ||
			(patchType == "security" && patch.Category == "security") ||
			(patchType == "critical" && patch.Severity == "critical") ||
			(patchType == "kernel" && strings.Contains(strings.ToLower(patch.Title), "kernel")) ||
			(patchType == "feature-update" && patch.Category == "feature-update") {
			filtered = append(filtered, patch)
		}
	}

	return filtered
}

// ListInstalledPatches returns currently installed patches.
func (m *InMemoryPatchManager) ListInstalledPatches(_ context.Context) ([]PatchInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.repositoryReachable {
		return nil, ErrNetworkError
	}

	return m.installedPatches, nil
}

// InstallPatches installs patches from the in-memory repository based on the
// configuration, updating installed state, reboot flags, and last-patch date.
func (m *InMemoryPatchManager) InstallPatches(_ context.Context, config *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.repositoryReachable {
		return ErrNetworkError
	}

	if !m.hasInstallPrivilege {
		return ErrPermissionDenied
	}

	if m.patchingInProgress {
		return ErrPatchingInProgress
	}

	if config.TestMode {
		// Dry run: report success without mutating the installed database.
		return nil
	}

	// Mark patching in progress for the duration of the operation.
	m.patchingInProgress = true
	defer func() { m.patchingInProgress = false }()

	// Resolve the patches to install from the repository (internal call, already locked).
	availablePatches := m.getAvailablePatchesInternal(config.PatchType)

	// Apply include/exclude resolution.
	var patchesToInstall []PatchInfo
	for _, patch := range availablePatches {
		shouldInstall := true

		for _, excludeID := range config.ExcludePatches {
			if patch.ID == excludeID {
				shouldInstall = false
				break
			}
		}

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

	// Apply each patch to the in-memory database.
	for _, patch := range patchesToInstall {
		patch.Installed = true
		m.installedPatches = append(m.installedPatches, patch)

		for i, available := range m.availablePatches {
			if available.ID == patch.ID {
				m.availablePatches = append(m.availablePatches[:i], m.availablePatches[i+1:]...)
				break
			}
		}

		if patch.RebootRequired {
			m.rebootRequired = true
		}
	}

	m.lastPatchDate = time.Now()

	return nil
}

// CheckRebootRequired returns true if a reboot is required after patching.
func (m *InMemoryPatchManager) CheckRebootRequired(_ context.Context) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.rebootRequired, nil
}

// GetLastPatchDate returns the date of the last successful patch operation.
func (m *InMemoryPatchManager) GetLastPatchDate(_ context.Context) (time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.lastPatchDate, nil
}

// Name returns the name of the in-memory patch manager for the current platform.
func (m *InMemoryPatchManager) Name() string {
	switch runtime.GOOS {
	case "linux":
		return "inmemory-apt"
	case "darwin":
		return "inmemory-softwareupdate"
	case "windows":
		return "inmemory-windowsupdate"
	default:
		return "inmemory"
	}
}

// IsValidPatchType checks if the given patch type is valid for this platform.
func (m *InMemoryPatchManager) IsValidPatchType(patchType string) bool {
	return validPatchTypes[patchType]
}

// SetRepositoryReachable controls whether the in-memory repository can be
// contacted. Setting it false drives real ErrNetworkError responses from
// enumeration and installation.
func (m *InMemoryPatchManager) SetRepositoryReachable(reachable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repositoryReachable = reachable
}

// SetInstallPrivilege controls whether the manager may mutate the installed
// database. Setting it false drives real ErrPermissionDenied responses.
func (m *InMemoryPatchManager) SetInstallPrivilege(privileged bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hasInstallPrivilege = privileged
}

// AddAvailablePatch adds a patch to the in-memory repository.
func (m *InMemoryPatchManager) AddAvailablePatch(patch PatchInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.availablePatches = append(m.availablePatches, patch)
}

// SetAvailablePatches replaces the in-memory repository contents.
func (m *InMemoryPatchManager) SetAvailablePatches(patches []PatchInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.availablePatches = patches
}

// SetRebootRequired sets the reboot-required state of the in-memory host.
func (m *InMemoryPatchManager) SetRebootRequired(required bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rebootRequired = required
}
