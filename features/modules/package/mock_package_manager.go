// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockPackageManager implements PackageManager for testing
type MockPackageManager struct {
	mu              sync.RWMutex
	installed       map[string]string
	failingPackages map[string]bool
	operationDelay  time.Duration
	managerName     string
}

// NewMockPackageManager creates a new mock package manager
func NewMockPackageManager() *MockPackageManager {
	return &MockPackageManager{
		installed:       make(map[string]string),
		failingPackages: make(map[string]bool),
		managerName:     "mock",
	}
}

// Install mocks package installation
func (m *MockPackageManager) Install(ctx context.Context, name string, version string) error {
	// Simulate operation delay
	if m.operationDelay > 0 {
		select {
		case <-time.After(m.operationDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failingPackages[name] {
		return fmt.Errorf("failed to install package %s", name)
	}

	m.installed[name] = version
	return nil
}

// Remove mocks package removal
func (m *MockPackageManager) Remove(ctx context.Context, name string) error {
	// Simulate operation delay
	if m.operationDelay > 0 {
		select {
		case <-time.After(m.operationDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failingPackages[name] {
		return fmt.Errorf("failed to remove package %s", name)
	}

	delete(m.installed, name)
	return nil
}

// GetInstalledVersion mocks getting installed package version
func (m *MockPackageManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	// Simulate operation delay
	if m.operationDelay > 0 {
		select {
		case <-time.After(m.operationDelay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if version, ok := m.installed[name]; ok {
		return version, nil
	}
	return "", fmt.Errorf("package %s not installed", name)
}

// ListInstalled mocks listing installed packages
func (m *MockPackageManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	// Simulate operation delay
	if m.operationDelay > 0 {
		select {
		case <-time.After(m.operationDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]string)
	for k, v := range m.installed {
		result[k] = v
	}
	return result, nil
}

// SetFailingPackage sets a package to fail operations
func (m *MockPackageManager) SetFailingPackage(name string, failing bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failingPackages[name] = failing
}

// SetDelay sets the operation delay
func (m *MockPackageManager) SetDelay(delay time.Duration) {
	m.operationDelay = delay
}

// Name returns the name of the mock package manager
func (m *MockPackageManager) Name() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.managerName
}

// IsValidManager checks if the given package manager name is valid
func (m *MockPackageManager) IsValidManager(name string) bool {
	validManagers := map[string]bool{
		"mock":    true,
		"apt":     true,
		"yum":     true,
		"dnf":     true,
		"pacman":  true,
		"brew":    true,
		"winget":  true,
		"choco":   true,
		"default": true,
	}
	return validManagers[name]
}

// SetManager sets the package manager name
func (m *MockPackageManager) SetManager(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.IsValidManager(name) {
		m.managerName = name
	}
}
