// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// testPackageManager is a test implementation of PackageManager that stores
// package state in memory. It is a real implementation of the interface
// (suitable for tests) rather than a mock — it correctly tracks install/remove
// state, supports configurable failures, and exercises the full PackageModule
// logic path without calling the OS package manager.
type testPackageManager struct {
	mu              sync.RWMutex
	installed       map[string]string
	failingPackages map[string]bool
	operationDelay  time.Duration
	managerName     string
}

func newTestPackageManager() *testPackageManager {
	return &testPackageManager{
		installed:       make(map[string]string),
		failingPackages: make(map[string]bool),
		managerName:     "test",
	}
}

func (m *testPackageManager) Install(ctx context.Context, name string, version string) error {
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

func (m *testPackageManager) Remove(ctx context.Context, name string) error {
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

func (m *testPackageManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
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

func (m *testPackageManager) ListInstalled(ctx context.Context) (map[string]string, error) {
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

func (m *testPackageManager) setFailingPackage(name string, failing bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failingPackages[name] = failing
}

func (m *testPackageManager) Name() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.managerName
}

func (m *testPackageManager) IsValidManager(name string) bool {
	validManagers := map[string]bool{
		"test":    true,
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
