// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package testing

import (
	"context"
	"sync"
)

// MockModule provides a mock implementation of a module for testing
type MockModule struct {
	mu sync.Mutex

	name     string
	getFunc  func(ctx context.Context, resourceID string) (string, error)
	setFunc  func(ctx context.Context, resourceID string, configData string) error
	testFunc func(ctx context.Context, resourceID string, configData string) (bool, error)

	// Record calls for verification
	GetCalls  []GetCall
	SetCalls  []SetCall
	TestCalls []TestCall
}

// GetCall records parameters for a Get call
type GetCall struct {
	ResourceID string
	Result     string
	Error      error
}

// SetCall records parameters for a Set call
type SetCall struct {
	ResourceID string
	ConfigData string
	Error      error
}

// TestCall records parameters for a Test call
type TestCall struct {
	ResourceID string
	ConfigData string
	Result     bool
	Error      error
}

// NewMockModule creates a new mock module
func NewMockModule(name string) *MockModule {
	return &MockModule{
		name:      name,
		GetCalls:  []GetCall{},
		SetCalls:  []SetCall{},
		TestCalls: []TestCall{},
	}
}

// Name returns the module name
func (m *MockModule) Name() string {
	return m.name
}

// Get returns the current state of the resource
func (m *MockModule) Get(ctx context.Context, resourceID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.getFunc != nil {
		result, err := m.getFunc(ctx, resourceID)
		m.GetCalls = append(m.GetCalls, GetCall{
			ResourceID: resourceID,
			Result:     result,
			Error:      err,
		})
		return result, err
	}

	// Default implementation returns empty config
	result := ""
	m.GetCalls = append(m.GetCalls, GetCall{
		ResourceID: resourceID,
		Result:     result,
		Error:      nil,
	})
	return result, nil
}

// Set applies the configuration to the resource
func (m *MockModule) Set(ctx context.Context, resourceID string, configData string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.setFunc != nil {
		err := m.setFunc(ctx, resourceID, configData)
		m.SetCalls = append(m.SetCalls, SetCall{
			ResourceID: resourceID,
			ConfigData: configData,
			Error:      err,
		})
		return err
	}

	// Default implementation just records the call
	m.SetCalls = append(m.SetCalls, SetCall{
		ResourceID: resourceID,
		ConfigData: configData,
		Error:      nil,
	})
	return nil
}

// Test validates if the current state matches the desired state
func (m *MockModule) Test(ctx context.Context, resourceID string, configData string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.testFunc != nil {
		result, err := m.testFunc(ctx, resourceID, configData)
		m.TestCalls = append(m.TestCalls, TestCall{
			ResourceID: resourceID,
			ConfigData: configData,
			Result:     result,
			Error:      err,
		})
		return result, err
	}

	// Default implementation returns true (passing test)
	m.TestCalls = append(m.TestCalls, TestCall{
		ResourceID: resourceID,
		ConfigData: configData,
		Result:     true,
		Error:      nil,
	})
	return true, nil
}

// SetGetFunc sets a custom function for Get
func (m *MockModule) SetGetFunc(fn func(ctx context.Context, resourceID string) (string, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getFunc = fn
}

// SetSetFunc sets a custom function for Set
func (m *MockModule) SetSetFunc(fn func(ctx context.Context, resourceID string, configData string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setFunc = fn
}

// SetTestFunc sets a custom function for Test
func (m *MockModule) SetTestFunc(fn func(ctx context.Context, resourceID string, configData string) (bool, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.testFunc = fn
}

// Reset clears all call records
func (m *MockModule) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.GetCalls = []GetCall{}
	m.SetCalls = []SetCall{}
	m.TestCalls = []TestCall{}
}
