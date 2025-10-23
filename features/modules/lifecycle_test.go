// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package modules

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestModuleState_String(t *testing.T) {
	tests := []struct {
		state    ModuleState
		expected string
	}{
		{ModuleStateUnknown, "Unknown"},
		{ModuleStateDiscovered, "Discovered"},
		{ModuleStateLoading, "Loading"},
		{ModuleStateInitializing, "Initializing"},
		{ModuleStateReady, "Ready"},
		{ModuleStateStarting, "Starting"},
		{ModuleStateRunning, "Running"},
		{ModuleStateStopping, "Stopping"},
		{ModuleStateStopped, "Stopped"},
		{ModuleStateError, "Error"},
		{ModuleStateFailed, "Failed"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("ModuleState.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestModuleState_IsTerminalState(t *testing.T) {
	tests := []struct {
		state      ModuleState
		isTerminal bool
	}{
		{ModuleStateUnknown, false},
		{ModuleStateDiscovered, false},
		{ModuleStateLoading, false},
		{ModuleStateInitializing, false},
		{ModuleStateReady, false},
		{ModuleStateStarting, false},
		{ModuleStateRunning, false},
		{ModuleStateStopping, false},
		{ModuleStateStopped, true},
		{ModuleStateError, false},
		{ModuleStateFailed, true},
	}

	for _, tt := range tests {
		t.Run(tt.state.String(), func(t *testing.T) {
			if got := tt.state.IsTerminalState(); got != tt.isTerminal {
				t.Errorf("ModuleState.IsTerminalState() = %v, want %v", got, tt.isTerminal)
			}
		})
	}
}

func TestModuleState_IsErrorState(t *testing.T) {
	tests := []struct {
		state   ModuleState
		isError bool
	}{
		{ModuleStateUnknown, false},
		{ModuleStateDiscovered, false},
		{ModuleStateLoading, false},
		{ModuleStateInitializing, false},
		{ModuleStateReady, false},
		{ModuleStateStarting, false},
		{ModuleStateRunning, false},
		{ModuleStateStopping, false},
		{ModuleStateStopped, false},
		{ModuleStateError, true},
		{ModuleStateFailed, true},
	}

	for _, tt := range tests {
		t.Run(tt.state.String(), func(t *testing.T) {
			if got := tt.state.IsErrorState(); got != tt.isError {
				t.Errorf("ModuleState.IsErrorState() = %v, want %v", got, tt.isError)
			}
		})
	}
}

func TestHealthState_String(t *testing.T) {
	tests := []struct {
		state    HealthState
		expected string
	}{
		{HealthStateUnknown, "Unknown"},
		{HealthStateHealthy, "Healthy"},
		{HealthStateWarning, "Warning"},
		{HealthStateUnhealthy, "Unhealthy"},
		{HealthStateCritical, "Critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("HealthState.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDefaultModuleConfig(t *testing.T) {
	config := DefaultModuleConfig()

	if config.InitializationTimeout != 30*time.Second {
		t.Errorf("InitializationTimeout = %v, want %v", config.InitializationTimeout, 30*time.Second)
	}

	if config.StartupTimeout != 30*time.Second {
		t.Errorf("StartupTimeout = %v, want %v", config.StartupTimeout, 30*time.Second)
	}

	if config.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want %v", config.ShutdownTimeout, 30*time.Second)
	}

	if config.HealthCheckInterval != 60*time.Second {
		t.Errorf("HealthCheckInterval = %v, want %v", config.HealthCheckInterval, 60*time.Second)
	}

	if config.MaxRetries != 3 {
		t.Errorf("MaxRetries = %v, want %v", config.MaxRetries, 3)
	}

	if config.RetryDelay != 5*time.Second {
		t.Errorf("RetryDelay = %v, want %v", config.RetryDelay, 5*time.Second)
	}

	if config.Settings == nil {
		t.Error("Settings should be initialized")
	}
}

func TestModuleInstance_StateOperations(t *testing.T) {
	instance := &ModuleInstance{
		State: ModuleStateDiscovered,
	}

	// Test GetState
	if state := instance.GetState(); state != ModuleStateDiscovered {
		t.Errorf("GetState() = %v, want %v", state, ModuleStateDiscovered)
	}

	// Test SetState
	instance.SetState(ModuleStateLoading)
	if state := instance.GetState(); state != ModuleStateLoading {
		t.Errorf("After SetState, GetState() = %v, want %v", state, ModuleStateLoading)
	}

	// Test that LastStateChange is updated
	oldTime := instance.LastStateChange
	time.Sleep(1 * time.Millisecond) // Ensure time difference
	instance.SetState(ModuleStateReady)
	if !instance.LastStateChange.After(oldTime) {
		t.Error("LastStateChange should be updated when state changes")
	}

	// Test setting same state doesn't change timestamp
	sameStateTime := instance.LastStateChange
	instance.SetState(ModuleStateReady)
	if !instance.LastStateChange.Equal(sameStateTime) {
		t.Error("LastStateChange should not change when setting same state")
	}
}

func TestModuleInstance_HealthOperations(t *testing.T) {
	health := HealthStatus{
		Status:    HealthStateHealthy,
		Message:   "All good",
		Timestamp: time.Now(),
	}

	instance := &ModuleInstance{
		Health: health,
	}

	// Test GetHealth
	if got := instance.GetHealth(); got.Status != health.Status {
		t.Errorf("GetHealth().Status = %v, want %v", got.Status, health.Status)
	}

	// Test SetHealth
	newHealth := HealthStatus{
		Status:    HealthStateWarning,
		Message:   "Some issues",
		Timestamp: time.Now(),
	}

	instance.SetHealth(newHealth)
	if got := instance.GetHealth(); got.Status != newHealth.Status {
		t.Errorf("After SetHealth, GetHealth().Status = %v, want %v", got.Status, newHealth.Status)
	}
}

func TestModuleInstance_ErrorOperations(t *testing.T) {
	instance := &ModuleInstance{}

	// Test initial state
	count, err := instance.GetErrorInfo()
	if count != 0 {
		t.Errorf("Initial error count = %v, want 0", count)
	}
	if err != nil {
		t.Errorf("Initial error = %v, want nil", err)
	}

	// Test IncrementErrorCount
	testErr := fmt.Errorf("test error")
	instance.IncrementErrorCount(testErr)

	count, err = instance.GetErrorInfo()
	if count != 1 {
		t.Errorf("Error count after increment = %v, want 1", count)
	}
	if err != testErr {
		t.Errorf("Last error = %v, want %v", err, testErr)
	}

	// Test multiple increments
	secondErr := fmt.Errorf("second error")
	instance.IncrementErrorCount(secondErr)

	count, err = instance.GetErrorInfo()
	if count != 2 {
		t.Errorf("Error count after second increment = %v, want 2", count)
	}
	if err != secondErr {
		t.Errorf("Last error = %v, want %v", err, secondErr)
	}
}

func TestLifecycleEventType_String(t *testing.T) {
	tests := []struct {
		eventType LifecycleEventType
		expected  string
	}{
		{EventTypeStateChange, "StateChange"},
		{EventTypeHealthChange, "HealthChange"},
		{EventTypeError, "Error"},
		{EventTypeWarning, "Warning"},
		{EventTypeInfo, "Info"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.eventType.String(); got != tt.expected {
				t.Errorf("LifecycleEventType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Mock module for testing lifecycle operations
type mockLifecycleModule struct {
	initError     error
	startError    error
	stopError     error
	shutdownError error
	health        HealthStatus
}

func (m *mockLifecycleModule) Get(ctx context.Context, resourceID string) (ConfigState, error) {
	return &mockConfigState{data: map[string]interface{}{"id": resourceID}}, nil
}

func (m *mockLifecycleModule) Set(ctx context.Context, resourceID string, config ConfigState) error {
	return nil
}

func (m *mockLifecycleModule) Initialize(ctx context.Context, config ModuleConfig) error {
	return m.initError
}

func (m *mockLifecycleModule) Start(ctx context.Context) error {
	return m.startError
}

func (m *mockLifecycleModule) Stop(ctx context.Context) error {
	return m.stopError
}

func (m *mockLifecycleModule) Shutdown(ctx context.Context) error {
	return m.shutdownError
}

func (m *mockLifecycleModule) Health() HealthStatus {
	return m.health
}

func TestDefaultLifecycleImplementation(t *testing.T) {
	module := &mockModule{name: "test"}
	lifecycle := NewDefaultLifecycleImplementation(module)

	ctx := context.Background()
	config := DefaultModuleConfig()

	// Test Initialize
	if err := lifecycle.Initialize(ctx, config); err != nil {
		t.Errorf("Initialize() error = %v, want nil", err)
	}

	// Test Start
	if err := lifecycle.Start(ctx); err != nil {
		t.Errorf("Start() error = %v, want nil", err)
	}

	// Test Stop
	if err := lifecycle.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v, want nil", err)
	}

	// Test Shutdown
	if err := lifecycle.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error = %v, want nil", err)
	}

	// Test Health
	health := lifecycle.Health()
	if health.Status != HealthStateHealthy {
		t.Errorf("Health().Status = %v, want %v", health.Status, HealthStateHealthy)
	}
}

func TestLifecycleOperationError(t *testing.T) {
	cause := fmt.Errorf("underlying error")
	err := NewLifecycleOperationError("test-module", "initialize", ModuleStateInitializing, cause)

	expectedMsg := "lifecycle operation 'initialize' failed for module 'test-module' in state 'Initializing': underlying error"
	if err.Error() != expectedMsg {
		t.Errorf("Error() = %v, want %v", err.Error(), expectedMsg)
	}

	if err.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
	}

	if err.Module != "test-module" {
		t.Errorf("Module = %v, want %v", err.Module, "test-module")
	}

	if err.Operation != "initialize" {
		t.Errorf("Operation = %v, want %v", err.Operation, "initialize")
	}

	if err.State != ModuleStateInitializing {
		t.Errorf("State = %v, want %v", err.State, ModuleStateInitializing)
	}
}

func TestLifecycleEventHandler(t *testing.T) {
	var receivedEvent LifecycleEvent
	handler := NewLifecycleEventHandler("test-handler", func(event LifecycleEvent) {
		receivedEvent = event
	})

	testEvent := LifecycleEvent{
		Type:      EventTypeInfo,
		Module:    "test-module",
		Message:   "test message",
		Timestamp: time.Now(),
	}

	handler.OnLifecycleEvent(testEvent)

	if receivedEvent.Type != testEvent.Type {
		t.Errorf("Handler received event type = %v, want %v", receivedEvent.Type, testEvent.Type)
	}

	if receivedEvent.Module != testEvent.Module {
		t.Errorf("Handler received module = %v, want %v", receivedEvent.Module, testEvent.Module)
	}

	if receivedEvent.Message != testEvent.Message {
		t.Errorf("Handler received message = %v, want %v", receivedEvent.Message, testEvent.Message)
	}

	// Test GetID
	if handler.GetID() != "test-handler" {
		t.Errorf("Handler GetID() = %v, want test-handler", handler.GetID())
	}
}

// Benchmark tests
func BenchmarkModuleInstance_GetState(b *testing.B) {
	instance := &ModuleInstance{State: ModuleStateRunning}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = instance.GetState()
	}
}

func BenchmarkModuleInstance_SetState(b *testing.B) {
	instance := &ModuleInstance{State: ModuleStateDiscovered}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		instance.SetState(ModuleState(i % 11)) // Cycle through states
	}
}

func BenchmarkDefaultLifecycleImplementation_Health(b *testing.B) {
	module := &mockModule{name: "benchmark"}
	lifecycle := NewDefaultLifecycleImplementation(module)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lifecycle.Health()
	}
}

// Test concurrent access to ModuleInstance
func TestModuleInstance_ConcurrentAccess(t *testing.T) {
	instance := &ModuleInstance{
		State: ModuleStateDiscovered,
		Health: HealthStatus{
			Status:    HealthStateHealthy,
			Timestamp: time.Now(),
		},
	}

	const numGoroutines = 100
	const numOperations = 100

	// Test concurrent state operations
	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			for j := 0; j < numOperations; j++ {
				// Alternate between reading and writing
				if j%2 == 0 {
					_ = instance.GetState()
				} else {
					instance.SetState(ModuleState(j % 11))
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	timeout := time.After(5 * time.Second)
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("Test timed out - possible deadlock")
		}
	}
}
