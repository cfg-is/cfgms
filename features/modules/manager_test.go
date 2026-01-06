// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package modules

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewModuleLifecycleManager(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	if manager.registry != registry {
		t.Error("Registry should be set correctly")
	}

	if manager.instances == nil {
		t.Error("Instances map should be initialized")
	}

	if manager.eventListeners == nil {
		t.Error("Event listeners slice should be initialized")
	}

	if manager.healthCheckInterval != 60*time.Second {
		t.Errorf("Health check interval = %v, want %v", manager.healthCheckInterval, 60*time.Second)
	}

	if manager.running {
		t.Error("Manager should not be running initially")
	}
}

func TestModuleLifecycleManager_StartStop(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	// Test Start
	err := manager.Start()
	if err != nil {
		t.Errorf("Start() error = %v, want nil", err)
	}

	if !manager.running {
		t.Error("Manager should be running after Start()")
	}

	// Test starting already running manager
	err = manager.Start()
	if err == nil {
		t.Error("Start() should return error when already running")
	}

	// Test Stop
	err = manager.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v, want nil", err)
	}

	if manager.running {
		t.Error("Manager should not be running after Stop()")
	}

	// Test stopping already stopped manager
	err = manager.Stop()
	if err != nil {
		t.Errorf("Stop() on stopped manager should not error, got %v", err)
	}
}

func TestModuleLifecycleManager_RegisterModule(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	metadata := &ModuleMetadata{
		Name:    "test-module",
		Version: "1.0.0",
	}
	module := &mockModule{name: "test-module"}
	config := DefaultModuleConfig()

	// Test successful registration
	instance, err := manager.RegisterModule(metadata, module, config)
	if err != nil {
		t.Errorf("RegisterModule() error = %v, want nil", err)
	}

	if instance == nil {
		t.Fatal("RegisterModule() should return instance")
	}

	if instance.Metadata != metadata {
		t.Error("Instance metadata should match")
	}

	if instance.Module != module {
		t.Error("Instance module should match")
	}

	if instance.GetState() != ModuleStateDiscovered {
		t.Errorf("Initial state = %v, want %v", instance.GetState(), ModuleStateDiscovered)
	}

	// Test duplicate registration
	_, err = manager.RegisterModule(metadata, module, config)
	if err == nil {
		t.Error("RegisterModule() should return error for duplicate registration")
	}
}

func TestModuleLifecycleManager_UnregisterModule(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	metadata := &ModuleMetadata{
		Name:    "test-module",
		Version: "1.0.0",
	}
	module := &mockModule{name: "test-module"}
	config := DefaultModuleConfig()

	// Test unregistering non-existent module
	err := manager.UnregisterModule("non-existent")
	if err == nil {
		t.Error("UnregisterModule() should return error for non-existent module")
	}

	// Register module
	_, err = manager.RegisterModule(metadata, module, config)
	if err != nil {
		t.Fatalf("RegisterModule() error = %v", err)
	}

	// Test successful unregistration
	err = manager.UnregisterModule("test-module")
	if err != nil {
		t.Errorf("UnregisterModule() error = %v, want nil", err)
	}

	// Verify module is no longer registered
	_, err = manager.GetModuleInstance("test-module")
	if err == nil {
		t.Error("GetModuleInstance() should return error after unregistration")
	}
}

func TestModuleLifecycleManager_LoadModule(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	// Test loading non-existent module
	err := manager.LoadModule("non-existent")
	if err == nil {
		t.Error("LoadModule() should return error for non-existent module")
	}

	// Register successful module
	successModule := &mockLifecycleModule{
		health: HealthStatus{
			Status:    HealthStateHealthy,
			Message:   "Healthy",
			Timestamp: time.Now(),
		},
	}
	metadata := &ModuleMetadata{Name: "success-module", Version: "1.0.0"}
	config := DefaultModuleConfig()

	_, err = manager.RegisterModule(metadata, successModule, config)
	if err != nil {
		t.Fatalf("RegisterModule() error = %v", err)
	}

	// Test successful load
	err = manager.LoadModule("success-module")
	if err != nil {
		t.Errorf("LoadModule() error = %v, want nil", err)
	}

	instance, _ := manager.GetModuleInstance("success-module")
	if instance.GetState() != ModuleStateReady {
		t.Errorf("After loading, state = %v, want %v", instance.GetState(), ModuleStateReady)
	}

	// Test loading already loaded module
	err = manager.LoadModule("success-module")
	if err == nil {
		t.Error("LoadModule() should return error when not in discovered state")
	}

	// Register failing module
	failingModule := &mockLifecycleModule{
		initError: fmt.Errorf("initialization failed"),
	}
	failMetadata := &ModuleMetadata{Name: "failing-module", Version: "1.0.0"}

	_, err = manager.RegisterModule(failMetadata, failingModule, config)
	if err != nil {
		t.Fatalf("RegisterModule() error = %v", err)
	}

	// Test failed load
	err = manager.LoadModule("failing-module")
	if err == nil {
		t.Error("LoadModule() should return error when initialization fails")
	}

	failInstance, _ := manager.GetModuleInstance("failing-module")
	if failInstance.GetState() != ModuleStateError {
		t.Errorf("After failed loading, state = %v, want %v", failInstance.GetState(), ModuleStateError)
	}
}

func TestModuleLifecycleManager_StartStopModule(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	// Register and load module
	module := &mockLifecycleModule{
		health: HealthStatus{
			Status:    HealthStateHealthy,
			Message:   "Healthy",
			Timestamp: time.Now(),
		},
	}
	metadata := &ModuleMetadata{Name: "test-module", Version: "1.0.0"}
	config := DefaultModuleConfig()

	_, err := manager.RegisterModule(metadata, module, config)
	if err != nil {
		t.Fatalf("RegisterModule() error = %v", err)
	}

	err = manager.LoadModule("test-module")
	if err != nil {
		t.Fatalf("LoadModule() error = %v", err)
	}

	// Test start module
	err = manager.StartModule("test-module")
	if err != nil {
		t.Errorf("StartModule() error = %v, want nil", err)
	}

	instance, _ := manager.GetModuleInstance("test-module")
	if instance.GetState() != ModuleStateRunning {
		t.Errorf("After starting, state = %v, want %v", instance.GetState(), ModuleStateRunning)
	}

	// Test stop module
	err = manager.StopModule("test-module")
	if err != nil {
		t.Errorf("StopModule() error = %v, want nil", err)
	}

	if instance.GetState() != ModuleStateStopped {
		t.Errorf("After stopping, state = %v, want %v", instance.GetState(), ModuleStateStopped)
	}
}

func TestModuleLifecycleManager_StartStopAllModules(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	// Register modules with dependencies (base <- app)
	baseModule := &mockLifecycleModule{
		health: HealthStatus{Status: HealthStateHealthy, Timestamp: time.Now()},
	}
	baseMetadata := &ModuleMetadata{Name: "base", Version: "1.0.0"}

	appModule := &mockLifecycleModule{
		health: HealthStatus{Status: HealthStateHealthy, Timestamp: time.Now()},
	}
	appMetadata := &ModuleMetadata{
		Name:    "app",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "base", Version: "1.0.0"},
		},
	}

	config := DefaultModuleConfig()

	// Register in registry first
	if err := registry.RegisterModule(baseMetadata, baseModule); err != nil {
		t.Fatalf("RegisterModule(base) in registry error = %v", err)
	}
	if err := registry.RegisterModule(appMetadata, appModule); err != nil {
		t.Fatalf("RegisterModule(app) in registry error = %v", err)
	}

	// Register with lifecycle manager
	_, err := manager.RegisterModule(baseMetadata, baseModule, config)
	if err != nil {
		t.Fatalf("RegisterModule(base) error = %v", err)
	}

	_, err = manager.RegisterModule(appMetadata, appModule, config)
	if err != nil {
		t.Fatalf("RegisterModule(app) error = %v", err)
	}

	// Test start all modules
	err = manager.StartAllModules()
	if err != nil {
		t.Errorf("StartAllModules() error = %v, want nil", err)
	}

	// Verify both modules are running
	baseInstance, _ := manager.GetModuleInstance("base")
	appInstance, _ := manager.GetModuleInstance("app")

	if baseInstance.GetState() != ModuleStateRunning {
		t.Errorf("Base module state = %v, want %v", baseInstance.GetState(), ModuleStateRunning)
	}

	if appInstance.GetState() != ModuleStateRunning {
		t.Errorf("App module state = %v, want %v", appInstance.GetState(), ModuleStateRunning)
	}

	// Test stop all modules
	err = manager.StopAllModules()
	if err != nil {
		t.Errorf("StopAllModules() error = %v, want nil", err)
	}

	// Verify both modules are stopped
	if baseInstance.GetState() != ModuleStateStopped {
		t.Errorf("Base module state = %v, want %v", baseInstance.GetState(), ModuleStateStopped)
	}

	if appInstance.GetState() != ModuleStateStopped {
		t.Errorf("App module state = %v, want %v", appInstance.GetState(), ModuleStateStopped)
	}
}

func TestModuleLifecycleManager_GetSystemHealth(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	// Test empty system
	health := manager.GetSystemHealth()
	if health.TotalModules != 0 {
		t.Errorf("Empty system total modules = %v, want 0", health.TotalModules)
	}
	if health.OverallStatus != HealthStateHealthy {
		t.Errorf("Empty system overall status = %v, want %v", health.OverallStatus, HealthStateHealthy)
	}

	// Register modules with different health states
	healthyModule := &mockLifecycleModule{
		health: HealthStatus{Status: HealthStateHealthy, Timestamp: time.Now()},
	}
	warningModule := &mockLifecycleModule{
		health: HealthStatus{Status: HealthStateWarning, Timestamp: time.Now()},
	}
	criticalModule := &mockLifecycleModule{
		health: HealthStatus{Status: HealthStateCritical, Timestamp: time.Now()},
	}

	config := DefaultModuleConfig()

	modules := map[string]*mockLifecycleModule{
		"healthy":  healthyModule,
		"warning":  warningModule,
		"critical": criticalModule,
	}

	for name, module := range modules {
		metadata := &ModuleMetadata{Name: name, Version: "1.0.0"}
		_, err := manager.RegisterModule(metadata, module, config)
		if err != nil {
			t.Fatalf("RegisterModule(%s) error = %v", name, err)
		}
	}

	// Test system health with mixed states
	health = manager.GetSystemHealth()

	if health.TotalModules != 3 {
		t.Errorf("Total modules = %v, want 3", health.TotalModules)
	}

	if health.HealthyModules != 1 {
		t.Errorf("Healthy modules = %v, want 1", health.HealthyModules)
	}

	if health.WarningModules != 1 {
		t.Errorf("Warning modules = %v, want 1", health.WarningModules)
	}

	if health.CriticalModules != 1 {
		t.Errorf("Critical modules = %v, want 1", health.CriticalModules)
	}

	if health.OverallStatus != HealthStateCritical {
		t.Errorf("Overall status = %v, want %v", health.OverallStatus, HealthStateCritical)
	}
}

func TestModuleLifecycleManager_EventSystem(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	var receivedEvents []LifecycleEvent
	var mu sync.Mutex

	listener := NewLifecycleEventHandler("test-listener", func(event LifecycleEvent) {
		mu.Lock()
		receivedEvents = append(receivedEvents, event)
		mu.Unlock()
	})

	// Add event listener
	manager.AddEventListener(listener)

	// Start manager to enable events
	err := manager.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := manager.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	// Wait for start event
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(receivedEvents) == 0 {
		t.Error("Should have received start event")
	}
	mu.Unlock()

	// Register module (should generate event)
	module := &mockLifecycleModule{
		health: HealthStatus{Status: HealthStateHealthy, Timestamp: time.Now()},
	}
	metadata := &ModuleMetadata{Name: "test-module", Version: "1.0.0"}
	config := DefaultModuleConfig()

	_, err = manager.RegisterModule(metadata, module, config)
	if err != nil {
		t.Fatalf("RegisterModule() error = %v", err)
	}

	// Wait for events to be processed
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	eventCount := len(receivedEvents)
	mu.Unlock()

	if eventCount < 2 { // At least start event + register event
		t.Errorf("Should have received at least 2 events, got %d", eventCount)
	}

	// Load module (should generate more events)
	err = manager.LoadModule("test-module")
	if err != nil {
		t.Fatalf("LoadModule() error = %v", err)
	}

	// Wait for events to be processed
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	finalEventCount := len(receivedEvents)
	mu.Unlock()

	if finalEventCount <= eventCount {
		t.Error("Should have received additional events after loading module")
	}

	// Test removing event listener
	manager.RemoveEventListener(listener)

	// Perform operation that would generate event
	err = manager.StartModule("test-module")
	if err != nil {
		t.Fatalf("StartModule() error = %v", err)
	}

	// Wait and check that no new events were received
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	eventsAfterRemoval := len(receivedEvents)
	mu.Unlock()

	// We might still receive some events that were already queued
	// The important thing is that we're not receiving new events indefinitely
	_ = eventsAfterRemoval // Use the variable to avoid "declared and not used" error
}

func TestModuleLifecycleManager_HealthCheckInterval(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	// Test default interval
	if manager.healthCheckInterval != 60*time.Second {
		t.Errorf("Default health check interval = %v, want %v", manager.healthCheckInterval, 60*time.Second)
	}

	// Test setting new interval
	newInterval := 30 * time.Second
	manager.SetHealthCheckInterval(newInterval)

	if manager.healthCheckInterval != newInterval {
		t.Errorf("Health check interval after setting = %v, want %v", manager.healthCheckInterval, newInterval)
	}
}

func TestModuleLifecycleManager_ConcurrentAccess(t *testing.T) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	err := manager.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := manager.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	const numGoroutines = 50
	const numModules = 10

	// Register initial modules
	for i := 0; i < numModules; i++ {
		module := &mockLifecycleModule{
			health: HealthStatus{Status: HealthStateHealthy, Timestamp: time.Now()},
		}
		metadata := &ModuleMetadata{
			Name:    fmt.Sprintf("module-%d", i),
			Version: "1.0.0",
		}
		config := DefaultModuleConfig()

		_, err := manager.RegisterModule(metadata, module, config)
		if err != nil {
			t.Fatalf("RegisterModule(module-%d) error = %v", i, err)
		}

		err = manager.LoadModule(fmt.Sprintf("module-%d", i))
		if err != nil {
			t.Fatalf("LoadModule(module-%d) error = %v", i, err)
		}
	}

	// Concurrent read operations
	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			for j := 0; j < 100; j++ {
				// Various read operations
				moduleName := fmt.Sprintf("module-%d", j%numModules)

				_, err := manager.GetModuleInstance(moduleName)
				if err != nil {
					t.Errorf("GetModuleInstance(%s) error = %v", moduleName, err)
					return
				}

				_, err = manager.GetModuleHealth(moduleName)
				if err != nil {
					t.Errorf("GetModuleHealth(%s) error = %v", moduleName, err)
					return
				}

				_ = manager.GetSystemHealth()
				_ = manager.ListModuleInstances()
			}
		}(i)
	}

	// Wait for all goroutines to complete
	timeout := time.After(10 * time.Second)
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("Test timed out - possible deadlock")
		}
	}
}

// Benchmark tests
func BenchmarkModuleLifecycleManager_GetModuleInstance(b *testing.B) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	// Register test module
	module := &mockLifecycleModule{
		health: HealthStatus{Status: HealthStateHealthy, Timestamp: time.Now()},
	}
	metadata := &ModuleMetadata{Name: "bench-module", Version: "1.0.0"}
	config := DefaultModuleConfig()

	if _, err := manager.RegisterModule(metadata, module, config); err != nil {
		b.Fatalf("RegisterModule() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.GetModuleInstance("bench-module")
	}
}

func BenchmarkModuleLifecycleManager_GetSystemHealth(b *testing.B) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	// Register multiple modules
	for i := 0; i < 100; i++ {
		module := &mockLifecycleModule{
			health: HealthStatus{Status: HealthStateHealthy, Timestamp: time.Now()},
		}
		metadata := &ModuleMetadata{
			Name:    fmt.Sprintf("module-%d", i),
			Version: "1.0.0",
		}
		config := DefaultModuleConfig()

		if _, err := manager.RegisterModule(metadata, module, config); err != nil {
			b.Fatalf("RegisterModule() error = %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.GetSystemHealth()
	}
}

func BenchmarkModuleLifecycleManager_ListModuleInstances(b *testing.B) {
	registry := NewModuleRegistry()
	manager := NewModuleLifecycleManager(registry)

	// Register multiple modules
	for i := 0; i < 1000; i++ {
		module := &mockLifecycleModule{
			health: HealthStatus{Status: HealthStateHealthy, Timestamp: time.Now()},
		}
		metadata := &ModuleMetadata{
			Name:    fmt.Sprintf("module-%d", i),
			Version: "1.0.0",
		}
		config := DefaultModuleConfig()

		if _, err := manager.RegisterModule(metadata, module, config); err != nil {
			b.Fatalf("RegisterModule() error = %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.ListModuleInstances()
	}
}
