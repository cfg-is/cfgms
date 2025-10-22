package modules

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/steward/discovery"
)

// mockModuleLoader implements ModuleLoader for testing
type mockModuleLoader struct {
	modules map[string]Module
	errors  map[string]error
}

func newMockModuleLoader() *mockModuleLoader {
	return &mockModuleLoader{
		modules: make(map[string]Module),
		errors:  make(map[string]error),
	}
}

func (ml *mockModuleLoader) LoadModule(moduleName string) (Module, error) {
	if err, exists := ml.errors[moduleName]; exists {
		return nil, err
	}
	if module, exists := ml.modules[moduleName]; exists {
		return module, nil
	}
	return nil, fmt.Errorf("module not found: %s", moduleName)
}

func (ml *mockModuleLoader) UnloadModule(moduleName string) {
	delete(ml.modules, moduleName)
}

func (ml *mockModuleLoader) UnloadAllModules() {
	ml.modules = make(map[string]Module)
}

func (ml *mockModuleLoader) ValidateModuleInterface(module interface{}) error {
	if _, ok := module.(Module); !ok {
		return fmt.Errorf("module does not implement Module interface")
	}
	return nil
}

func (ml *mockModuleLoader) GetModuleInfo(moduleName string) (discovery.ModuleInfo, bool) {
	return discovery.ModuleInfo{}, false
}

func TestNewLifecycleAwareModuleFactory(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	if factory == nil {
		t.Fatal("NewLifecycleAwareModuleFactory() should return non-nil factory")
	}

	if factory.loader == nil {
		t.Error("Underlying loader should be initialized")
	}

	if factory.lifecycleManager == nil {
		t.Error("Lifecycle manager should be initialized")
	}

	if factory.registry != moduleRegistry {
		t.Error("Registry should be set correctly")
	}
}

func TestLifecycleAwareModuleFactory_StartStop(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	// Test Start
	err := factory.Start()
	if err != nil {
		t.Errorf("Start() error = %v, want nil", err)
	}

	// Test Stop
	err = factory.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v, want nil", err)
	}
}

func TestLifecycleAwareModuleFactory_LoadModule(t *testing.T) {
	discoveryRegistry := discovery.ModuleRegistry{
		"test-module": discovery.ModuleInfo{
			Name: "test-module",
			Path: "/test/path",
		},
	}

	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	err := factory.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	// Test loading non-existent module
	_, err = factory.LoadModule("non-existent")
	if err == nil {
		t.Error("LoadModule() should return error for non-existent module")
	}

	// Note: Testing actual module loading would require setting up the built-in
	// module registry in the underlying factory, which is complex for this test.
	// In practice, this would be tested with integration tests.
}

func TestLifecycleAwareModuleFactory_LoadModuleWithConfig(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	err := factory.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	moduleConfig := ModuleConfig{
		InitializationTimeout: 10 * time.Second,
		StartupTimeout:        10 * time.Second,
		ShutdownTimeout:       10 * time.Second,
	}

	// Test with custom config
	_, err = factory.LoadModuleWithConfig("non-existent", moduleConfig)
	if err == nil {
		t.Error("LoadModuleWithConfig() should return error for non-existent module")
	}
}

func TestLifecycleAwareModuleFactory_ModuleOperations(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	err := factory.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	// Test operations on non-existent module
	err = factory.StartModule("non-existent")
	if err == nil {
		t.Error("StartModule() should return error for non-existent module")
	}

	err = factory.StopModule("non-existent")
	if err == nil {
		t.Error("StopModule() should return error for non-existent module")
	}

	_, err = factory.GetModule("non-existent")
	if err == nil {
		t.Error("GetModule() should return error for non-existent module")
	}

	_, err = factory.GetModuleInstance("non-existent")
	if err == nil {
		t.Error("GetModuleInstance() should return error for non-existent module")
	}

	_, err = factory.GetModuleState("non-existent")
	if err == nil {
		t.Error("GetModuleState() should return error for non-existent module")
	}

	_, err = factory.GetModuleHealth("non-existent")
	if err == nil {
		t.Error("GetModuleHealth() should return error for non-existent module")
	}
}

func TestLifecycleAwareModuleFactory_ListModules(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	err := factory.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	// Test empty list
	modules := factory.ListModules()
	if len(modules) != 0 {
		t.Errorf("ListModules() should return empty slice, got %d modules", len(modules))
	}
}

func TestLifecycleAwareModuleFactory_GetSystemHealth(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	err := factory.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	health := factory.GetSystemHealth()

	if health.TotalModules != 0 {
		t.Errorf("GetSystemHealth().TotalModules = %v, want 0", health.TotalModules)
	}

	if health.OverallStatus != HealthStateHealthy {
		t.Errorf("GetSystemHealth().OverallStatus = %v, want %v", health.OverallStatus, HealthStateHealthy)
	}
}

func TestLifecycleAwareModuleFactory_EventSystem(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	var receivedEvents []LifecycleEvent
	var mu sync.Mutex
	listener := NewLifecycleEventHandler("test-listener", func(event LifecycleEvent) {
		mu.Lock()
		receivedEvents = append(receivedEvents, event)
		mu.Unlock()
	})

	// Add event listener
	factory.AddEventListener(listener)

	err := factory.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	// Wait for start event
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	eventCount := len(receivedEvents)
	mu.Unlock()

	if eventCount == 0 {
		t.Error("Should have received at least one event after starting")
	}

	// Remove event listener
	factory.RemoveEventListener(listener)
}

func TestLifecycleAwareModuleFactory_Configuration(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	// Test default configuration
	defaultConfig := factory.GetDefaultConfig()
	expectedDefault := DefaultModuleConfig()

	if defaultConfig.InitializationTimeout != expectedDefault.InitializationTimeout {
		t.Errorf("Default InitializationTimeout = %v, want %v", defaultConfig.InitializationTimeout, expectedDefault.InitializationTimeout)
	}

	// Test setting custom configuration
	customModuleConfig := ModuleConfig{
		InitializationTimeout: 15 * time.Second,
		StartupTimeout:        15 * time.Second,
		ShutdownTimeout:       15 * time.Second,
		HealthCheckInterval:   30 * time.Second,
		MaxRetries:            5,
		RetryDelay:            2 * time.Second,
		Settings:              make(map[string]interface{}),
	}

	factory.SetDefaultConfig(customModuleConfig)

	retrievedConfig := factory.GetDefaultConfig()
	if retrievedConfig.InitializationTimeout != customModuleConfig.InitializationTimeout {
		t.Errorf("After setting custom config, InitializationTimeout = %v, want %v", retrievedConfig.InitializationTimeout, customModuleConfig.InitializationTimeout)
	}

	// Test setting health check interval
	newInterval := 45 * time.Second
	factory.SetHealthCheckInterval(newInterval)
}

func TestLifecycleAwareModuleFactory_UnloadModule(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	err := factory.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	// Test unloading non-existent module
	err = factory.UnloadModule("non-existent")
	if err == nil {
		t.Error("UnloadModule() should return error for non-existent module")
	}
}

func TestLifecycleAwareModuleFactory_Shutdown(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	err := factory.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	ctx := context.Background()
	err = factory.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v, want nil", err)
	}
}

func TestModuleFactoryBridge(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	lifecycleFactory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)
	bridge := NewModuleFactoryBridge(lifecycleFactory)

	// Test bridge methods
	_, err := bridge.LoadModule("non-existent")
	if err == nil {
		t.Error("Bridge LoadModule() should return error for non-existent module")
	}

	_, err = bridge.CreateModuleInstance("non-existent")
	if err == nil {
		t.Error("Bridge CreateModuleInstance() should return error for non-existent module")
	}

	modules := bridge.GetLoadedModules()
	if len(modules) != 0 {
		t.Errorf("Bridge GetLoadedModules() should return empty slice, got %d", len(modules))
	}

	// Test that UnloadModule and UnloadAllModules don't panic
	bridge.UnloadModule("non-existent")
	bridge.UnloadAllModules()

	// Test ValidateModuleInterface
	err = bridge.ValidateModuleInterface(&mockModule{})
	if err != nil {
		t.Errorf("ValidateModuleInterface() error = %v, want nil", err)
	}

	// Test GetModuleInfo
	_, exists := bridge.GetModuleInfo("non-existent")
	if exists {
		t.Error("GetModuleInfo() should return false for non-existent module")
	}

	// Test GetLifecycleFactory
	retrievedFactory := bridge.GetLifecycleFactory()
	if retrievedFactory != lifecycleFactory {
		t.Error("GetLifecycleFactory() should return the original factory")
	}
}

// Integration test with actual module operations
func TestLifecycleAwareModuleFactory_Integration(t *testing.T) {
	// Create a test module that we can actually register
	testModule := &mockLifecycleModule{
		health: HealthStatus{
			Status:    HealthStateHealthy,
			Message:   "Test module is healthy",
			Timestamp: time.Now(),
		},
	}

	// Set up registries
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()

	// Register module in module registry
	testMetadata := &ModuleMetadata{
		Name:    "test-module",
		Version: "1.0.0",
	}
	err := moduleRegistry.RegisterModule(testMetadata, testModule)
	if err != nil {
		t.Fatalf("Failed to register module in registry: %v", err)
	}

	err = moduleRegistry.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize registry: %v", err)
	}

	mockLoader := newMockModuleLoader()
	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)

	err = factory.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	// Manually register the module with lifecycle manager
	// (since the discovery registry doesn't have it)
	moduleConfig := DefaultModuleConfig()
	_, err = factory.lifecycleManager.RegisterModule(testMetadata, testModule, moduleConfig)
	if err != nil {
		t.Fatalf("Failed to register module with lifecycle manager: %v", err)
	}

	// Test loading the module
	err = factory.lifecycleManager.LoadModule("test-module")
	if err != nil {
		t.Errorf("LoadModule() error = %v, want nil", err)
	}

	// Test getting module state
	state, err := factory.GetModuleState("test-module")
	if err != nil {
		t.Errorf("GetModuleState() error = %v, want nil", err)
	}

	if state != ModuleStateReady {
		t.Errorf("Module state = %v, want %v", state, ModuleStateReady)
	}

	// Test starting the module
	err = factory.StartModule("test-module")
	if err != nil {
		t.Errorf("StartModule() error = %v, want nil", err)
	}

	// Verify state changed to running
	state, err = factory.GetModuleState("test-module")
	if err != nil {
		t.Errorf("GetModuleState() after start error = %v, want nil", err)
	}

	if state != ModuleStateRunning {
		t.Errorf("Module state after start = %v, want %v", state, ModuleStateRunning)
	}

	// Test getting module health
	health, err := factory.GetModuleHealth("test-module")
	if err != nil {
		t.Errorf("GetModuleHealth() error = %v, want nil", err)
	}

	if health.Status != HealthStateHealthy {
		t.Errorf("Module health status = %v, want %v", health.Status, HealthStateHealthy)
	}

	// Test stopping the module
	err = factory.StopModule("test-module")
	if err != nil {
		t.Errorf("StopModule() error = %v, want nil", err)
	}

	// Verify state changed to stopped
	state, err = factory.GetModuleState("test-module")
	if err != nil {
		t.Errorf("GetModuleState() after stop error = %v, want nil", err)
	}

	if state != ModuleStateStopped {
		t.Errorf("Module state after stop = %v, want %v", state, ModuleStateStopped)
	}

	// Test system health
	systemHealth := factory.GetSystemHealth()
	if systemHealth.TotalModules != 1 {
		t.Errorf("System health total modules = %v, want 1", systemHealth.TotalModules)
	}
}

// Benchmark tests
func BenchmarkLifecycleAwareModuleFactory_GetModule(b *testing.B) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)
	if err := factory.Start(); err != nil {
		b.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			b.Errorf("Stop() error = %v", stopErr)
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = factory.GetModule("non-existent")
	}
}

func BenchmarkLifecycleAwareModuleFactory_GetSystemHealth(b *testing.B) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader)
	if err := factory.Start(); err != nil {
		b.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			b.Errorf("Stop() error = %v", stopErr)
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = factory.GetSystemHealth()
	}
}
