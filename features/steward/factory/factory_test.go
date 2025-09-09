package factory

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockModule implements the Module interface for testing
type mockModule struct {
	mock.Mock
}

func (m *mockModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	args := m.Called(ctx, resourceID)
	return args.Get(0).(modules.ConfigState), args.Error(1)
}

func (m *mockModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	args := m.Called(ctx, resourceID, config)
	return args.Error(0)
}


func TestNew(t *testing.T) {
	registry := discovery.ModuleRegistry{
		"test-module": discovery.ModuleInfo{
			Name:    "test-module",
			Version: "1.0.0",
			Path:    "/test/path",
		},
	}
	
	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionFail,
	}

	factory := New(registry, errorConfig)

	assert.NotNil(t, factory)
	assert.Equal(t, registry, factory.registry)
	assert.Equal(t, errorConfig, factory.config)
	assert.NotNil(t, factory.instances)
	assert.Len(t, factory.instances, 0)
}

func TestValidateModuleInterface(t *testing.T) {
	factory := &ModuleFactory{}

	tests := []struct {
		name    string
		module  interface{}
		wantErr bool
	}{
		{
			name:    "valid module interface",
			module:  &mockModule{},
			wantErr: false,
		},
		{
			name:    "invalid module - not implementing interface",
			module:  "not a module",
			wantErr: true,
		},
		{
			name:    "invalid module - missing methods",
			module:  struct{}{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := factory.ValidateModuleInterface(tt.module)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateModuleInstance(t *testing.T) {
	tests := []struct {
		name         string
		moduleName   string
		registry     discovery.ModuleRegistry
		errorAction  config.ErrorAction
		expectModule bool
		expectErr    bool
	}{
		{
			name:       "module not in registry - fail action",
			moduleName: "non-existent",
			registry:   discovery.ModuleRegistry{},
			errorAction: config.ActionFail,
			expectModule: false,
			expectErr:   true,
		},
		{
			name:       "module not in registry - continue action",
			moduleName: "non-existent",
			registry:   discovery.ModuleRegistry{},
			errorAction: config.ActionContinue,
			expectModule: false,
			expectErr:   false,
		},
		{
			name:       "module not in registry - warn action",
			moduleName: "non-existent",
			registry:   discovery.ModuleRegistry{},
			errorAction: config.ActionWarn,
			expectModule: false,
			expectErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorConfig := config.ErrorHandlingConfig{
				ModuleLoadFailure: tt.errorAction,
			}
			
			factory := New(tt.registry, errorConfig)

			module, err := factory.CreateModuleInstance(tt.moduleName)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.expectModule {
				assert.NotNil(t, module)
			} else {
				assert.Nil(t, module)
			}
		})
	}
}

func TestGetLoadedModules(t *testing.T) {
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{}
	factory := New(registry, errorConfig)

	// Initially empty
	modules := factory.GetLoadedModules()
	assert.Len(t, modules, 0)

	// Add some instances manually for testing
	factory.instances["module1"] = &mockModule{}
	factory.instances["module2"] = &mockModule{}

	modules = factory.GetLoadedModules()
	assert.Len(t, modules, 2)
	assert.Contains(t, modules, "module1")
	assert.Contains(t, modules, "module2")
}

func TestUnloadModule(t *testing.T) {
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{}
	factory := New(registry, errorConfig)

	// Add module instance
	factory.instances["test-module"] = &mockModule{}
	assert.Len(t, factory.instances, 1)

	// Unload module
	factory.UnloadModule("test-module")
	assert.Len(t, factory.instances, 0)
}

func TestUnloadAllModules(t *testing.T) {
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{}
	factory := New(registry, errorConfig)

	// Add multiple module instances
	factory.instances["module1"] = &mockModule{}
	factory.instances["module2"] = &mockModule{}
	factory.instances["module3"] = &mockModule{}
	assert.Len(t, factory.instances, 3)

	// Unload all modules
	factory.UnloadAllModules()
	assert.Len(t, factory.instances, 0)
}

func TestGetModuleInfo(t *testing.T) {
	moduleInfo := discovery.ModuleInfo{
		Name:    "test-module",
		Version: "1.0.0",
		Path:    "/test/path",
	}
	
	registry := discovery.ModuleRegistry{
		"test-module": moduleInfo,
	}
	
	errorConfig := config.ErrorHandlingConfig{}
	factory := New(registry, errorConfig)

	// Test existing module
	info, exists := factory.GetModuleInfo("test-module")
	assert.True(t, exists)
	assert.Equal(t, moduleInfo, info)

	// Test non-existent module
	_, exists = factory.GetModuleInfo("non-existent")
	assert.False(t, exists)
}