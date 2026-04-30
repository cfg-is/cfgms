// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package factory

import (
	"testing"

	"github.com/cfgis/cfgms/features/modules/file"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"

	"github.com/stretchr/testify/assert"
)

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
	f := &ModuleFactory{}

	tests := []struct {
		name    string
		module  interface{}
		wantErr bool
	}{
		{
			name:    "valid module interface",
			module:  file.New(),
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
			err := f.ValidateModuleInterface(tt.module)

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
			name:         "module not in registry - fail action",
			moduleName:   "non-existent",
			registry:     discovery.ModuleRegistry{},
			errorAction:  config.ActionFail,
			expectModule: false,
			expectErr:    true,
		},
		{
			name:         "module not in registry - continue action",
			moduleName:   "non-existent",
			registry:     discovery.ModuleRegistry{},
			errorAction:  config.ActionContinue,
			expectModule: false,
			expectErr:    false,
		},
		{
			name:         "module not in registry - warn action",
			moduleName:   "non-existent",
			registry:     discovery.ModuleRegistry{},
			errorAction:  config.ActionWarn,
			expectModule: false,
			expectErr:    false,
		},
		{
			name:         "built-in file module loads successfully",
			moduleName:   "file",
			registry:     discovery.ModuleRegistry{},
			errorAction:  config.ActionFail,
			expectModule: true,
			expectErr:    false,
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
	loaded := factory.GetLoadedModules()
	assert.Len(t, loaded, 0)

	// Load real built-in modules via the factory
	_, err := factory.LoadModule("file")
	assert.NoError(t, err)
	_, err = factory.LoadModule("directory")
	assert.NoError(t, err)

	loaded = factory.GetLoadedModules()
	assert.Len(t, loaded, 2)
	assert.Contains(t, loaded, "file")
	assert.Contains(t, loaded, "directory")
}

func TestUnloadModule(t *testing.T) {
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{}
	factory := New(registry, errorConfig)

	// Load a real module
	_, err := factory.LoadModule("file")
	assert.NoError(t, err)
	assert.Len(t, factory.instances, 1)

	factory.UnloadModule("file")
	assert.Len(t, factory.instances, 0)
}

func TestUnloadAllModules(t *testing.T) {
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{}
	factory := New(registry, errorConfig)

	// Load multiple real built-in modules
	for _, name := range []string{"file", "directory", "script"} {
		_, err := factory.LoadModule(name)
		assert.NoError(t, err)
	}
	assert.Len(t, factory.instances, 3)

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

func TestAllSevenBuiltinModulesLoad(t *testing.T) {
	factory := New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail})
	for _, name := range []string{"acme", "directory", "file", "firewall", "package", "patch", "script"} {
		mod, err := factory.LoadModule(name)
		assert.NoError(t, err, "built-in module %q must load without error", name)
		assert.NotNil(t, mod, "built-in module %q must not be nil", name)
	}
}
