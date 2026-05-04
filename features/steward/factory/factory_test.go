// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package factory

import (
	"context"
	"errors"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/file"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	factory := New(registry, errorConfig, logging.NewNoopLogger())

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

			factory := New(tt.registry, errorConfig, logging.NewNoopLogger())

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
	factory := New(registry, errorConfig, logging.NewNoopLogger())

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
	factory := New(registry, errorConfig, logging.NewNoopLogger())

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
	factory := New(registry, errorConfig, logging.NewNoopLogger())

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
	factory := New(registry, errorConfig, logging.NewNoopLogger())

	// Test existing module
	info, exists := factory.GetModuleInfo("test-module")
	assert.True(t, exists)
	assert.Equal(t, moduleInfo, info)

	// Test non-existent module
	_, exists = factory.GetModuleInfo("non-existent")
	assert.False(t, exists)
}

func TestAllSevenBuiltinModulesLoad(t *testing.T) {
	factory := New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail}, logging.NewNoopLogger())
	for _, name := range []string{"acme", "directory", "file", "firewall", "package", "patch", "script"} {
		mod, err := factory.LoadModule(name)
		assert.NoError(t, err, "built-in module %q must load without error", name)
		assert.NotNil(t, mod, "built-in module %q must not be nil", name)
	}
}

// stubFailingSecretStoreModule implements modules.Module and modules.SecretStoreInjectable.
// SetSecretStore always returns an error to exercise the warning-log path in attemptSecretStoreInjection.
type stubFailingSecretStoreModule struct{}

func (s *stubFailingSecretStoreModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	return nil, nil
}

func (s *stubFailingSecretStoreModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

func (s *stubFailingSecretStoreModule) SetSecretStore(_ secretsif.SecretStore) error {
	return errors.New("injection always fails")
}

func (s *stubFailingSecretStoreModule) GetSecretStore() (secretsif.SecretStore, bool) {
	return nil, false
}

// stubSecretStore is a no-op SecretStore that satisfies the interface so the
// factory's nil-guard does not short-circuit before reaching SetSecretStore.
type stubSecretStore struct{}

func (s *stubSecretStore) StoreSecret(_ context.Context, _ *secretsif.SecretRequest) error {
	return nil
}
func (s *stubSecretStore) GetSecret(_ context.Context, _ string) (*secretsif.Secret, error) {
	return nil, nil
}
func (s *stubSecretStore) DeleteSecret(_ context.Context, _ string) error { return nil }
func (s *stubSecretStore) ListSecrets(_ context.Context, _ *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	return nil, nil
}
func (s *stubSecretStore) GetSecrets(_ context.Context, _ []string) (map[string]*secretsif.Secret, error) {
	return nil, nil
}
func (s *stubSecretStore) StoreSecrets(_ context.Context, _ map[string]*secretsif.SecretRequest) error {
	return nil
}
func (s *stubSecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsif.Secret, error) {
	return nil, nil
}
func (s *stubSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsif.SecretVersion, error) {
	return nil, nil
}
func (s *stubSecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsif.SecretMetadata, error) {
	return nil, nil
}
func (s *stubSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *stubSecretStore) RotateSecret(_ context.Context, _ string, _ string) error { return nil }
func (s *stubSecretStore) ExpireSecret(_ context.Context, _ string) error           { return nil }
func (s *stubSecretStore) HealthCheck(_ context.Context) error                      { return nil }
func (s *stubSecretStore) Close() error                                             { return nil }

func TestModuleFactory_injectSecretStore_logsWarning(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	f := New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{}, mock)
	f.secretStore = &stubSecretStore{}

	mod := &stubFailingSecretStoreModule{}
	f.attemptSecretStoreInjection(mod, "test-module")

	warnLogs := mock.GetLogs("warn")
	require.Len(t, warnLogs, 1)
	assert.Equal(t, "failed to inject secret store into module", warnLogs[0].Message)
}
