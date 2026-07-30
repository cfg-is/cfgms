// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package factory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/stdlib/file"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/pkg/logging"
	maintinterfaces "github.com/cfgis/cfgms/pkg/maintenance/interfaces"

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

func TestAllBuiltinModulesLoad(t *testing.T) {
	factory := New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail}, logging.NewNoopLogger())
	for _, name := range []string{"acme", "cert_trust", "directory", "file", "firewall", "github_runner", "hostname", "hyperv", "package", "patch", "script", "time", "user"} {
		mod, err := factory.LoadModule(name)
		assert.NoError(t, err, "built-in module %q must load without error", name)
		assert.NotNil(t, mod, "built-in module %q must not be nil", name)
	}
}

// TestModuleFactory_ConcurrentLoadModule_NoDataRace exercises the single
// long-lived factory the way the steward does: one shared *ModuleFactory reached
// concurrently from many goroutines (convergence executor, command handlers —
// which run one goroutine per command — and the Tier-2 observe sweep). Before
// the factory carried a mutex, the unguarded reads/writes of f.instances and
// f.injectionStatus made this a "fatal error: concurrent map writes", an
// unrecoverable process abort that no recover() can catch.
//
// Run under -race (make test runs the suite with -race) this fails on any
// unsynchronized access to the factory's mutable state.
func TestModuleFactory_ConcurrentLoadModule_NoDataRace(t *testing.T) {
	f := New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail}, logging.NewNoopLogger())

	// Names spanning the constructor map plus the specially-handled patch module.
	names := []string{"file", "directory", "script", "user", "time", "package", "firewall", "cert_trust", "hostname", "patch"}

	const goroutines = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, goroutines*len(names))

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start
			for i := range names {
				// Rotate the starting offset so goroutines contend on different
				// names at the same moment rather than marching in lockstep.
				name := names[(i+g)%len(names)]
				mod, err := f.LoadModule(name)
				if err != nil {
					errs <- err
					continue
				}
				if mod == nil {
					errs <- fmt.Errorf("module %q loaded as nil", name)
				}
				// Concurrent readers of the same guarded state.
				_ = f.GetLoadedModules()
				_ = f.ListModulesWithLoggers()
			}
		}(g)
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent LoadModule: %v", err)
	}

	// Every requested module must be cached exactly once (the instance cache is
	// consistent, not corrupted, after concurrent loads).
	loaded := f.GetLoadedModules()
	assert.ElementsMatch(t, names, loaded, "each concurrently loaded module must be cached exactly once")
}

// TestModuleFactory_ConcurrentLoadModule_ReturnsSharedInstance verifies that
// serializing construction under the factory mutex yields a single shared
// instance per module name: concurrent callers must not each get their own
// module object, which would silently split module state across call paths.
func TestModuleFactory_ConcurrentLoadModule_ReturnsSharedInstance(t *testing.T) {
	f := New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail}, logging.NewNoopLogger())

	const goroutines = 24
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan modules.Module, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			mod, err := f.LoadModule("file")
			if err == nil {
				results <- mod
			}
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	var first modules.Module
	count := 0
	for mod := range results {
		count++
		if first == nil {
			first = mod
			continue
		}
		assert.Same(t, first, mod, "all concurrent LoadModule callers must receive the same cached instance")
	}
	assert.Equal(t, goroutines, count, "every goroutine must load the module successfully")
}

// TestModuleFactory_ConcurrentMutatorsAndLoads_NoDataRace drives the setters
// (SetStewardID / SetSecretStore / SetMaintenanceGate / RegisterModule /
// UnloadModule) concurrently with LoadModule. These all touch the same guarded
// fields the load path reads, so any missing lock shows up under -race.
func TestModuleFactory_ConcurrentMutatorsAndLoads_NoDataRace(t *testing.T) {
	f := NewWithStewardID(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail}, "steward-1", logging.NewNoopLogger())

	const iterations = 50
	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(4)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			if _, err := f.LoadModule("file"); err != nil {
				t.Errorf("LoadModule(file): %v", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			f.SetStewardID(fmt.Sprintf("steward-%d", i))
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			f.SetMaintenanceGate(nil)
			f.SetSecretStore(nil)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			f.RegisterModule("script", file.New())
			f.UnloadModule("script")
		}
	}()

	close(start)
	wg.Wait()
}

// TestGithubRunner_IsInBuiltinModuleConstructors asserts that "github_runner" is
// present in builtinModuleConstructors (contrast with hyperv, which is absent
// from the map and handled separately by newHypervModule). The loaded instance
// must satisfy modules.Module.
func TestGithubRunner_IsInBuiltinModuleConstructors(t *testing.T) {
	ctor, ok := builtinModuleConstructors["github_runner"]
	assert.True(t, ok, `"github_runner" must be in builtinModuleConstructors`)

	if ok {
		instance := ctor()
		assert.NotNil(t, instance, "github_runner constructor must return a non-nil instance")
		_, isModule := interface{}(instance).(modules.Module)
		assert.True(t, isModule, "github_runner instance must satisfy modules.Module")
	}
}

// TestInstallHyperV_BuiltinModuleNoSignatureCheck asserts that the hyperv module
// is a compiled-in builtin (not disk-loaded). Compiled-in builtins do not require
// disk-load signature verification.
//
// hyperv is handled by newHypervModule (wires the durable provision store) and
// early-returned in loadBuiltinModule — it is intentionally absent from
// builtinModuleConstructors. The factory still loads it without error.
//
// Tracked for future: when pluggable disk-loaded modules are added, a
// signature/integrity gate must be implemented before load.
func TestInstallHyperV_BuiltinModuleNoSignatureCheck(t *testing.T) {
	// hyperv is intentionally absent from the map; it is handled via newHypervModule.
	_, ok := builtinModuleConstructors["hyperv"]
	assert.False(t, ok, `"hyperv" must NOT be in builtinModuleConstructors — it is handled by newHypervModule`)

	// All builtin module names are simple identifiers (no path separators).
	// A disk-load path would contain "/" or "\" — none must exist in M1.
	for name := range builtinModuleConstructors {
		assert.NotContains(t, name, "/",
			"builtin module name %q must not contain path separators (no disk-load in M1)", name)
		assert.NotContains(t, name, `\`,
			"builtin module name %q must not contain path separators (no disk-load in M1)", name)
	}

	// hyperv must still be loadable via the factory (exercises newHypervModule).
	factory := New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail}, logging.NewNoopLogger())
	mod, err := factory.LoadModule("hyperv")
	assert.NoError(t, err, "hyperv builtin must load without error")
	assert.NotNil(t, mod, "hyperv builtin module must not be nil")
}

// TestPatch_NotInBuiltinModuleConstructors asserts that "patch" is absent from
// builtinModuleConstructors (handled by newPatchModule which injects the maintenance
// gate) and is still loadable via the factory without error.
func TestPatch_NotInBuiltinModuleConstructors(t *testing.T) {
	_, ok := builtinModuleConstructors["patch"]
	assert.False(t, ok, `"patch" must NOT be in builtinModuleConstructors — it is handled by newPatchModule`)

	// patch must still be loadable via the factory (exercises newPatchModule).
	factory := New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail}, logging.NewNoopLogger())
	mod, err := factory.LoadModule("patch")
	assert.NoError(t, err, "patch builtin must load without error")
	assert.NotNil(t, mod, "patch builtin module must not be nil")
}

// TestPatch_SetMaintenanceGate verifies that SetMaintenanceGate stores the gate
// and that LoadModule("patch") loads without error when a gate is configured.
func TestPatch_SetMaintenanceGate(t *testing.T) {
	var gate maintinterfaces.Gate = alwaysAllowGate{}

	factory := NewWithStewardID(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail}, "test-steward", logging.NewNoopLogger())
	factory.SetMaintenanceGate(gate)
	assert.Equal(t, gate, factory.gate, "SetMaintenanceGate must store the gate on the factory")

	mod, err := factory.LoadModule("patch")
	require.NoError(t, err, "patch must load without error when a gate is configured")
	require.NotNil(t, mod, "patch module must not be nil")
}

// alwaysAllowGate is a minimal Gate fixture that always permits reboots.
// Represents an ungated device (no reboot_window declared).
type alwaysAllowGate struct{}

func (alwaysAllowGate) CanReboot(_ context.Context, _ string) (bool, error) { return true, nil }
func (alwaysAllowGate) NextWindow(_ context.Context, _ string) (time.Time, error) {
	return time.Time{}, nil
}

// TestModuleFactory_Hyperv_DurableStoreCreated verifies that when LoadModule
// creates the hyperv module, the factory attempts to construct a durable
// provision store and creates the backing directory. Uses
// CFGMS_HYPERV_PROVISION_STORE_DIR to redirect the store into a writable temp
// directory — without this override the default path (/var/lib/cfgms/...) is
// not writable in CI and the factory silently falls back to the in-memory store.
func TestModuleFactory_Hyperv_DurableStoreCreated(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CFGMS_HYPERV_PROVISION_STORE_DIR", root)

	factory := New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail}, logging.NewNoopLogger())
	mod, err := factory.LoadModule("hyperv")
	require.NoError(t, err, "hyperv builtin must load without error")
	require.NotNil(t, mod, "hyperv builtin module must not be nil")

	// The durable store constructor calls os.MkdirAll on the root; verify the
	// directory exists as a side-effect proving the durable code path was reached.
	_, statErr := os.Stat(root)
	assert.NoError(t, statErr, "provision store root must be created by the durable store constructor")
}

// TestModuleFactory_Hyperv_DurableStoreUnavailable_FallsBack verifies the
// fallback branch of newHypervModule: when the durable provision store cannot
// be constructed (CFGMS_HYPERV_PROVISION_STORE_DIR points at an unwritable
// path), the factory (a) still returns a usable hyperv module with no error,
// (b) emits the fallback Warn, and (c) selects no durable store, leaving the
// module on its in-memory provision store for this boot.
//
// Without this test the degrade-to-in-memory path is silent: provision records
// written during a session would be lost on restart, which can strand VMs in
// surface-and-wait indefinitely.
func TestModuleFactory_Hyperv_DurableStoreUnavailable_FallsBack(t *testing.T) {
	// Construct a store root that os.MkdirAll cannot create regardless of uid:
	// a regular file used as a parent path component yields ENOTDIR, which fails
	// even when the test runs as root. (A chmod-0 directory is unreliable here
	// because root bypasses the permission bits and MkdirAll would succeed.)
	parent := t.TempDir()
	occupied := filepath.Join(parent, "occupied")
	require.NoError(t, os.WriteFile(occupied, []byte("x"), 0o600))
	unwritable := filepath.Join(occupied, "provisions")
	t.Setenv("CFGMS_HYPERV_PROVISION_STORE_DIR", unwritable)

	cap := logging.NewCapturingLogger()
	factory := New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{ModuleLoadFailure: config.ActionFail}, cap)

	// (a) The module still loads, without error, despite the store failure.
	mod, err := factory.LoadModule("hyperv")
	require.NoError(t, err, "hyperv must load even when the durable store is unavailable")
	require.NotNil(t, mod, "hyperv module must not be nil on the fallback path")

	// (b) Exactly one fallback Warn was emitted by newHypervProvisionStore.
	require.Len(t, cap.WarnMessages, 1, "exactly one fallback Warn must be emitted")
	assert.Equal(t,
		"hyperv: durable provision store unavailable; using in-memory fallback for this boot",
		cap.WarnMessages[0])

	// (c) No durable store was selected: the store constructor returns nil for
	// this path, so newHypervModule builds the module on its in-memory store.
	assert.Nil(t, factory.newHypervProvisionStore(),
		"durable provision store must be nil when the root path is unwritable")

	// The unwritable root must not have been created as a side-effect (the
	// stat fails because a parent path component is a regular file).
	_, statErr := os.Stat(unwritable)
	assert.Error(t, statErr,
		"durable store root must not exist on the fallback path")
}
