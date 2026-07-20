// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
)

// fakeRegistry builds a provider registry backed by testPackageManager
// (a real, non-mock implementation of PackageManager) so selectManager can
// be exercised deterministically without depending on winget/choco/apt/etc.
// being installed on the test host.
func fakeRegistry(available map[string]bool) map[string]providerEntry {
	reg := make(map[string]providerEntry, len(available))
	for name, ok := range available {
		avail := ok
		providerName := name
		reg[providerName] = providerEntry{
			probe: func(_ context.Context) bool { return avail },
			constructor: func() PackageManager {
				return newTestPackageManagerNamed(providerName)
			},
		}
	}
	return reg
}

// TestPlatformDefaultProviders pins the built-in per-platform default
// provider allowlist and confirms choco is never part of any of them —
// choco is used only when an admin explicitly lists it (resource-level
// `providers`/`package_manager` or @defaults).
func TestPlatformDefaultProviders(t *testing.T) {
	cases := []struct {
		goos string
		want []string
	}{
		{"windows", []string{"winget"}},
		{"darwin", []string{"brew"}},
		{"linux", []string{"apt", "dnf", "yum", "pacman"}},
		{"freebsd", []string{"apt", "dnf", "yum", "pacman"}}, // any other unix-like platform
	}
	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			got := platformDefaultProvidersFor(tc.goos)
			assert.Equal(t, tc.want, got)
			assert.NotContains(t, got, "choco", "built-in default must never include choco")
		})
	}
}

// TestPackageModule_ResolveProviders pins the precedence order: a resource's
// own declared providers win, else the host-wide @defaults policy, else the
// platform built-in default.
func TestPackageModule_ResolveProviders(t *testing.T) {
	t.Run("resource providers win over @defaults", func(t *testing.T) {
		m := &PackageModule{defaultProviders: []string{"choco"}}
		got := m.resolveProviders([]string{"winget"})
		assert.Equal(t, []string{"winget"}, got)
	})

	t.Run("falls back to @defaults when resource declares nothing", func(t *testing.T) {
		m := &PackageModule{defaultProviders: []string{"choco", "winget"}}
		got := m.resolveProviders(nil)
		assert.Equal(t, []string{"choco", "winget"}, got)
	})

	t.Run("falls back to platform default when nothing configured", func(t *testing.T) {
		m := &PackageModule{}
		got := m.resolveProviders(nil)
		assert.Equal(t, platformDefaultProviders(), got)
		assert.NotContains(t, got, "choco", "platform default must never include choco")
	})

	t.Run("empty resource list still falls through (not treated as an explicit empty choice)", func(t *testing.T) {
		m := &PackageModule{defaultProviders: []string{"apt"}}
		got := m.resolveProviders([]string{})
		assert.Equal(t, []string{"apt"}, got)
	})
}

// TestPackageModule_SelectManager exercises the allowlist selection logic:
// first-available wins, unavailable providers are skipped in order, an
// entirely-unavailable list produces an explicit error naming the providers
// tried, unknown provider names are rejected, and a provider outside the
// declared list is never silently substituted in.
func TestPackageModule_SelectManager(t *testing.T) {
	t.Run("first available wins", func(t *testing.T) {
		m := &PackageModule{registry: fakeRegistry(map[string]bool{"winget": true, "choco": true})}
		mgr, name, err := m.selectManager(context.Background(), []string{"winget", "choco"})
		require.NoError(t, err)
		assert.Equal(t, "winget", name)
		assert.Equal(t, "winget", mgr.Name())
	})

	t.Run("unavailable first is skipped to the next available", func(t *testing.T) {
		m := &PackageModule{registry: fakeRegistry(map[string]bool{"winget": false, "choco": true})}
		mgr, name, err := m.selectManager(context.Background(), []string{"winget", "choco"})
		require.NoError(t, err)
		assert.Equal(t, "choco", name)
		assert.Equal(t, "choco", mgr.Name())
	})

	t.Run("none available returns an explicit error naming the tried list", func(t *testing.T) {
		m := &PackageModule{registry: fakeRegistry(map[string]bool{"winget": false, "choco": false})}
		_, _, err := m.selectManager(context.Background(), []string{"winget", "choco"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "winget")
		assert.Contains(t, err.Error(), "choco")
	})

	t.Run("unknown provider name is rejected with a clear error", func(t *testing.T) {
		m := &PackageModule{registry: fakeRegistry(map[string]bool{"winget": true})}
		_, _, err := m.selectManager(context.Background(), []string{"bogus-provider"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bogus-provider")
	})

	t.Run("never selects a provider outside the declared list", func(t *testing.T) {
		// choco is available in the registry but not in the resource's list —
		// selection must fail rather than silently falling back to it.
		m := &PackageModule{registry: fakeRegistry(map[string]bool{"winget": false, "choco": true})}
		_, _, err := m.selectManager(context.Background(), []string{"winget"})
		require.Error(t, err, "must not silently fall back to choco, which isn't in the declared list")
		assert.Contains(t, err.Error(), "winget")
	})

	t.Run("nil registry field falls back to defaultProviderRegistry", func(t *testing.T) {
		m := &PackageModule{}
		// A provider that genuinely doesn't exist in the built-in registry.
		_, _, err := m.selectManager(context.Background(), []string{"not-a-real-provider"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not-a-real-provider")
	})
}

// TestConfig_EffectiveProviders_BackCompat pins that a resource authored with
// only the legacy singular `package_manager` (no `providers`) resolves to a
// single-item providers list.
func TestConfig_EffectiveProviders_BackCompat(t *testing.T) {
	t.Run("package_manager only", func(t *testing.T) {
		cfg := createConfigFromYAML(`
name: git
state: present
version: latest
package_manager: winget
`)
		assert.Equal(t, []string{"winget"}, cfg.effectiveProviders())
	})

	t.Run("providers list wins when both are set", func(t *testing.T) {
		cfg := createConfigFromYAML(`
name: git
state: present
version: latest
package_manager: choco
providers:
  - winget
  - choco
`)
		assert.Equal(t, []string{"winget", "choco"}, cfg.effectiveProviders())
	})

	t.Run("neither set", func(t *testing.T) {
		cfg := createConfigFromYAML(`
name: git
state: present
version: latest
`)
		assert.Nil(t, cfg.effectiveProviders())
	})
}

// TestPackageModule_MetaDefaults verifies the "@defaults" meta-resource:
// Set stores the host-wide default provider policy without attempting any
// package operation, and Get reports it back so the resource converges
// clean.
func TestPackageModule_MetaDefaults(t *testing.T) {
	m := &PackageModule{registry: defaultProviderRegistry}
	ctx := context.Background()

	cfg := createConfigFromYAML(`
name: "@defaults"
state: present
providers:
  - choco
  - winget
`)
	require.NoError(t, m.Set(ctx, metaDefaultsName, cfg))
	assert.Equal(t, []string{"choco", "winget"}, m.defaultProviders)

	got, err := m.Get(ctx, metaDefaultsName)
	require.NoError(t, err)
	gotCfg, ok := got.(*Config)
	require.True(t, ok)
	assert.Equal(t, metaDefaultsName, gotCfg.Name)
	assert.Equal(t, "present", gotCfg.State)
	assert.Equal(t, []string{"choco", "winget"}, gotCfg.Providers)
}

// TestPackageModule_MetaDefaults_NoPackageOp verifies @defaults never
// touches a real (or test) package manager — it must not call Install,
// Remove, or GetInstalledVersion on any registered provider.
func TestPackageModule_MetaDefaults_NoPackageOp(t *testing.T) {
	// A registry whose probes/constructors panic if ever invoked: proves
	// @defaults handling short-circuits before any provider selection.
	panicky := map[string]providerEntry{
		"winget": {
			probe:       func(_ context.Context) bool { panic("must not probe for @defaults") },
			constructor: func() PackageManager { panic("must not construct a manager for @defaults") },
		},
	}
	m := &PackageModule{registry: panicky}
	ctx := context.Background()

	cfg := createConfigFromYAML(`
name: "@defaults"
providers:
  - winget
`)
	require.NoError(t, m.Set(ctx, metaDefaultsName, cfg))

	_, err := m.Get(ctx, metaDefaultsName)
	require.NoError(t, err)
}

// TestPackageModule_MetaDefaults_ExemptFromPackageValidation verifies
// @defaults bypasses validatePackageName/version validation entirely: a
// Config with no State (which would fail normal package validate()) is
// still accepted because it's not a package.
func TestPackageModule_MetaDefaults_ExemptFromPackageValidation(t *testing.T) {
	m := &PackageModule{registry: defaultProviderRegistry}
	cfg := &Config{Name: metaDefaultsName, Providers: []string{"winget"}} // no State, no Version
	require.NoError(t, m.Set(context.Background(), metaDefaultsName, cfg))
	assert.Equal(t, []string{"winget"}, m.defaultProviders)
}

// TestPackageModule_ProvidersEcho_NoDrift verifies a resource authored with
// its own `providers` list sees that exact list echoed back by Get, so
// desired==observed and there is no false drift on the providers field.
func TestPackageModule_ProvidersEcho_NoDrift(t *testing.T) {
	mgr := newTestPackageManager()
	m, err := NewPackageModule(mgr)
	require.NoError(t, err)

	ctx := context.Background()
	cfg := createConfigFromYAML(`
name: nginx
state: present
version: latest
providers:
  - apt
  - dnf
`)

	configurable, ok := modules.Module(m).(modules.Configurable)
	require.True(t, ok)
	require.NoError(t, configurable.Configure(cfg))
	require.NoError(t, m.Set(ctx, "nginx", cfg))

	require.NoError(t, configurable.Configure(cfg))
	got, err := m.Get(ctx, "nginx")
	require.NoError(t, err)

	// AsMap emits []interface{} (not []string) so it matches the desired config,
	// which decodes JSON/YAML arrays as []interface{} — otherwise the comparator's
	// reflect.DeepEqual type check would flag a false drift on every cycle.
	assert.Equal(t, []interface{}{"apt", "dnf"}, got.AsMap()["providers"],
		"observed providers must echo the authored list verbatim (as []interface{})")
	// The drift comparator only compares fields the AUTHORED config declares
	// as managed (see resolved_module_drift note); Get additionally reports
	// PackageManager (the selected provider) even when not authored — that's
	// pre-existing, unrelated behavior. What must hold here is that
	// "providers" is a managed field on BOTH sides, so the comparator
	// actually evaluates it.
	assert.Contains(t, cfg.GetManagedFields(), "providers")
	assert.Contains(t, got.GetManagedFields(), "providers")
}

// TestPackageModule_ProvidersEcho_BackCompatDoesNotLeakIntoEcho verifies that
// when only the legacy `package_manager` singular is authored (no
// `providers` key), Get does NOT invent a `providers` key on the observed
// side — preserving desired==observed for resources that never declared
// `providers` at all.
func TestPackageModule_ProvidersEcho_BackCompatDoesNotLeakIntoEcho(t *testing.T) {
	mgr := newTestPackageManager()
	m, err := NewPackageModule(mgr)
	require.NoError(t, err)

	ctx := context.Background()
	cfg := createConfigFromYAML(`
name: nginx
state: present
version: latest
package_manager: test
`)

	configurable := modules.Module(m).(modules.Configurable)
	require.NoError(t, configurable.Configure(cfg))
	require.NoError(t, m.Set(ctx, "nginx", cfg))

	require.NoError(t, configurable.Configure(cfg))
	got, err := m.Get(ctx, "nginx")
	require.NoError(t, err)

	_, hasProviders := got.AsMap()["providers"]
	assert.False(t, hasProviders, "package_manager-only authoring must not surface a providers key on Get")
	_, authoredHasProviders := cfg.AsMap()["providers"]
	assert.False(t, authoredHasProviders)
}

// TestPackageModule_GetSelectsViaRegistryAndCaches proves the production
// (New()) path: Get with no directly-injected manager resolves through
// resolveProviders + selectManager against the registry, and caches the
// selected manager so a second Get for the same provider-list key does not
// re-probe (the panicky-on-second-probe registry below fails the test if it
// does).
func TestPackageModule_GetSelectsViaRegistryAndCaches(t *testing.T) {
	probeCalls := 0
	reg := map[string]providerEntry{
		"test-provider": {
			probe: func(_ context.Context) bool {
				probeCalls++
				return true
			},
			constructor: func() PackageManager {
				mgr := newTestPackageManagerNamed("test-provider")
				mgr.installed["nginx"] = "1.2.3"
				return mgr
			},
		},
	}
	m := &PackageModule{registry: reg}
	ctx := context.Background()

	cfg := createConfigFromYAML(`
name: nginx
state: present
version: latest
providers:
  - test-provider
`)
	configurable := modules.Module(m).(modules.Configurable)
	require.NoError(t, configurable.Configure(cfg))

	got, err := m.Get(ctx, "nginx")
	require.NoError(t, err)
	gotCfg := got.(*Config)
	assert.Equal(t, "present", gotCfg.State)
	// The config declares `version: latest` (update off), so Get echoes "latest"
	// for the installed package rather than the concrete version — an installed
	// unpinned package is compliant and must not drift. (See echoVersion.)
	assert.Equal(t, "latest", gotCfg.Version)
	assert.Equal(t, "test-provider", gotCfg.PackageManager)
	assert.Equal(t, 1, probeCalls)

	// Second Get for the same resolved provider-list key must hit the cache,
	// not probe again.
	require.NoError(t, configurable.Configure(cfg))
	_, err = m.Get(ctx, "nginx")
	require.NoError(t, err)
	assert.Equal(t, 1, probeCalls, "second Get must use the cached manager, not re-probe")
}

// TestPackageModule_SelectManager_NoAvailableProvider_SurfacesFromGet proves
// the end-to-end behavior: when no provider in the resolved list is
// available, Get returns the explicit "no available package provider"
// error rather than silently falling back.
func TestPackageModule_SelectManager_NoAvailableProvider_SurfacesFromGet(t *testing.T) {
	reg := fakeRegistry(map[string]bool{"winget": false})
	m := &PackageModule{registry: reg}
	ctx := context.Background()

	cfg := createConfigFromYAML(`
name: nginx
state: present
version: latest
providers:
  - winget
`)
	configurable := modules.Module(m).(modules.Configurable)
	require.NoError(t, configurable.Configure(cfg))

	_, err := m.Get(ctx, "nginx")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "winget")
}
