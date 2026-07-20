// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// metaDefaultsName is the reserved resource name that configures the
// module's host-wide default provider allowlist instead of installing a
// package. See PackageModule.Set/Get for its handling.
const metaDefaultsName = "@defaults"

// providerEntry describes one registrable package-manager provider: how to
// probe whether it's usable on this host, and how to construct it once
// selected.
type providerEntry struct {
	probe       func(ctx context.Context) bool
	constructor func() PackageManager
}

// defaultProviderRegistry is the built-in set of providers the module can
// select from. A resource (or @defaults, or the platform built-in default)
// names providers from this set by name; unknown names are rejected.
var defaultProviderRegistry = map[string]providerEntry{
	"winget": {probe: wingetProbe, constructor: newWingetManagerAuto},
	"choco":  {probe: cmdProbe("choco"), constructor: newChocolateyManager},
	"apt":    {probe: cmdProbe("apt-get"), constructor: newAptManager},
	"dnf":    {probe: cmdProbe("dnf"), constructor: newDnfManager},
	"yum":    {probe: cmdProbe("yum"), constructor: newYumManager},
	"pacman": {probe: cmdProbe("pacman"), constructor: newPacmanManager},
	"brew":   {probe: cmdProbe("brew"), constructor: newHomebrewManager},
}

// cmdProbe returns an availability probe that succeeds when `<cmdName>
// --version` exits cleanly.
func cmdProbe(cmdName string) func(ctx context.Context) bool {
	return func(ctx context.Context) bool {
		_, err := exec.CommandContext(ctx, cmdName, "--version").Output()
		return err == nil
	}
}

// wingetProbe reports whether a working winget.exe can be resolved, either
// via the PATH app-execution alias (interactive users) or the packaged
// WindowsApps binary (SYSTEM/service contexts, see resolveWinget).
func wingetProbe(ctx context.Context) bool {
	_, ok := resolveWinget(ctx)
	return ok
}

// newWingetManagerAuto constructs a wingetManager using whichever winget
// invocation path resolveWinget finds. This re-probes once; selection
// results are cached by PackageModule.selectOrCachedManager so it only runs
// on a cache miss.
func newWingetManagerAuto() PackageManager {
	bin, ok := resolveWinget(context.Background())
	if !ok {
		bin = "winget"
	}
	return newWingetManagerWithPath(bin)
}

// platformDefaultProviders returns the built-in provider allowlist used when
// neither a resource's own `providers`/`package_manager` nor an @defaults
// policy is configured. Chocolatey is deliberately excluded from every
// platform default — it is used only when an admin explicitly lists it.
func platformDefaultProviders() []string {
	return platformDefaultProvidersFor(runtime.GOOS)
}

// platformDefaultProvidersFor is the goos-parameterized form of
// platformDefaultProviders, split out so all three platform defaults are
// unit-testable regardless of which OS the test runs on.
func platformDefaultProvidersFor(goos string) []string {
	switch goos {
	case "windows":
		return []string{"winget"}
	case "darwin":
		return []string{"brew"}
	default:
		// linux and any other unix-like platform
		return []string{"apt", "dnf", "yum", "pacman"}
	}
}

// resolveProviders determines the ordered provider allowlist to use for a
// single package resource: the resource's own declared providers win,
// falling back to the host-wide @defaults policy (m.defaultProviders),
// falling back to the platform built-in default. Callers must hold m.mu.
func (m *PackageModule) resolveProviders(resourceProviders []string) []string {
	if len(resourceProviders) > 0 {
		return resourceProviders
	}
	if len(m.defaultProviders) > 0 {
		return m.defaultProviders
	}
	return platformDefaultProviders()
}

// selectManager iterates providers in order and returns the first one whose
// availability probe passes, along with its name. It never selects a
// provider outside the given list. An unknown provider name anywhere in the
// list is rejected up front (before any probing); if none of the (valid)
// providers are available, an explicit error names the full list tried.
// Callers must hold m.mu (registry is immutable after construction, but this
// keeps the locking contract uniform with the rest of the module).
func (m *PackageModule) selectManager(ctx context.Context, providers []string) (PackageManager, string, error) {
	reg := m.registry
	if reg == nil {
		reg = defaultProviderRegistry
	}

	for _, name := range providers {
		if _, ok := reg[name]; !ok {
			return nil, "", fmt.Errorf("unknown package provider %q (valid providers: winget, choco, apt, dnf, yum, pacman, brew)", name)
		}
	}

	for _, name := range providers {
		if reg[name].probe(ctx) {
			return reg[name].constructor(), name, nil
		}
	}

	return nil, "", fmt.Errorf("no available package provider among %v", providers)
}

// extractProviders reads the raw `providers` list from a module ConfigState's
// AsMap() output. It does NOT apply the package_manager back-compat
// fallback — callers that need that use Config.effectiveProviders (Set,
// which has the full typed Config) or PackageModule.authoredProviders (Get,
// which only has Configure-recorded state). Keeping extraction raw here is
// what lets Get echo back exactly what was authored under `providers` with
// no false drift when only the legacy singular package_manager was set.
func extractProviders(configMap map[string]interface{}) []string {
	switch v := configMap["providers"].(type) {
	case []string:
		if len(v) == 0 {
			return nil
		}
		out := make([]string, len(v))
		copy(out, v)
		return out
	case []interface{}:
		var out []string
		for _, p := range v {
			if s, ok := p.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// stringsToIfaces converts a []string to []interface{} so AsMap emits string
// lists in the same shape the desired config decodes to (JSON/YAML arrays are
// []interface{}), keeping the drift comparator's reflect.DeepEqual from treating
// an otherwise-identical list as changed purely on element type.
func stringsToIfaces(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// authoredProviders returns the resource's own provider allowlist as
// recorded by Configure: the raw `providers` list if authored, else the
// back-compat single-item list derived from `package_manager`, else nil.
// Used by Get, which has no Config parameter and only Configure-recorded
// state to work from. Callers must hold m.mu.
func (m *PackageModule) authoredProviders() []string {
	if len(m.resolvedProviders) > 0 {
		return m.resolvedProviders
	}
	if m.resolvedPackageManager != "" {
		return []string{m.resolvedPackageManager}
	}
	return nil
}

// selectOrCachedManager resolves the package manager to use for a resource:
// the legacy directly-injected manager when present (NewPackageModule
// constructor / most existing tests, which bypass the provider allowlist
// entirely), otherwise the first available provider from
// resolveProviders/selectManager, cached by the resolved provider-list key
// so repeated Get/Set calls don't re-probe. Logs the selection once per
// cache miss. Callers must hold m.mu.
func (m *PackageModule) selectOrCachedManager(ctx context.Context, resourceProviders []string, pkgName string) (PackageManager, string, error) {
	if m.packageManager != nil {
		return m.packageManager, m.packageManager.Name(), nil
	}

	resolved := m.resolveProviders(resourceProviders)
	key := strings.Join(resolved, "\x00")

	if mgr, ok := m.managerCache[key]; ok {
		return mgr, mgr.Name(), nil
	}

	mgr, providerName, err := m.selectManager(ctx, resolved)
	if err != nil {
		return nil, "", err
	}

	if m.managerCache == nil {
		m.managerCache = make(map[string]PackageManager)
	}
	m.managerCache[key] = mgr

	if logger, ok := m.GetLogger(); ok {
		logger.Info("package provider selected", "provider", providerName, "package", pkgName)
	}

	return mgr, providerName, nil
}
