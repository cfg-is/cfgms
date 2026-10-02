// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package migrate

import (
	"fmt"
	"sort"
	"sync"
)

var (
	regMu    sync.RWMutex
	registry = make(map[string]MigratorFactory)
)

// Register registers a MigratorFactory under name.
// Providers call this from their init() functions via a blank import in the CLI binary.
// Re-registering an existing name overwrites the previous factory.
func Register(name string, f MigratorFactory) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[name] = f
}

// Lookup returns the MigratorFactory for name.
// If name is not registered, the error message lists all registered names.
func Lookup(name string) (MigratorFactory, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	f, ok := registry[name]
	if !ok {
		names := registeredNamesSorted()
		return nil, fmt.Errorf("no migrator registered for %q; registered providers: %v", name, names)
	}
	return f, nil
}

// RegisteredNames returns a sorted slice of registered provider names.
func RegisteredNames() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	return registeredNamesSorted()
}

// registeredNamesSorted returns sorted names; caller must hold regMu (any mode).
func registeredNamesSorted() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
