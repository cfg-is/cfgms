// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

// This file exports the provider registry's internal state to the external
// interfaces_test package. Registry tests must run against real storage
// providers, and importing pkg/storage/providers/* from inside this package
// would form an import cycle (providers import this package). The external
// interfaces_test package has no such restriction, so the registry tests live
// there and reach the unexported registry through these two helpers.

// RegistrySnapshot returns a copy of the currently registered providers.
func RegistrySnapshot() map[string]StorageProvider {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	out := make(map[string]StorageProvider, len(globalRegistry.providers))
	for name, provider := range globalRegistry.providers {
		out[name] = provider
	}
	return out
}

// RegistryReplace replaces the registry contents with a copy of providers.
func RegistryReplace(providers map[string]StorageProvider) {
	next := make(map[string]StorageProvider, len(providers))
	for name, provider := range providers {
		next[name] = provider
	}

	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()
	globalRegistry.providers = next
}
