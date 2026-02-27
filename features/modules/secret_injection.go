// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Secret store injection for CFGMS modules.
//
// This file implements the SecretStoreInjectable interface, paralleling the
// LoggingInjectable pattern in logging_injection.go. Modules that need access
// to encrypted secret storage can implement this interface to receive a
// SecretStore instance from the steward at runtime.
package modules

import (
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// SecretStoreInjectable defines the interface that modules can optionally implement
// to receive secret store injection from the steward at runtime.
//
// This interface preserves code signing and application allowlisting:
//   - Modules maintain their original constructors and binary signatures
//   - The steward can inject a secret store after module creation
//   - If a module doesn't implement this interface, it has no secret access
//   - No changes to existing module APIs or constructors are required
type SecretStoreInjectable interface {
	// SetSecretStore injects a secret store implementation into the module.
	SetSecretStore(store secretsif.SecretStore) error

	// GetSecretStore returns the currently injected secret store, if any.
	GetSecretStore() (store secretsif.SecretStore, injected bool)
}

// DefaultSecretStoreSupport provides a default implementation of SecretStoreInjectable
// that modules can embed to gain secret store injection support.
type DefaultSecretStoreSupport struct {
	injectedSecretStore secretsif.SecretStore
}

// SetSecretStore implements SecretStoreInjectable.SetSecretStore.
func (d *DefaultSecretStoreSupport) SetSecretStore(store secretsif.SecretStore) error {
	if store == nil {
		return ErrInvalidInput
	}
	d.injectedSecretStore = store
	return nil
}

// GetSecretStore implements SecretStoreInjectable.GetSecretStore.
func (d *DefaultSecretStoreSupport) GetSecretStore() (secretsif.SecretStore, bool) {
	if d.injectedSecretStore == nil {
		return nil, false
	}
	return d.injectedSecretStore, true
}

// HasInjectedSecretStore returns true if a secret store has been successfully injected.
func (d *DefaultSecretStoreSupport) HasInjectedSecretStore() bool {
	return d.injectedSecretStore != nil
}
