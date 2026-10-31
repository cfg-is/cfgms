// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Secret store injection for CFGMS modules.
//
// This file implements the SecretStoreInjectable interface, paralleling the
// LoggingInjectable pattern in logging_injection.go. Modules that need access
// to encrypted secret storage can implement this interface to receive a
// SecretStore instance from the steward at runtime.
package modules

import (
	"context"

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

// CredentialClient requests a controller-issued one-time initial password for a
// declared resource (Issue #5555). The password is returned to the caller in
// memory only: implementations must not queue it, retry it from disk, or place it
// in an error.
type CredentialClient interface {
	// IssueInitialCredential asks the controller for the password of the
	// resource named resourceID of the given kind (e.g. "activedirectory.user").
	IssueInitialCredential(ctx context.Context, resourceID, kind string) (string, error)
}

// CredentialClientInjectable is implemented by in-process modules that create
// accounts and need an initial password. The steward injects the client after
// module creation, so module constructors and binary signatures are unchanged.
type CredentialClientInjectable interface {
	// SetCredentialClient injects the client.
	SetCredentialClient(client CredentialClient) error

	// GetCredentialClient returns the injected client, if any.
	GetCredentialClient() (client CredentialClient, injected bool)
}

// DefaultCredentialClientSupport provides a default CredentialClientInjectable
// that modules can embed.
type DefaultCredentialClientSupport struct {
	injectedCredentialClient CredentialClient
}

// SetCredentialClient implements CredentialClientInjectable.
func (d *DefaultCredentialClientSupport) SetCredentialClient(client CredentialClient) error {
	if client == nil {
		return ErrInvalidInput
	}
	d.injectedCredentialClient = client
	return nil
}

// GetCredentialClient implements CredentialClientInjectable.
func (d *DefaultCredentialClientSupport) GetCredentialClient() (CredentialClient, bool) {
	if d.injectedCredentialClient == nil {
		return nil, false
	}
	return d.injectedCredentialClient, true
}
