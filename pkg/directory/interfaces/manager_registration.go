// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package interfaces

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ConfigResolver supplies the ProviderConfig used to connect a registered
// provider on first use. It is called each time the manager has to (re)connect.
type ConfigResolver func(ctx context.Context) (ProviderConfig, error)

// ProviderConnectError is returned when the manager cannot lazily connect a
// registered provider. The provider stays registered; the next call retries.
type ProviderConnectError struct {
	Provider string
	Stage    string // "resolve config" or "connect"
	Err      error
}

func (e *ProviderConnectError) Error() string {
	return fmt.Sprintf("directory provider '%s': %s failed: %v", logging.SanitizeLogValue(e.Provider), e.Stage, e.Err)
}

func (e *ProviderConnectError) Unwrap() error { return e.Err }

// providerRegistration is the manager's per-provider state: the provider, its
// optional config resolver, the connect mutex and the operation counters.
type providerRegistration struct {
	provider  DirectoryProvider
	resolver  ConfigResolver
	connectMu sync.Mutex

	requests   atomic.Int64
	errors     atomic.Int64
	totalNanos atomic.Int64
}

// RegisterProvider registers an already-built provider without calling Connect
// or HealthCheck. The provider is connected lazily by ConnectedProvider, using
// resolver for its config (a nil resolver connects with a zero ProviderConfig).
// The first provider registered becomes the default.
func (m *DirectoryProviderManager) RegisterProvider(name string, p DirectoryProvider, resolver ConfigResolver) error {
	if name == "" {
		return errors.New("provider name is required")
	}
	if p == nil {
		return errors.New("provider is required")
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.providers[name]; exists {
		return fmt.Errorf("provider '%s' is already registered", logging.SanitizeLogValue(name))
	}

	m.providers[name] = p
	m.registrations[name] = &providerRegistration{provider: p, resolver: resolver}
	if m.defaultName == "" {
		m.defaultName = name
	}
	return nil
}

// SetDefaultProvider sets the provider used when a caller passes an empty name.
func (m *DirectoryProviderManager) SetDefaultProvider(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.providers[name]; !exists {
		return fmt.Errorf("provider '%s' not found in manager", logging.SanitizeLogValue(name))
	}
	m.defaultName = name
	return nil
}

// GetDefaultProvider returns the name of the default provider.
func (m *DirectoryProviderManager) GetDefaultProvider() (string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.defaultName == "" {
		return "", errors.New("no default directory provider configured")
	}
	return m.defaultName, nil
}

// GetProviderOrDefault retrieves a provider by name; an empty name resolves to
// the default provider. It does not connect the provider.
func (m *DirectoryProviderManager) GetProviderOrDefault(name string) (DirectoryProvider, error) {
	reg, _, err := m.registration(name)
	if err != nil {
		return nil, err
	}
	return reg.provider, nil
}

// registration resolves name (empty means default) to its registration.
func (m *DirectoryProviderManager) registration(name string) (*providerRegistration, string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if name == "" {
		if m.defaultName == "" {
			return nil, "", errors.New("no default directory provider configured")
		}
		name = m.defaultName
	}
	reg, exists := m.registrations[name]
	if !exists {
		return nil, "", fmt.Errorf("provider '%s' not found in manager", logging.SanitizeLogValue(name))
	}
	return reg, name, nil
}

// ConnectedProvider returns the named provider (empty means default), connecting
// it first when it reports not connected. Concurrent first calls connect once.
// Because the provider is asked every time, a Disconnect is followed by a
// reconnect on the next call. Resolver and Connect failures are returned as
// *ProviderConnectError and leave the provider registered.
func (m *DirectoryProviderManager) ConnectedProvider(ctx context.Context, name string) (DirectoryProvider, error) {
	reg, resolved, err := m.registration(name)
	if err != nil {
		return nil, err
	}
	if err := reg.ensureConnected(ctx, resolved); err != nil {
		return nil, err
	}
	return reg.provider, nil
}

func (r *providerRegistration) ensureConnected(ctx context.Context, name string) error {
	if r.provider.IsConnected(ctx) {
		return nil
	}

	r.connectMu.Lock()
	defer r.connectMu.Unlock()

	if r.provider.IsConnected(ctx) {
		return nil
	}

	var cfg ProviderConfig
	if r.resolver != nil {
		var err error
		if cfg, err = r.resolver(ctx); err != nil {
			return &ProviderConnectError{Provider: name, Stage: "resolve config", Err: err}
		}
	}
	if err := r.provider.Connect(ctx, cfg); err != nil {
		return &ProviderConnectError{Provider: name, Stage: "connect", Err: err}
	}
	return nil
}
