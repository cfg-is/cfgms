// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"errors"
	"fmt"
	"sync"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ErrTenantRequired is returned when a tenant-scoped script library lookup is
// attempted without a tenant. There is no fallback to a global repository.
var ErrTenantRequired = errors.New("tenant ID is required to resolve the script library")

// TenantScriptResolver is the optional interface a ScriptRepository implements
// when the script library is stored per tenant. ScriptRepository.Get carries no
// tenant, so callers that know the tenant reach the library through this.
type TenantScriptResolver interface {
	// GetForTenant retrieves a script from the tenant's library (empty version = latest).
	GetForTenant(tenantID, id, version string) (*VersionedScript, error)
	// ListForTenant lists the tenant's library with optional filtering.
	ListForTenant(tenantID string, filter *ScriptFilter) ([]*ScriptMetadata, error)
}

// TenantScriptRepository resolves a GitScriptRepository per tenant and caches it.
// It satisfies ScriptRepository so it can be wired where a plain repository is
// expected, but the tenant-less methods always fail closed with ErrTenantRequired.
type TenantScriptRepository struct {
	configStore cfgconfig.ConfigStore

	mu    sync.RWMutex
	repos map[string]*GitScriptRepository
}

var (
	_ ScriptRepository     = (*TenantScriptRepository)(nil)
	_ TenantScriptResolver = (*TenantScriptRepository)(nil)
)

// NewTenantScriptRepository creates a tenant-resolving repository over configStore.
func NewTenantScriptRepository(configStore cfgconfig.ConfigStore) (*TenantScriptRepository, error) {
	if configStore == nil {
		return nil, fmt.Errorf("configStore is required")
	}
	return &TenantScriptRepository{
		configStore: configStore,
		repos:       make(map[string]*GitScriptRepository),
	}, nil
}

// ForTenant returns the (cached) repository for a tenant. An empty tenant is an error.
func (t *TenantScriptRepository) ForTenant(tenantID string) (*GitScriptRepository, error) {
	if tenantID == "" {
		return nil, ErrTenantRequired
	}

	t.mu.RLock()
	repo, ok := t.repos[tenantID]
	t.mu.RUnlock()
	if ok {
		return repo, nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if repo, ok := t.repos[tenantID]; ok {
		return repo, nil
	}
	repo, err := NewGitScriptRepository(t.configStore, tenantID, false)
	if err != nil {
		return nil, err
	}
	t.repos[tenantID] = repo
	return repo, nil
}

// GetForTenant implements TenantScriptResolver.
func (t *TenantScriptRepository) GetForTenant(tenantID, id, version string) (*VersionedScript, error) {
	repo, err := t.ForTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return repo.Get(id, version)
}

// ListForTenant implements TenantScriptResolver.
func (t *TenantScriptRepository) ListForTenant(tenantID string, filter *ScriptFilter) ([]*ScriptMetadata, error) {
	repo, err := t.ForTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return repo.List(filter)
}

// The tenant-less ScriptRepository methods fail closed.

// Create always fails: a script must be created through ForTenant.
func (t *TenantScriptRepository) Create(*VersionedScript) error { return ErrTenantRequired }

// Get always fails: use GetForTenant.
func (t *TenantScriptRepository) Get(string, string) (*VersionedScript, error) {
	return nil, ErrTenantRequired
}

// List always fails: use ListForTenant.
func (t *TenantScriptRepository) List(*ScriptFilter) ([]*ScriptMetadata, error) {
	return nil, ErrTenantRequired
}

// Update always fails: a script must be updated through ForTenant.
func (t *TenantScriptRepository) Update(*VersionedScript) error { return ErrTenantRequired }

// Delete always fails: a script must be deleted through ForTenant.
func (t *TenantScriptRepository) Delete(string, string) error { return ErrTenantRequired }

// ListVersions always fails: use ForTenant.
func (t *TenantScriptRepository) ListVersions(string) ([]*Version, error) {
	return nil, ErrTenantRequired
}

// GetLatestVersion always fails: use ForTenant.
func (t *TenantScriptRepository) GetLatestVersion(string) (*Version, error) {
	return nil, ErrTenantRequired
}

// Rollback always fails: use ForTenant.
func (t *TenantScriptRepository) Rollback(string, string) error { return ErrTenantRequired }
