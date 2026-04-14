// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package git implements production-ready git-based storage provider for CFGMS
// Provides git-based storage with versioning, audit trails, and SOPS encryption
package git

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/cfgis/cfgms/pkg/cache"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// GitProvider implements the StorageProvider interface using git for persistence
type GitProvider struct{}

// Name returns the provider name
func (p *GitProvider) Name() string {
	return "git"
}

// Description returns a human-readable description
func (p *GitProvider) Description() string {
	return "Production Git-based storage with versioning, audit trails, and SOPS encryption"
}

// GetVersion returns the provider version
func (p *GitProvider) GetVersion() string {
	return "2.0.0"
}

// GetCapabilities returns the provider's capabilities
func (p *GitProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsTransactions:   false,            // Git doesn't support ACID transactions
		SupportsVersioning:     true,             // Native git versioning
		SupportsFullTextSearch: false,            // Limited search capabilities
		SupportsEncryption:     true,             // SOPS integration
		SupportsCompression:    true,             // Git's built-in compression
		SupportsReplication:    true,             // Distributed git repositories
		SupportsSharding:       false,            // Single repository per tenant
		MaxBatchSize:           100,              // Reasonable batch size for git operations
		MaxConfigSize:          10 * 1024 * 1024, // 10MB per config file
		MaxAuditRetentionDays:  3650,             // 10 years with git history
	}
}

// Available checks if git is available and accessible
func (p *GitProvider) Available() (bool, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return false, fmt.Errorf("git not found in PATH")
	}
	return true, nil
}

// CreateClientTenantStore creates a git-based client tenant store
func (p *GitProvider) CreateClientTenantStore(config map[string]interface{}) (interfaces.ClientTenantStore, error) {
	repoPathStr := "/tmp/cfgms-git-test"
	if repoPath, ok := config["repository_path"]; ok {
		if pathStr, ok := repoPath.(string); ok && pathStr != "" {
			repoPathStr = pathStr
		}
	}

	remoteURL := ""
	if remote, ok := config["remote_url"]; ok {
		if remoteStr, ok := remote.(string); ok {
			remoteURL = remoteStr
		}
	}

	store, err := NewGitClientTenantStore(repoPathStr, remoteURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create git client tenant store: %w", err)
	}

	return store, nil
}

// CreateConfigStore creates a git-based configuration store
func (p *GitProvider) CreateConfigStore(config map[string]interface{}) (interfaces.ConfigStore, error) {
	repoPathStr := "/tmp/cfgms-git-config"
	if repoPath, ok := config["repository_path"]; ok {
		if pathStr, ok := repoPath.(string); ok && pathStr != "" {
			repoPathStr = pathStr + "/configs"
		}
	}

	remoteURL := ""
	if remote, ok := config["remote_url"]; ok {
		if remoteStr, ok := remote.(string); ok {
			remoteURL = remoteStr
		}
	}

	store, err := NewGitConfigStore(repoPathStr, remoteURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create git config store: %w", err)
	}

	return store, nil
}

// CreateAuditStore creates a git-based audit store
func (p *GitProvider) CreateAuditStore(config map[string]interface{}) (interfaces.AuditStore, error) {
	repoPathStr := "/tmp/cfgms-git-audit"
	if repoPath, ok := config["repository_path"]; ok {
		if pathStr, ok := repoPath.(string); ok && pathStr != "" {
			repoPathStr = pathStr + "/audit"
		}
	}

	remoteURL := ""
	if remote, ok := config["remote_url"]; ok {
		if remoteStr, ok := remote.(string); ok {
			remoteURL = remoteStr
		}
	}

	store, err := NewGitAuditStore(repoPathStr, remoteURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create git audit store: %w", err)
	}

	return store, nil
}

func (p *GitProvider) CreateRuntimeStore(config map[string]interface{}) (interfaces.RuntimeStore, error) {
	// Git provider implements RuntimeStore using shared cache for runtime/session data.
	// Git is for durable configuration storage; runtime sessions are ephemeral by nature.
	// Epic 6 Compliance: Uses shared cache instead of duplicate implementation.
	cacheConfig := cache.CacheConfig{
		Name:            "git-runtime",
		MaxSessions:     1000,
		MaxRuntimeItems: 2000,
		DefaultTTL:      1 * time.Hour,
		CleanupInterval: 10 * time.Minute,
	}
	return cache.NewRuntimeCache(cacheConfig), nil
}

func (p *GitProvider) CreateRBACStore(config map[string]interface{}) (interfaces.RBACStore, error) {
	repoPathStr := "/tmp/cfgms-git-rbac"
	if repoPath, ok := config["repository_path"]; ok {
		if pathStr, ok := repoPath.(string); ok && pathStr != "" {
			repoPathStr = pathStr + "/rbac"
		}
	}

	remoteURL := ""
	if remote, ok := config["remote_url"]; ok {
		if remoteStr, ok := remote.(string); ok {
			remoteURL = remoteStr
		}
	}

	store, err := NewGitRBACStore(repoPathStr, remoteURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create git RBAC store: %w", err)
	}

	return store, nil
}

func (p *GitProvider) CreateTenantStore(config map[string]interface{}) (interfaces.TenantStore, error) {
	repoPathStr := "/tmp/cfgms-git-tenant"
	if repoPath, ok := config["repository_path"]; ok {
		if pathStr, ok := repoPath.(string); ok && pathStr != "" {
			repoPathStr = pathStr + "/tenants"
		}
	}

	remoteURL := ""
	if remote, ok := config["remote_url"]; ok {
		if remoteStr, ok := remote.(string); ok {
			remoteURL = remoteStr
		}
	}

	store, err := NewGitTenantStore(repoPathStr, remoteURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create git tenant store: %w", err)
	}

	return store, nil
}

func (p *GitProvider) CreateRegistrationTokenStore(config map[string]interface{}) (interfaces.RegistrationTokenStore, error) {
	repoPathStr := "/tmp/cfgms-git-registration"
	if repoPath, ok := config["repository_path"]; ok {
		if pathStr, ok := repoPath.(string); ok && pathStr != "" {
			repoPathStr = pathStr + "/registration"
		}
	}

	remoteURL := ""
	if remote, ok := config["remote_url"]; ok {
		if remoteStr, ok := remote.(string); ok {
			remoteURL = remoteStr
		}
	}

	store, err := NewGitRegistrationTokenStore(repoPathStr, remoteURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create git registration token store: %w", err)
	}

	return store, nil
}

// CreateSessionStore is not supported by the git provider.
// Use the SQLite provider for durable session storage.
func (p *GitProvider) CreateSessionStore(config map[string]interface{}) (interfaces.SessionStore, error) {
	return nil, interfaces.ErrNotSupported
}

// Auto-register this provider (Salt-style)
func init() {
	interfaces.RegisterStorageProvider(&GitProvider{})
}
