package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// ClientStoreType defines the type of client tenant store to use
type ClientStoreType string

const (
	// ClientStoreMemory uses in-memory storage (development/testing)
	ClientStoreMemory ClientStoreType = "memory"
	
	// ClientStoreFile uses file-based storage (simple deployments)
	ClientStoreFile ClientStoreType = "file"
	
	// ClientStoreGit uses git-based storage with Mozilla's secret management (default CFGMS approach)
	ClientStoreGit ClientStoreType = "git"
	
	// ClientStoreDatabase uses database storage (production deployments)
	ClientStoreDatabase ClientStoreType = "database"
	
	// ClientStoreHybrid uses hybrid git+database storage (enterprise deployments)
	ClientStoreHybrid ClientStoreType = "hybrid"
)

// ClientStoreConfig defines configuration for client tenant storage
type ClientStoreConfig struct {
	// Type of storage backend to use
	Type ClientStoreType `yaml:"type" json:"type"`
	
	// File backend configuration (when Type = "file")
	FilePath string `yaml:"file_path,omitempty" json:"file_path,omitempty"`
	
	// Git backend configuration (when Type = "git")
	GitRepository string `yaml:"git_repository,omitempty" json:"git_repository,omitempty"`
	GitBranch     string `yaml:"git_branch,omitempty" json:"git_branch,omitempty"`
	
	// Database backend configuration (when Type = "database")
	DatabaseURL string `yaml:"database_url,omitempty" json:"database_url,omitempty"`
	
	// Hybrid configuration (when Type = "hybrid")
	HybridConfig *HybridStoreConfig `yaml:"hybrid,omitempty" json:"hybrid,omitempty"`
	
	// Sharding configuration
	EnableSharding bool `yaml:"enable_sharding" json:"enable_sharding"`
	ShardCount     int  `yaml:"shard_count" json:"shard_count"`
}

// HybridStoreConfig defines configuration for hybrid storage
type HybridStoreConfig struct {
	GitRepository string `yaml:"git_repository" json:"git_repository"`
	GitBranch     string `yaml:"git_branch" json:"git_branch"`
	DatabaseURL   string `yaml:"database_url" json:"database_url"`
	SyncInterval  string `yaml:"sync_interval" json:"sync_interval"` // e.g., "5m", "1h"
}

// DefaultClientStoreConfig returns the default configuration for client tenant storage
// Following CFGMS philosophy: defaults to file-based storage for simple deployments
func DefaultClientStoreConfig() *ClientStoreConfig {
	return &ClientStoreConfig{
		Type:           ClientStoreFile,
		FilePath:       "/var/lib/cfgms/msp-client-data",
		EnableSharding: false,
		ShardCount:     1,
	}
}

// ProductionClientStoreConfig returns configuration optimized for production MSP deployments
func ProductionClientStoreConfig(databaseURL string) *ClientStoreConfig {
	return &ClientStoreConfig{
		Type:           ClientStoreDatabase,
		DatabaseURL:    databaseURL,
		EnableSharding: true,
		ShardCount:     8,
	}
}

// GitBasedClientStoreConfig returns configuration for git-based storage following CFGMS default approach
func GitBasedClientStoreConfig(repository, branch string) *ClientStoreConfig {
	return &ClientStoreConfig{
		Type:           ClientStoreGit,
		GitRepository:  repository,
		GitBranch:      branch,
		EnableSharding: false,
		ShardCount:     1,
	}
}

// generateUniqueID generates a unique identifier for test isolation
func generateUniqueID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// NewClientTenantStore creates a new ClientTenantStore based on configuration
// This factory now uses the global plugin architecture with git as the unified backend:
// - All storage types now use git provider (memory option removed for simplicity)
// - Production deployments: Database backend with full ACID transactions (coming in Epic 5)
func NewClientTenantStore(config *ClientStoreConfig, logger interface{}) (ClientTenantStore, error) {
	// Convert the local config to the global storage config format
	var providerName string
	globalConfig := make(map[string]interface{})
	
	switch config.Type {
	case ClientStoreMemory:
		// Memory storage deprecated - use git provider instead
		providerName = "git"
		globalConfig["repository_path"] = fmt.Sprintf("/tmp/cfgms-memory-replacement-%s.git", generateUniqueID())
		
	case ClientStoreFile:
		// Use git provider with local repository path
		providerName = "git"
		globalConfig["repository_path"] = config.FilePath
		if config.FilePath == "" {
			globalConfig["repository_path"] = fmt.Sprintf("/tmp/cfgms-client-tenants-%s.git", generateUniqueID())
		}
		
	case ClientStoreGit:
		providerName = "git"
		if config.GitRepository != "" {
			globalConfig["remote_url"] = config.GitRepository
			// Use unique path to avoid test conflicts
			globalConfig["repository_path"] = fmt.Sprintf("/tmp/cfgms-client-git-%s", generateUniqueID())
		} else {
			// Use unique path to avoid test conflicts
			globalConfig["repository_path"] = fmt.Sprintf("/tmp/cfgms-client-tenants-%s.git", generateUniqueID())
		}
		
	case ClientStoreDatabase:
		providerName = "database"
		globalConfig["database_url"] = config.DatabaseURL
		if poolSize := 10; poolSize > 0 {
			globalConfig["pool_size"] = poolSize
		}
		
	case ClientStoreHybrid:
		// For hybrid, use database as primary (MVP approach)
		if config.HybridConfig == nil {
			return nil, fmt.Errorf("hybrid configuration required for hybrid client store")
		}
		providerName = "database"
		globalConfig["database_url"] = config.HybridConfig.DatabaseURL
		
	default:
		return nil, fmt.Errorf("unsupported client store type: %s", config.Type)
	}
	
	// Use the global storage interface to create the store
	store, err := interfaces.CreateClientTenantStoreFromConfig(providerName, globalConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create client tenant store via global plugin system: %w", err)
	}
	
	// Wrap the global interface to match our local interface
	return &GlobalStorageAdapter{store: store}, nil
}

// GlobalStorageAdapter adapts the global storage interface to our local interface
// This allows gradual migration from local to global interfaces
type GlobalStorageAdapter struct {
	store interfaces.ClientTenantStore
}

func (g *GlobalStorageAdapter) StoreClientTenant(client *ClientTenant) error {
	globalClient := &interfaces.ClientTenant{
		ID:               client.ID,
		TenantID:         client.TenantID,
		TenantName:       client.TenantName,
		DomainName:       client.DomainName,
		AdminEmail:       client.AdminEmail,
		ConsentedAt:      client.ConsentedAt,
		Status:           interfaces.ClientTenantStatus(client.Status),
		ClientIdentifier: client.ClientIdentifier,
		Metadata:         client.Metadata,
		CreatedAt:        client.CreatedAt,
		UpdatedAt:        client.UpdatedAt,
	}
	return g.store.StoreClientTenant(globalClient)
}

func (g *GlobalStorageAdapter) GetClientTenant(tenantID string) (*ClientTenant, error) {
	globalClient, err := g.store.GetClientTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return &ClientTenant{
		ID:               globalClient.ID,
		TenantID:         globalClient.TenantID,
		TenantName:       globalClient.TenantName,
		DomainName:       globalClient.DomainName,
		AdminEmail:       globalClient.AdminEmail,
		ConsentedAt:      globalClient.ConsentedAt,
		Status:           ClientTenantStatus(globalClient.Status),
		ClientIdentifier: globalClient.ClientIdentifier,
		Metadata:         globalClient.Metadata,
		CreatedAt:        globalClient.CreatedAt,
		UpdatedAt:        globalClient.UpdatedAt,
	}, nil
}

func (g *GlobalStorageAdapter) GetClientTenantByIdentifier(clientIdentifier string) (*ClientTenant, error) {
	globalClient, err := g.store.GetClientTenantByIdentifier(clientIdentifier)
	if err != nil {
		return nil, err
	}
	return &ClientTenant{
		ID:               globalClient.ID,
		TenantID:         globalClient.TenantID,
		TenantName:       globalClient.TenantName,
		DomainName:       globalClient.DomainName,
		AdminEmail:       globalClient.AdminEmail,
		ConsentedAt:      globalClient.ConsentedAt,
		Status:           ClientTenantStatus(globalClient.Status),
		ClientIdentifier: globalClient.ClientIdentifier,
		Metadata:         globalClient.Metadata,
		CreatedAt:        globalClient.CreatedAt,
		UpdatedAt:        globalClient.UpdatedAt,
	}, nil
}

func (g *GlobalStorageAdapter) ListClientTenants(status ClientTenantStatus) ([]*ClientTenant, error) {
	globalStatus := interfaces.ClientTenantStatus(status)
	globalClients, err := g.store.ListClientTenants(globalStatus)
	if err != nil {
		return nil, err
	}
	
	var clients []*ClientTenant
	for _, globalClient := range globalClients {
		clients = append(clients, &ClientTenant{
			ID:               globalClient.ID,
			TenantID:         globalClient.TenantID,
			TenantName:       globalClient.TenantName,
			DomainName:       globalClient.DomainName,
			AdminEmail:       globalClient.AdminEmail,
			ConsentedAt:      globalClient.ConsentedAt,
			Status:           ClientTenantStatus(globalClient.Status),
			ClientIdentifier: globalClient.ClientIdentifier,
			Metadata:         globalClient.Metadata,
			CreatedAt:        globalClient.CreatedAt,
			UpdatedAt:        globalClient.UpdatedAt,
		})
	}
	return clients, nil
}

func (g *GlobalStorageAdapter) UpdateClientTenantStatus(tenantID string, status ClientTenantStatus) error {
	globalStatus := interfaces.ClientTenantStatus(status)
	return g.store.UpdateClientTenantStatus(tenantID, globalStatus)
}

func (g *GlobalStorageAdapter) DeleteClientTenant(tenantID string) error {
	return g.store.DeleteClientTenant(tenantID)
}

func (g *GlobalStorageAdapter) StoreAdminConsentRequest(request *AdminConsentRequest) error {
	globalRequest := &interfaces.AdminConsentRequest{
		ClientIdentifier: request.ClientIdentifier,
		ClientName:       request.ClientName,
		RequestedBy:      request.RequestedBy,
		State:            request.State,
		ExpiresAt:        request.ExpiresAt,
		CreatedAt:        request.CreatedAt,
		Metadata:         request.Metadata,
	}
	return g.store.StoreAdminConsentRequest(globalRequest)
}

func (g *GlobalStorageAdapter) GetAdminConsentRequest(state string) (*AdminConsentRequest, error) {
	globalRequest, err := g.store.GetAdminConsentRequest(state)
	if err != nil {
		return nil, err
	}
	return &AdminConsentRequest{
		ClientIdentifier: globalRequest.ClientIdentifier,
		ClientName:       globalRequest.ClientName,
		RequestedBy:      globalRequest.RequestedBy,
		State:            globalRequest.State,
		ExpiresAt:        globalRequest.ExpiresAt,
		CreatedAt:        globalRequest.CreatedAt,
		Metadata:         globalRequest.Metadata,
	}, nil
}

func (g *GlobalStorageAdapter) DeleteAdminConsentRequest(state string) error {
	return g.store.DeleteAdminConsentRequest(state)
}

// Legacy functions removed - now using global plugin architecture
// All storage creation goes through interfaces.CreateClientTenantStoreFromConfig

// maskDatabaseURL masks sensitive information in database URL for logging
func maskDatabaseURL(url string) string {
	if url == "" {
		return ""
	}
	
	// Simple masking - in production, use more sophisticated URL parsing
	if len(url) > 20 {
		return url[:8] + "***" + url[len(url)-8:]
	}
	return "***"
}

// ValidateClientStoreConfig validates client store configuration
func ValidateClientStoreConfig(config *ClientStoreConfig) error {
	if config == nil {
		return fmt.Errorf("client store configuration is required")
	}
	
	switch config.Type {
	case ClientStoreMemory:
		// No additional validation needed
		
	case ClientStoreFile:
		if config.FilePath == "" {
			return fmt.Errorf("file_path is required for file client store")
		}
		
	case ClientStoreGit:
		// Git repository is optional - uses temp directory if not specified
		if config.GitBranch == "" {
			config.GitBranch = "main" // Default branch
		}
		
	case ClientStoreDatabase:
		if config.DatabaseURL == "" {
			return fmt.Errorf("database_url is required for database client store")
		}
		
	case ClientStoreHybrid:
		if config.HybridConfig == nil {
			return fmt.Errorf("hybrid configuration is required for hybrid client store")
		}
		if config.HybridConfig.GitRepository == "" {
			return fmt.Errorf("git_repository is required for hybrid client store")
		}
		if config.HybridConfig.DatabaseURL == "" {
			return fmt.Errorf("database_url is required for hybrid client store")
		}
		if config.HybridConfig.SyncInterval == "" {
			config.HybridConfig.SyncInterval = "5m" // Default sync interval
		}
		
	default:
		return fmt.Errorf("unsupported client store type: %s", config.Type)
	}
	
	// Validate sharding configuration
	if config.EnableSharding {
		if config.ShardCount <= 0 {
			return fmt.Errorf("shard_count must be positive when sharding is enabled")
		}
		if config.ShardCount > 256 {
			return fmt.Errorf("shard_count cannot exceed 256")
		}
	} else {
		config.ShardCount = 1 // Ensure consistent state
	}
	
	return nil
}

// GetRecommendedStoreType returns the recommended store type based on deployment characteristics
func GetRecommendedStoreType(clientCount int, requiresHA bool, hasDatabase bool) ClientStoreType {
	// Simple heuristics for store type recommendation
	if clientCount <= 10 && !requiresHA {
		return ClientStoreFile
	}
	
	if clientCount <= 100 && !requiresHA && !hasDatabase {
		return ClientStoreGit
	}
	
	// Check for hybrid first (most specific - requires both HA and database)
	if hasDatabase && requiresHA {
		return ClientStoreHybrid
	}
	
	if hasDatabase && clientCount > 50 {
		return ClientStoreDatabase
	}
	
	// Default to git-based storage (CFGMS philosophy)
	return ClientStoreGit
}

// ClientStoreInfo provides information about the configured client store
type ClientStoreInfo struct {
	Type           ClientStoreType `json:"type"`
	Implementation string          `json:"implementation"`
	Features       []string        `json:"features"`
	Limitations    []string        `json:"limitations"`
}

// GetClientStoreInfo returns information about the configured client store
func GetClientStoreInfo(config *ClientStoreConfig) *ClientStoreInfo {
	info := &ClientStoreInfo{
		Type: config.Type,
	}
	
	switch config.Type {
	case ClientStoreMemory:
		info.Implementation = "Git-backed storage (memory option deprecated)"
		info.Features = []string{"Persistent storage", "Version control", "Audit trail"}
		info.Limitations = []string{"Requires git", "Temporary files in /tmp"}
		
	case ClientStoreFile:
		info.Implementation = "Local filesystem storage"
		info.Features = []string{"Persistent storage", "No external dependencies", "Simple deployment"}
		info.Limitations = []string{"Single node only", "No concurrent access", "Manual backup required"}
		
	case ClientStoreGit:
		info.Implementation = "Git-based configuration storage"
		info.Features = []string{"Version control", "Distributed", "Audit trail", "Mozilla secret management"}
		info.Limitations = []string{"Requires git repository", "Network dependency", "Complex conflict resolution"}
		
	case ClientStoreDatabase:
		info.Implementation = "Database storage (PostgreSQL)"
		info.Features = []string{"ACID transactions", "High availability", "Concurrent access", "Query capabilities"}
		info.Limitations = []string{"Requires database", "Additional infrastructure", "More complex deployment"}
		
	case ClientStoreHybrid:
		info.Implementation = "Hybrid git + database storage"
		info.Features = []string{"Best of both worlds", "Fast local access", "Distributed backup", "High availability"}
		info.Limitations = []string{"Complex configuration", "Requires both git and database", "Synchronization overhead"}
	}
	
	if config.EnableSharding {
		info.Features = append(info.Features, fmt.Sprintf("Sharding (%d shards)", config.ShardCount))
	}
	
	return info
}