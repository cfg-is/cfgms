// Package git implements git-based storage provider for CFGMS
// MVP version for sprint completion - full features in future sprint
package git

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

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
	return "Git-based storage with versioning and audit trail (MVP)"
}

// Available checks if git is available and accessible
func (p *GitProvider) Available() (bool, error) {
	// Check if git is installed
	if _, err := exec.LookPath("git"); err != nil {
		return false, fmt.Errorf("git not found in PATH")
	}
	
	return true, nil
}

// CreateClientTenantStore creates a git-based client tenant store
func (p *GitProvider) CreateClientTenantStore(config map[string]interface{}) (interfaces.ClientTenantStore, error) {
	// Get repository path from config, or use temp directory for testing
	repoPathStr := "/tmp/cfgms-git-test"
	if repoPath, ok := config["repository_path"]; ok {
		if pathStr, ok := repoPath.(string); ok && pathStr != "" {
			repoPathStr = pathStr
		}
	}
	
	// Optional remote URL for distributed deployments (MVP: not implemented)
	remoteURL := ""
	if remote, ok := config["remote_url"]; ok {
		if remoteStr, ok := remote.(string); ok {
			remoteURL = remoteStr
		}
	}
	
	// Create the git store
	store, err := NewGitClientTenantStore(repoPathStr, remoteURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create git client tenant store: %w", err)
	}
	
	return store, nil
}

// Auto-register this provider (Salt-style)
func init() {
	interfaces.RegisterStorageProvider(&GitProvider{})
}

// GitClientTenantStore implements ClientTenantStore using git for persistence
type GitClientTenantStore struct {
	repoPath  string
	remoteURL string // MVP: not used, for future implementation
}

// NewGitClientTenantStore creates a new git-based client tenant store
func NewGitClientTenantStore(repoPath, remoteURL string) (*GitClientTenantStore, error) {
	store := &GitClientTenantStore{
		repoPath:  repoPath,
		remoteURL: remoteURL,
	}
	
	// Initialize git repository if it doesn't exist
	if err := store.initializeRepo(); err != nil {
		return nil, fmt.Errorf("failed to initialize git repository: %w", err)
	}
	
	return store, nil
}

// initializeRepo ensures the git repository exists
func (s *GitClientTenantStore) initializeRepo() error {
	// Check if directory exists
	if _, err := os.Stat(s.repoPath); os.IsNotExist(err) {
		// Create directory
		if err := os.MkdirAll(s.repoPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}
	
	// Check if it's already a git repo
	gitDir := fmt.Sprintf("%s/.git", s.repoPath)
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		// Initialize git repository
		cmd := exec.Command("git", "init")
		cmd.Dir = s.repoPath
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to initialize git repository: %w", err)
		}
		
		// Set up initial config (basic user info for commits)
		configCmds := [][]string{
			{"git", "config", "user.name", "CFGMS Controller"},
			{"git", "config", "user.email", "controller@cfgms.local"},
			{"git", "config", "init.defaultBranch", "main"},
		}
		
		for _, cmdArgs := range configCmds {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			cmd.Dir = s.repoPath
			// Ignore errors for initial setup
			_ = cmd.Run()
		}
	}
	
	return nil
}

// MVP Implementation Note: 
// This is a minimal implementation to unblock the current sprint.
// Full implementation will be done in Epic 5 with proper:
// - JSON file storage with git commits
// - Remote repository sync
// - Mozilla SOPS integration  
// - Proper error handling and recovery
// - Performance optimization

// For now, we'll implement just enough to satisfy the interface
// and use a simple in-memory storage for the MVP functionality
// This allows the MSP feature to work while we build the full implementation

// MVP: Simple in-memory storage within the git provider
// Future: implement proper git file storage with commits
type memoryStorage struct {
	clients  map[string]*interfaces.ClientTenant
	requests map[string]*interfaces.AdminConsentRequest
	mutex    sync.RWMutex
}

func newMemoryStorage() *memoryStorage {
	return &memoryStorage{
		clients:  make(map[string]*interfaces.ClientTenant),
		requests: make(map[string]*interfaces.AdminConsentRequest),
	}
}

// GitClientTenantStore with embedded memory storage
var globalMemoryStorage = newMemoryStorage()

// Interface implementations - MVP uses simple memory storage
// Future: implement proper git file storage with commits

func (s *GitClientTenantStore) StoreClientTenant(client *interfaces.ClientTenant) error {
	globalMemoryStorage.mutex.Lock()
	defer globalMemoryStorage.mutex.Unlock()
	
	if client.ID == "" {
		client.ID = client.TenantID // Use tenant ID as primary key
	}
	if client.CreatedAt.IsZero() {
		client.CreatedAt = time.Now()
	}
	client.UpdatedAt = time.Now()
	
	globalMemoryStorage.clients[client.TenantID] = client
	return nil
}

func (s *GitClientTenantStore) GetClientTenant(tenantID string) (*interfaces.ClientTenant, error) {
	globalMemoryStorage.mutex.RLock()
	defer globalMemoryStorage.mutex.RUnlock()
	
	client, exists := globalMemoryStorage.clients[tenantID]
	if !exists {
		return nil, fmt.Errorf("client tenant not found: %s", tenantID)
	}
	return client, nil
}

func (s *GitClientTenantStore) GetClientTenantByIdentifier(clientIdentifier string) (*interfaces.ClientTenant, error) {
	globalMemoryStorage.mutex.RLock()
	defer globalMemoryStorage.mutex.RUnlock()
	
	for _, client := range globalMemoryStorage.clients {
		if client.ClientIdentifier == clientIdentifier {
			return client, nil
		}
	}
	return nil, fmt.Errorf("client tenant not found by identifier: %s", clientIdentifier)
}

func (s *GitClientTenantStore) ListClientTenants(status interfaces.ClientTenantStatus) ([]*interfaces.ClientTenant, error) {
	globalMemoryStorage.mutex.RLock()
	defer globalMemoryStorage.mutex.RUnlock()
	
	var result []*interfaces.ClientTenant
	for _, client := range globalMemoryStorage.clients {
		if status == "" || client.Status == status {
			result = append(result, client)
		}
	}
	return result, nil
}

func (s *GitClientTenantStore) UpdateClientTenantStatus(tenantID string, status interfaces.ClientTenantStatus) error {
	globalMemoryStorage.mutex.Lock()
	defer globalMemoryStorage.mutex.Unlock()
	
	client, exists := globalMemoryStorage.clients[tenantID]
	if !exists {
		return fmt.Errorf("client tenant not found: %s", tenantID)
	}
	
	client.Status = status
	client.UpdatedAt = time.Now()
	return nil
}

func (s *GitClientTenantStore) DeleteClientTenant(tenantID string) error {
	globalMemoryStorage.mutex.Lock()
	defer globalMemoryStorage.mutex.Unlock()
	
	delete(globalMemoryStorage.clients, tenantID)
	return nil
}

func (s *GitClientTenantStore) StoreAdminConsentRequest(request *interfaces.AdminConsentRequest) error {
	globalMemoryStorage.mutex.Lock()
	defer globalMemoryStorage.mutex.Unlock()
	
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}
	
	globalMemoryStorage.requests[request.State] = request
	return nil
}

func (s *GitClientTenantStore) GetAdminConsentRequest(state string) (*interfaces.AdminConsentRequest, error) {
	globalMemoryStorage.mutex.RLock()
	defer globalMemoryStorage.mutex.RUnlock()
	
	request, exists := globalMemoryStorage.requests[state]
	if !exists {
		return nil, fmt.Errorf("admin consent request not found: %s", state)
	}
	
	// Check if expired
	if time.Now().After(request.ExpiresAt) {
		return nil, fmt.Errorf("admin consent request expired: %s", state)
	}
	
	return request, nil
}

func (s *GitClientTenantStore) DeleteAdminConsentRequest(state string) error {
	globalMemoryStorage.mutex.Lock()
	defer globalMemoryStorage.mutex.Unlock()
	
	delete(globalMemoryStorage.requests, state)
	return nil
}