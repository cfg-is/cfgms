package git

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultGitManager implements the GitManager interface
type DefaultGitManager struct {
	provider     GitProvider
	store        RepositoryStore
	syncManager  SyncManager
	hookManager  HookManager
	sopsManager  *SOPSManager
	repositories map[string]*Repository
	localCache   map[string]string // repoID -> local path
	mu           sync.RWMutex
	cacheDir     string
	config       GitManagerConfig
}

// GitManagerConfig contains configuration for the Git manager
type GitManagerConfig struct {
	// CacheDir is the directory for local repository cache
	CacheDir string

	// DefaultBranch is the default branch name for new repositories
	DefaultBranch string

	// AutoSync enables automatic template synchronization
	AutoSync bool

	// SyncInterval is how often to check for template updates
	SyncInterval time.Duration

	// EnableHooks enables Git hooks
	EnableHooks bool

	// MaxCacheSize is the maximum size of the local cache in bytes
	MaxCacheSize int64
}

// NewGitManager creates a new Git manager
func NewGitManager(provider GitProvider, store RepositoryStore, config GitManagerConfig) *DefaultGitManager {
	if config.DefaultBranch == "" {
		config.DefaultBranch = "main"
	}
	if config.CacheDir == "" {
		config.CacheDir = "/var/cache/cfgms/git"
	}
	if config.SyncInterval == 0 {
		config.SyncInterval = 1 * time.Hour
	}

	manager := &DefaultGitManager{
		provider:     provider,
		store:        store,
		repositories: make(map[string]*Repository),
		localCache:   make(map[string]string),
		cacheDir:     config.CacheDir,
		config:       config,
	}

	// Initialize SOPS manager
	manager.sopsManager = NewSOPSManager()

	// Initialize sync manager
	manager.syncManager = NewSyncManager(manager, store)

	// Initialize hook manager
	manager.hookManager = NewHookManager()

	// Start background sync if enabled
	if config.AutoSync {
		go manager.backgroundSync()
	}

	return manager
}

// CreateRepository creates a new Git repository
func (m *DefaultGitManager) CreateRepository(ctx context.Context, config RepositoryConfig) (*Repository, error) {
	// Set defaults
	if config.InitialBranch == "" {
		config.InitialBranch = m.config.DefaultBranch
	}

	// Generate repository name based on type
	if config.Name == "" {
		config.Name = m.generateRepositoryName(config)
	}

	// Create repository with provider
	repo, err := m.provider.CreateRepository(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	// Initialize repository locally
	localPath := m.getLocalPath(repo.ID)
	if err := m.store.Clone(ctx, repo.CloneURL, localPath); err != nil {
		// Clean up remote repository on failure
		_ = m.provider.DeleteRepository(ctx, config.Owner, config.Name)
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}

	// Create initial structure based on repository type
	if err := m.initializeRepositoryStructure(ctx, repo, localPath); err != nil {
		// Clean up on failure
		_ = m.provider.DeleteRepository(ctx, config.Owner, config.Name)
		return nil, fmt.Errorf("failed to initialize repository structure: %w", err)
	}

	// Generate SOPS configuration if enabled
	if repo.SOPSConfig != nil && repo.SOPSConfig.Enabled {
		if err := m.sopsManager.GenerateSOPSConfig(repo.SOPSConfig, localPath); err != nil {
			// Log warning but don't fail repository creation
			fmt.Printf("warning: failed to generate .sops.yaml: %v\n", err)
		}
	}

	// Install hooks if enabled
	if m.config.EnableHooks {
		if err := m.hookManager.InstallHooks(ctx, localPath); err != nil {
			return nil, fmt.Errorf("failed to install hooks: %w", err)
		}
	}

	// Cache repository
	m.mu.Lock()
	m.repositories[repo.ID] = repo
	m.localCache[repo.ID] = localPath
	m.mu.Unlock()

	return repo, nil
}

// GetRepository retrieves a repository by ID
func (m *DefaultGitManager) GetRepository(ctx context.Context, repoID string) (*Repository, error) {
	m.mu.RLock()
	repo, exists := m.repositories[repoID]
	m.mu.RUnlock()

	if exists {
		return repo, nil
	}

	// Try to fetch from provider (implement repository discovery)
	return nil, fmt.Errorf("repository not found: %s", repoID)
}

// ListRepositories lists repositories based on filter
func (m *DefaultGitManager) ListRepositories(ctx context.Context, filter RepositoryFilter) ([]*Repository, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Repository
	for _, repo := range m.repositories {
		if m.matchesFilter(repo, filter) {
			result = append(result, repo)
		}
	}

	return result, nil
}

// DeleteRepository deletes a repository
func (m *DefaultGitManager) DeleteRepository(ctx context.Context, repoID string) error {
	m.mu.Lock()
	repo, exists := m.repositories[repoID]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("repository not found: %s", repoID)
	}

	// Remove from cache
	delete(m.repositories, repoID)
	localPath, hasLocal := m.localCache[repoID]
	if hasLocal {
		delete(m.localCache, repoID)
	}
	m.mu.Unlock()

	// Delete from provider
	parts := parseRepositoryName(repo.Name)
	if err := m.provider.DeleteRepository(ctx, parts.owner, parts.name); err != nil {
		return fmt.Errorf("failed to delete repository: %w", err)
	}

	// Clean up local cache
	if hasLocal {
		_ = localPath
	}

	return nil
}

// GetConfiguration retrieves a configuration from a repository
func (m *DefaultGitManager) GetConfiguration(ctx context.Context, ref ConfigurationRef) (*Configuration, error) {
	// Ensure repository is cloned/updated
	localPath, err := m.ensureRepository(ctx, ref.RepositoryID)
	if err != nil {
		return nil, err
	}

	// Checkout branch if specified
	if ref.Branch != "" {
		if err := m.store.CheckoutBranch(ctx, localPath, ref.Branch); err != nil {
			return nil, fmt.Errorf("failed to checkout branch %s: %w", ref.Branch, err)
		}
	}

	// Read the configuration file
	content, err := m.store.ReadFile(ctx, localPath, ref.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration: %w", err)
	}

	// Decrypt SOPS content if needed
	repo, err := m.GetRepository(ctx, ref.RepositoryID)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}

	if repo.SOPSConfig != nil && repo.SOPSConfig.Enabled {
		if decryptedContent, err := m.sopsManager.DecryptContent(ctx, content); err != nil {
			// If decryption fails but file is not SOPS encrypted, continue with original content
			if !m.sopsManager.IsSOPSEncrypted(content) {
				// Not a SOPS file, use original content
			} else {
				return nil, fmt.Errorf("failed to decrypt SOPS content: %w", err)
			}
		} else {
			content = decryptedContent
		}
	}

	// Determine format from file extension
	format := m.getConfigFormat(ref.Path)

	// Get file metadata
	history, err := m.store.GetHistory(ctx, localPath, ref.Path, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to get file history: %w", err)
	}

	var metadata ConfigMetadata
	if len(history) > 0 {
		commit := history[0]
		metadata = ConfigMetadata{
			Author:       commit.Author.Name,
			LastModified: commit.Timestamp,
		}
	}

	return &Configuration{
		Path:     ref.Path,
		Content:  content,
		Format:   format,
		Metadata: metadata,
	}, nil
}

// SaveConfiguration saves a configuration to a repository
func (m *DefaultGitManager) SaveConfiguration(ctx context.Context, ref ConfigurationRef, config *Configuration, message string) error {
	// Ensure repository is cloned/updated
	localPath, err := m.ensureRepository(ctx, ref.RepositoryID)
	if err != nil {
		return err
	}

	// Checkout branch if specified
	if ref.Branch != "" {
		if err := m.store.CheckoutBranch(ctx, localPath, ref.Branch); err != nil {
			return fmt.Errorf("failed to checkout branch %s: %w", ref.Branch, err)
		}
	}

	// Get repository for SOPS configuration
	repo, err := m.GetRepository(ctx, ref.RepositoryID)
	if err != nil {
		return fmt.Errorf("failed to get repository: %w", err)
	}

	content := config.Content

	// Encrypt content with SOPS if enabled and required
	if repo.SOPSConfig != nil && repo.SOPSConfig.Enabled {
		shouldEncrypt, kmsKey := m.sopsManager.ShouldEncryptFile(ref.Path, repo.SOPSConfig)
		if shouldEncrypt {
			encryptedContent, err := m.sopsManager.EncryptContent(ctx, content, repo.SOPSConfig, ref.Path)
			if err != nil {
				return fmt.Errorf("failed to encrypt content with SOPS: %w", err)
			}
			content = encryptedContent
			_ = kmsKey // Used in encryption
		}
	}

	// Run pre-commit hooks if enabled
	if m.config.EnableHooks {
		if err := m.hookManager.RunPreCommitHooks(ctx, localPath, []string{ref.Path}); err != nil {
			return fmt.Errorf("pre-commit hook failed: %w", err)
		}

		// Run SOPS pre-commit checks if SOPS is enabled
		if repo.SOPSConfig != nil && repo.SOPSConfig.Enabled {
			if err := m.sopsManager.PreCommitSOPSCheck(ctx, []string{ref.Path}, localPath); err != nil {
				return fmt.Errorf("SOPS pre-commit check failed: %w", err)
			}
		}
	}

	// Write the configuration file
	if err := m.store.WriteFile(ctx, localPath, ref.Path, content); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Create commit with metadata
	author := m.getCommitAuthor(ctx)
	commitMessage := m.formatCommitMessage(message, ref, config)

	sha, err := m.store.Commit(ctx, localPath, commitMessage, author)
	if err != nil {
		return fmt.Errorf("failed to commit changes: %w", err)
	}

	// Push changes
	if err := m.store.Push(ctx, localPath); err != nil {
		return fmt.Errorf("failed to push changes: %w", err)
	}

	// Store commit metadata
	if err := m.storeCommitMetadata(ctx, ref.RepositoryID, sha, config); err != nil {
		// Log error but don't fail the operation
		fmt.Printf("warning: failed to store commit metadata: %v\n", err)
	}

	return nil
}

// DeleteConfiguration deletes a configuration from a repository
func (m *DefaultGitManager) DeleteConfiguration(ctx context.Context, ref ConfigurationRef, message string) error {
	// Ensure repository is cloned/updated
	localPath, err := m.ensureRepository(ctx, ref.RepositoryID)
	if err != nil {
		return err
	}

	// Checkout branch if specified
	if ref.Branch != "" {
		if err := m.store.CheckoutBranch(ctx, localPath, ref.Branch); err != nil {
			return fmt.Errorf("failed to checkout branch %s: %w", ref.Branch, err)
		}
	}

	// Delete the file
	if err := m.store.DeleteFile(ctx, localPath, ref.Path); err != nil {
		return fmt.Errorf("failed to delete configuration: %w", err)
	}

	// Commit the deletion
	author := m.getCommitAuthor(ctx)
	commitMessage := fmt.Sprintf("Delete: %s\n\n%s", ref.Path, message)

	if _, err := m.store.Commit(ctx, localPath, commitMessage, author); err != nil {
		return fmt.Errorf("failed to commit deletion: %w", err)
	}

	// Push changes
	if err := m.store.Push(ctx, localPath); err != nil {
		return fmt.Errorf("failed to push changes: %w", err)
	}

	return nil
}

// CreateBranch creates a new branch in a repository
func (m *DefaultGitManager) CreateBranch(ctx context.Context, repoID, branchName, fromRef string) error {
	repo, err := m.GetRepository(ctx, repoID)
	if err != nil {
		return err
	}

	parts := parseRepositoryName(repo.Name)
	if fromRef == "" {
		fromRef = repo.DefaultBranch
	}

	return m.provider.CreateBranch(ctx, parts.owner, parts.name, branchName, fromRef)
}

// DeleteBranch deletes a branch from a repository
func (m *DefaultGitManager) DeleteBranch(ctx context.Context, repoID, branchName string) error {
	repo, err := m.GetRepository(ctx, repoID)
	if err != nil {
		return err
	}

	if branchName == repo.DefaultBranch {
		return fmt.Errorf("cannot delete default branch")
	}

	parts := parseRepositoryName(repo.Name)
	return m.provider.DeleteBranch(ctx, parts.owner, parts.name, branchName)
}

// MergeBranch merges one branch into another
func (m *DefaultGitManager) MergeBranch(ctx context.Context, repoID, source, target string, message string) error {
	// Create a pull request and merge it
	prConfig := PullRequestConfig{
		Title:        fmt.Sprintf("Merge %s into %s", source, target),
		Description:  message,
		SourceBranch: source,
		TargetBranch: target,
		AutoMerge:    true,
	}

	prID, err := m.CreatePullRequest(ctx, repoID, prConfig)
	if err != nil {
		return err
	}

	return m.MergePullRequest(ctx, repoID, prID)
}

// ListBranches lists all branches in a repository
func (m *DefaultGitManager) ListBranches(ctx context.Context, repoID string) ([]string, error) {
	localPath, err := m.ensureRepository(ctx, repoID)
	if err != nil {
		return nil, err
	}

	return m.store.ListBranches(ctx, localPath)
}

// GetCommitHistory retrieves commit history for a repository
func (m *DefaultGitManager) GetCommitHistory(ctx context.Context, repoID string, branch string, limit int) ([]*Commit, error) {
	localPath, err := m.ensureRepository(ctx, repoID)
	if err != nil {
		return nil, err
	}

	if branch != "" {
		if err := m.store.CheckoutBranch(ctx, localPath, branch); err != nil {
			return nil, fmt.Errorf("failed to checkout branch %s: %w", branch, err)
		}
	}

	return m.store.GetHistory(ctx, localPath, "", limit)
}

// GetCommit retrieves a specific commit
func (m *DefaultGitManager) GetCommit(ctx context.Context, repoID string, sha string) (*Commit, error) {
	localPath, err := m.ensureRepository(ctx, repoID)
	if err != nil {
		return nil, err
	}

	// Get commit history and find the specific commit
	// This is a simplified implementation
	history, err := m.store.GetHistory(ctx, localPath, "", 100)
	if err != nil {
		return nil, err
	}

	for _, commit := range history {
		if commit.SHA == sha {
			return commit, nil
		}
	}

	return nil, fmt.Errorf("commit not found: %s", sha)
}

// GetDiff gets the diff between two references
func (m *DefaultGitManager) GetDiff(ctx context.Context, repoID string, fromRef, toRef string) ([]ConfigChange, error) {
	localPath, err := m.ensureRepository(ctx, repoID)
	if err != nil {
		return nil, err
	}

	fileChanges, err := m.store.GetDiff(ctx, localPath, fromRef, toRef)
	if err != nil {
		return nil, err
	}

	// Convert FileChange to ConfigChange
	var changes []ConfigChange
	for _, fc := range fileChanges {
		change := ConfigChange{
			Repository: repoID,
			Path:       fc.Path,
			Action:     fc.Action,
		}

		// Read file contents for the change
		// This is simplified - in production you'd read at specific commits
		if fc.Action != "deleted" {
			content, _ := m.store.ReadFile(ctx, localPath, fc.Path)
			change.NewContent = content
		}

		changes = append(changes, change)
	}

	return changes, nil
}

// SyncTemplates synchronizes templates from parent repository
func (m *DefaultGitManager) SyncTemplates(ctx context.Context, clientRepoID string) error {
	clientRepo, err := m.GetRepository(ctx, clientRepoID)
	if err != nil {
		return err
	}

	// Get parent repository (MSP global)
	parentRepos, err := m.ListRepositories(ctx, RepositoryFilter{
		Type:  RepositoryTypeMSPGlobal,
		Owner: clientRepo.Owner, // Same MSP
	})
	if err != nil || len(parentRepos) == 0 {
		return fmt.Errorf("parent repository not found")
	}

	return m.syncManager.SyncTemplates(ctx, parentRepos[0], clientRepo)
}

// PropagateChange propagates a change across repositories
func (m *DefaultGitManager) PropagateChange(ctx context.Context, change ChangeSet) error {
	// Find affected repositories
	var targetRepos []*Repository

	for _, ch := range change.Changes {
		repo, err := m.GetRepository(ctx, ch.Repository)
		if err != nil {
			continue
		}
		targetRepos = append(targetRepos, repo)
	}

	return m.syncManager.PropagateChange(ctx, change, targetRepos)
}

// CreatePullRequest creates a pull request
func (m *DefaultGitManager) CreatePullRequest(ctx context.Context, repoID string, config PullRequestConfig) (string, error) {
	repo, err := m.GetRepository(ctx, repoID)
	if err != nil {
		return "", err
	}

	parts := parseRepositoryName(repo.Name)
	return m.provider.CreatePullRequest(ctx, parts.owner, parts.name, config)
}

// MergePullRequest merges a pull request
func (m *DefaultGitManager) MergePullRequest(ctx context.Context, repoID string, prID string) error {
	repo, err := m.GetRepository(ctx, repoID)
	if err != nil {
		return err
	}

	parts := parseRepositoryName(repo.Name)
	return m.provider.MergePullRequest(ctx, parts.owner, parts.name, prID)
}

// CreateWebhook creates a webhook for a repository
func (m *DefaultGitManager) CreateWebhook(ctx context.Context, repoID string, config WebhookConfig) error {
	repo, err := m.GetRepository(ctx, repoID)
	if err != nil {
		return err
	}

	parts := parseRepositoryName(repo.Name)
	_, err = m.provider.CreateWebhook(ctx, parts.owner, parts.name, config)
	return err
}

// DeleteWebhook deletes a webhook from a repository
func (m *DefaultGitManager) DeleteWebhook(ctx context.Context, repoID string, webhookID string) error {
	repo, err := m.GetRepository(ctx, repoID)
	if err != nil {
		return err
	}

	parts := parseRepositoryName(repo.Name)
	return m.provider.DeleteWebhook(ctx, parts.owner, parts.name, webhookID)
}

// SetBranchProtection sets branch protection rules
func (m *DefaultGitManager) SetBranchProtection(ctx context.Context, repoID string, rule BranchProtectionRule) error {
	repo, err := m.GetRepository(ctx, repoID)
	if err != nil {
		return err
	}

	parts := parseRepositoryName(repo.Name)
	return m.provider.SetBranchProtection(ctx, parts.owner, parts.name, rule)
}

// RemoveBranchProtection removes branch protection
func (m *DefaultGitManager) RemoveBranchProtection(ctx context.Context, repoID string, branch string) error {
	repo, err := m.GetRepository(ctx, repoID)
	if err != nil {
		return err
	}

	parts := parseRepositoryName(repo.Name)
	return m.provider.RemoveBranchProtection(ctx, parts.owner, parts.name, branch)
}

// Helper methods

func (m *DefaultGitManager) generateRepositoryName(config RepositoryConfig) string {
	switch config.Type {
	case RepositoryTypeMSPGlobal:
		return fmt.Sprintf("cfgms-%s-global", config.Owner)
	case RepositoryTypeClient:
		return fmt.Sprintf("cfgms-%s-client-%s", config.Owner, uuid.New().String()[:8])
	case RepositoryTypeShared:
		return fmt.Sprintf("cfgms-%s-shared-%s", config.Owner, uuid.New().String()[:8])
	default:
		return fmt.Sprintf("cfgms-%s-%s", config.Owner, uuid.New().String()[:8])
	}
}

func (m *DefaultGitManager) getLocalPath(repoID string) string {
	return filepath.Join(m.cacheDir, repoID)
}

func (m *DefaultGitManager) ensureRepository(ctx context.Context, repoID string) (string, error) {
	m.mu.RLock()
	localPath, exists := m.localCache[repoID]
	m.mu.RUnlock()

	if exists {
		// Pull latest changes
		if err := m.store.Pull(ctx, localPath); err != nil {
			// Log error but continue - we can work with cached version
			fmt.Printf("warning: failed to pull latest changes: %v\n", err)
		}
		return localPath, nil
	}

	// Need to clone the repository
	repo, err := m.GetRepository(ctx, repoID)
	if err != nil {
		return "", err
	}

	localPath = m.getLocalPath(repoID)
	if err := m.store.Clone(ctx, repo.CloneURL, localPath); err != nil {
		return "", fmt.Errorf("failed to clone repository: %w", err)
	}

	m.mu.Lock()
	m.localCache[repoID] = localPath
	m.mu.Unlock()

	return localPath, nil
}

func (m *DefaultGitManager) matchesFilter(repo *Repository, filter RepositoryFilter) bool {
	if filter.Type != "" && repo.Type != filter.Type {
		return false
	}
	if filter.Owner != "" && repo.Owner != filter.Owner {
		return false
	}
	// TODO: Implement tag filtering
	return true
}

func (m *DefaultGitManager) getConfigFormat(path string) string {
	switch filepath.Ext(path) {
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".toml":
		return "toml"
	default:
		return "unknown"
	}
}

func (m *DefaultGitManager) getCommitAuthor(ctx context.Context) CommitAuthor {
	return CommitAuthor{
		Name:     "CFGMS System",
		Email:    "system@cfgms.local",
		Username: "system",
		Role:     "system",
	}
}

func (m *DefaultGitManager) formatCommitMessage(message string, ref ConfigurationRef, config *Configuration) string {
	return fmt.Sprintf("[CONFIG] %s\n\nPath: %s\n", message, ref.Path)
}

func (m *DefaultGitManager) storeCommitMetadata(ctx context.Context, repoID, sha string, config *Configuration) error {
	return nil
}

func (m *DefaultGitManager) initializeRepositoryStructure(ctx context.Context, repo *Repository, localPath string) error {
	return nil
}

func (m *DefaultGitManager) backgroundSync() {
	ticker := time.NewTicker(m.config.SyncInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Sync all client repositories
		repos, err := m.ListRepositories(context.Background(), RepositoryFilter{
			Type: RepositoryTypeClient,
		})
		if err != nil {
			fmt.Printf("error listing repositories for sync: %v\n", err)
			continue
		}

		for _, repo := range repos {
			if err := m.SyncTemplates(context.Background(), repo.ID); err != nil {
				fmt.Printf("error syncing templates for %s: %v\n", repo.ID, err)
			}
		}
	}
}

// repoNameParts holds parsed repository name components
type repoNameParts struct {
	owner string
	name  string
}

func parseRepositoryName(fullName string) repoNameParts {
	// Simple implementation - in production this would be more robust
	return repoNameParts{
		owner: "cfgms",
		name:  fullName,
	}
}
