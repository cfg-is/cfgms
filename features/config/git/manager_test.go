package git

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock implementations for testing

type MockGitProvider struct {
	mock.Mock
}

func (m *MockGitProvider) CreateRepository(ctx context.Context, config RepositoryConfig) (*Repository, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(*Repository), args.Error(1)
}

func (m *MockGitProvider) GetRepository(ctx context.Context, owner, name string) (*Repository, error) {
	args := m.Called(ctx, owner, name)
	return args.Get(0).(*Repository), args.Error(1)
}

func (m *MockGitProvider) DeleteRepository(ctx context.Context, owner, name string) error {
	args := m.Called(ctx, owner, name)
	return args.Error(0)
}

func (m *MockGitProvider) CreateBranch(ctx context.Context, owner, repo, branch, fromRef string) error {
	args := m.Called(ctx, owner, repo, branch, fromRef)
	return args.Error(0)
}

func (m *MockGitProvider) DeleteBranch(ctx context.Context, owner, repo, branch string) error {
	args := m.Called(ctx, owner, repo, branch)
	return args.Error(0)
}

func (m *MockGitProvider) GetDefaultBranch(ctx context.Context, owner, repo string) (string, error) {
	args := m.Called(ctx, owner, repo)
	return args.String(0), args.Error(1)
}

func (m *MockGitProvider) CreatePullRequest(ctx context.Context, owner, repo string, config PullRequestConfig) (string, error) {
	args := m.Called(ctx, owner, repo, config)
	return args.String(0), args.Error(1)
}

func (m *MockGitProvider) MergePullRequest(ctx context.Context, owner, repo, prID string) error {
	args := m.Called(ctx, owner, repo, prID)
	return args.Error(0)
}

func (m *MockGitProvider) CreateWebhook(ctx context.Context, owner, repo string, config WebhookConfig) (string, error) {
	args := m.Called(ctx, owner, repo, config)
	return args.String(0), args.Error(1)
}

func (m *MockGitProvider) DeleteWebhook(ctx context.Context, owner, repo, webhookID string) error {
	args := m.Called(ctx, owner, repo, webhookID)
	return args.Error(0)
}

func (m *MockGitProvider) SetBranchProtection(ctx context.Context, owner, repo string, rule BranchProtectionRule) error {
	args := m.Called(ctx, owner, repo, rule)
	return args.Error(0)
}

func (m *MockGitProvider) RemoveBranchProtection(ctx context.Context, owner, repo, branch string) error {
	args := m.Called(ctx, owner, repo, branch)
	return args.Error(0)
}

type MockRepositoryStore struct {
	mock.Mock
}

func (m *MockRepositoryStore) Clone(ctx context.Context, cloneURL, localPath string) error {
	args := m.Called(ctx, cloneURL, localPath)
	return args.Error(0)
}

func (m *MockRepositoryStore) Pull(ctx context.Context, localPath string) error {
	args := m.Called(ctx, localPath)
	return args.Error(0)
}

func (m *MockRepositoryStore) Push(ctx context.Context, localPath string) error {
	args := m.Called(ctx, localPath)
	return args.Error(0)
}

func (m *MockRepositoryStore) ReadFile(ctx context.Context, localPath, filePath string) ([]byte, error) {
	args := m.Called(ctx, localPath, filePath)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockRepositoryStore) WriteFile(ctx context.Context, localPath, filePath string, content []byte) error {
	args := m.Called(ctx, localPath, filePath, content)
	return args.Error(0)
}

func (m *MockRepositoryStore) DeleteFile(ctx context.Context, localPath, filePath string) error {
	args := m.Called(ctx, localPath, filePath)
	return args.Error(0)
}

func (m *MockRepositoryStore) Commit(ctx context.Context, localPath string, message string, author CommitAuthor) (string, error) {
	args := m.Called(ctx, localPath, message, author)
	return args.String(0), args.Error(1)
}

func (m *MockRepositoryStore) GetHistory(ctx context.Context, localPath, filePath string, limit int) ([]*Commit, error) {
	args := m.Called(ctx, localPath, filePath, limit)
	return args.Get(0).([]*Commit), args.Error(1)
}

func (m *MockRepositoryStore) GetDiff(ctx context.Context, localPath string, fromRef, toRef string) ([]FileChange, error) {
	args := m.Called(ctx, localPath, fromRef, toRef)
	return args.Get(0).([]FileChange), args.Error(1)
}

func (m *MockRepositoryStore) CreateBranch(ctx context.Context, localPath, branchName string) error {
	args := m.Called(ctx, localPath, branchName)
	return args.Error(0)
}

func (m *MockRepositoryStore) CheckoutBranch(ctx context.Context, localPath, branchName string) error {
	args := m.Called(ctx, localPath, branchName)
	return args.Error(0)
}

func (m *MockRepositoryStore) ListBranches(ctx context.Context, localPath string) ([]string, error) {
	args := m.Called(ctx, localPath)
	return args.Get(0).([]string), args.Error(1)
}

// Test functions

func TestGitManager_CreateRepository(t *testing.T) {
	// Setup mocks
	mockProvider := &MockGitProvider{}
	mockStore := &MockRepositoryStore{}
	
	config := GitManagerConfig{
		CacheDir:      "/tmp/test-cache",
		DefaultBranch: "main",
		EnableHooks:   false, // Disable hooks for simple test
	}
	
	manager := NewGitManager(mockProvider, mockStore, config)
	
	// Test repository configuration
	repoConfig := RepositoryConfig{
		Type:        RepositoryTypeClient,
		Name:        "test-repo",
		Description: "Test repository",
		Owner:       "test-owner",
		Provider:    "github",
		Private:     true,
	}
	
	// Expected config after manager processing (with default branch set)
	expectedConfig := repoConfig
	expectedConfig.InitialBranch = "main"
	
	// Expected repository response
	expectedRepo := &Repository{
		ID:            "github:test-owner/test-repo",
		Type:          RepositoryTypeClient,
		Name:          "test-repo",
		Owner:         "test-owner",
		Provider:      "github",
		CloneURL:      "https://github.com/test-owner/test-repo.git",
		DefaultBranch: "main",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	
	// Setup mock expectations
	mockProvider.On("CreateRepository", mock.Anything, expectedConfig).Return(expectedRepo, nil)
	mockStore.On("Clone", mock.Anything, expectedRepo.CloneURL, mock.AnythingOfType("string")).Return(nil)
	
	// Execute test
	ctx := context.Background()
	result, err := manager.CreateRepository(ctx, repoConfig)
	
	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, expectedRepo.ID, result.ID)
	assert.Equal(t, expectedRepo.Name, result.Name)
	assert.Equal(t, expectedRepo.Type, result.Type)
	
	// Verify mock calls
	mockProvider.AssertExpectations(t)
	mockStore.AssertExpectations(t)
}

func TestGitManager_SaveConfiguration(t *testing.T) {
	// Setup mocks
	mockProvider := &MockGitProvider{}
	mockStore := &MockRepositoryStore{}
	
	config := GitManagerConfig{
		CacheDir:      "/tmp/test-cache",
		DefaultBranch: "main",
		EnableHooks:   false,
	}
	
	manager := NewGitManager(mockProvider, mockStore, config)
	
	// Add a test repository to the manager
	testRepo := &Repository{
		ID:            "test-repo-1",
		Name:          "test-repo",
		DefaultBranch: "main",
		CloneURL:      "https://github.com/test/repo.git",
	}
	manager.repositories["test-repo-1"] = testRepo
	manager.localCache["test-repo-1"] = "/tmp/test-cache/test-repo-1"
	
	// Test configuration
	configRef := ConfigurationRef{
		RepositoryID: "test-repo-1",
		Path:         "config.yaml",
	}
	
	testConfig := &Configuration{
		Path:    "config.yaml",
		Content: []byte("test: configuration"),
		Format:  "yaml",
	}
	
	// Setup mock expectations
	mockStore.On("Pull", mock.Anything, "/tmp/test-cache/test-repo-1").Return(nil)
	mockStore.On("WriteFile", mock.Anything, "/tmp/test-cache/test-repo-1", "config.yaml", testConfig.Content).Return(nil)
	mockStore.On("Commit", mock.Anything, "/tmp/test-cache/test-repo-1", mock.AnythingOfType("string"), mock.AnythingOfType("CommitAuthor")).Return("abc123", nil)
	mockStore.On("Push", mock.Anything, "/tmp/test-cache/test-repo-1").Return(nil)
	
	// Execute test
	ctx := context.Background()
	err := manager.SaveConfiguration(ctx, configRef, testConfig, "Update configuration")
	
	// Assertions
	assert.NoError(t, err)
	
	// Verify mock calls
	mockStore.AssertExpectations(t)
}

func TestGitManager_GetConfiguration(t *testing.T) {
	// Setup mocks
	mockProvider := &MockGitProvider{}
	mockStore := &MockRepositoryStore{}
	
	config := GitManagerConfig{
		CacheDir:      "/tmp/test-cache",
		DefaultBranch: "main",
	}
	
	manager := NewGitManager(mockProvider, mockStore, config)
	
	// Add a test repository to the manager
	testRepo := &Repository{
		ID:   "test-repo-1",
		Name: "test-repo",
	}
	manager.repositories["test-repo-1"] = testRepo
	manager.localCache["test-repo-1"] = "/tmp/test-cache/test-repo-1"
	
	// Test configuration reference
	configRef := ConfigurationRef{
		RepositoryID: "test-repo-1",
		Path:         "config.yaml",
	}
	
	// Expected file content
	expectedContent := []byte("test: configuration")
	expectedCommits := []*Commit{
		{
			SHA:       "abc123",
			Message:   "Test commit",
			Timestamp: time.Now(),
			Author: CommitAuthor{
				Name:  "Test Author",
				Email: "test@example.com",
			},
		},
	}
	
	// Setup mock expectations
	mockStore.On("Pull", mock.Anything, "/tmp/test-cache/test-repo-1").Return(nil)
	mockStore.On("ReadFile", mock.Anything, "/tmp/test-cache/test-repo-1", "config.yaml").Return(expectedContent, nil)
	mockStore.On("GetHistory", mock.Anything, "/tmp/test-cache/test-repo-1", "config.yaml", 1).Return(expectedCommits, nil)
	
	// Execute test
	ctx := context.Background()
	result, err := manager.GetConfiguration(ctx, configRef)
	
	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "config.yaml", result.Path)
	assert.Equal(t, expectedContent, result.Content)
	assert.Equal(t, "yaml", result.Format)
	assert.Equal(t, "Test Author", result.Metadata.Author)
	
	// Verify mock calls
	mockStore.AssertExpectations(t)
}

func TestGitManager_ListRepositories(t *testing.T) {
	// Setup mocks
	mockProvider := &MockGitProvider{}
	mockStore := &MockRepositoryStore{}
	
	config := GitManagerConfig{
		CacheDir: "/tmp/test-cache",
	}
	
	manager := NewGitManager(mockProvider, mockStore, config)
	
	// Add test repositories
	repo1 := &Repository{
		ID:    "repo-1",
		Type:  RepositoryTypeClient,
		Owner: "client-1",
	}
	repo2 := &Repository{
		ID:    "repo-2",
		Type:  RepositoryTypeMSPGlobal,
		Owner: "msp-1",
	}
	repo3 := &Repository{
		ID:    "repo-3",
		Type:  RepositoryTypeClient,
		Owner: "client-2",
	}
	
	manager.repositories["repo-1"] = repo1
	manager.repositories["repo-2"] = repo2
	manager.repositories["repo-3"] = repo3
	
	// Test filter for client repositories
	filter := RepositoryFilter{
		Type: RepositoryTypeClient,
	}
	
	// Execute test
	ctx := context.Background()
	results, err := manager.ListRepositories(ctx, filter)
	
	// Assertions
	assert.NoError(t, err)
	assert.Len(t, results, 2) // Should return repo-1 and repo-3
	
	// Verify all returned repos are client type
	for _, repo := range results {
		assert.Equal(t, RepositoryTypeClient, repo.Type)
	}
}

func TestGitManager_CreateBranch(t *testing.T) {
	// Setup mocks
	mockProvider := &MockGitProvider{}
	mockStore := &MockRepositoryStore{}
	
	config := GitManagerConfig{
		CacheDir: "/tmp/test-cache",
	}
	
	manager := NewGitManager(mockProvider, mockStore, config)
	
	// Add test repository
	testRepo := &Repository{
		ID:            "test-repo-1",
		Name:          "test-repo",
		DefaultBranch: "main",
	}
	manager.repositories["test-repo-1"] = testRepo
	
	// Setup mock expectations
	mockProvider.On("CreateBranch", mock.Anything, "cfgms", "test-repo", "feature-branch", "main").Return(nil)
	
	// Execute test
	ctx := context.Background()
	err := manager.CreateBranch(ctx, "test-repo-1", "feature-branch", "")
	
	// Assertions
	assert.NoError(t, err)
	
	// Verify mock calls
	mockProvider.AssertExpectations(t)
}

func TestGitManager_GenerateRepositoryName(t *testing.T) {
	mockProvider := &MockGitProvider{}
	mockStore := &MockRepositoryStore{}
	
	config := GitManagerConfig{}
	manager := NewGitManager(mockProvider, mockStore, config)
	
	tests := []struct {
		name     string
		config   RepositoryConfig
		expected string
	}{
		{
			name: "MSP Global Repository",
			config: RepositoryConfig{
				Type:  RepositoryTypeMSPGlobal,
				Owner: "msp-123",
			},
			expected: "cfgms-msp-123-global",
		},
		{
			name: "Client Repository",
			config: RepositoryConfig{
				Type:  RepositoryTypeClient,
				Owner: "msp-123",
			},
			expected: "cfgms-msp-123-client-", // UUID will be appended
		},
		{
			name: "Shared Repository",
			config: RepositoryConfig{
				Type:  RepositoryTypeShared,
				Owner: "msp-123",
			},
			expected: "cfgms-msp-123-shared-", // UUID will be appended
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.generateRepositoryName(tt.config)
			
			if tt.config.Type == RepositoryTypeMSPGlobal {
				assert.Equal(t, tt.expected, result)
			} else {
				// For client and shared repos, check prefix
				assert.True(t, strings.HasPrefix(result, tt.expected))
				// Should have UUID suffix
				assert.Greater(t, len(result), len(tt.expected))
			}
		})
	}
}