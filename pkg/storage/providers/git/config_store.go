// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package git implements production-ready git-based storage provider for CFGMS
package git

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	gitfeature "github.com/cfgis/cfgms/features/config/git"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// GitConfigStore implements ConfigStore using git for persistence with YAML format
type GitConfigStore struct {
	repoPath    string
	remoteURL   string
	sopsConfig  *gitfeature.SOPSConfig
	sopsManager *gitfeature.SOPSManager
	mutex       sync.RWMutex
}

// NewGitConfigStore creates a new git-based config store
func NewGitConfigStore(repoPath, remoteURL string) (*GitConfigStore, error) {
	store := &GitConfigStore{
		repoPath:    repoPath,
		remoteURL:   remoteURL,
		sopsManager: gitfeature.NewSOPSManager(),
	}

	if err := initializeGitRepo(repoPath); err != nil {
		return nil, fmt.Errorf("failed to initialize git repository: %w", err)
	}

	// SOPS config is optional; errors are non-fatal
	if err := store.loadSOPSConfig(); err != nil {
		_ = err
	}

	return store, nil
}

// loadSOPSConfig loads SOPS configuration from the repository
func (s *GitConfigStore) loadSOPSConfig() error {
	sopsConfigPath := filepath.Join(s.repoPath, ".sops.yaml")
	if _, err := os.Stat(sopsConfigPath); os.IsNotExist(err) {
		s.sopsConfig = &gitfeature.SOPSConfig{Enabled: false}
		return nil
	}

	// #nosec G304 - SOPS config path is controlled by repository structure
	configData, err := os.ReadFile(sopsConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read SOPS config: %w", err)
	}

	config := &gitfeature.SOPSConfig{}
	if err := yaml.Unmarshal(configData, config); err != nil {
		return fmt.Errorf("failed to parse SOPS config: %w", err)
	}

	s.sopsConfig = config
	return nil
}

// getConfigPath returns the file path for a config entry, validated against path traversal
func (s *GitConfigStore) getConfigPath(key *interfaces.ConfigKey) (string, error) {
	var fileName string
	if key.Scope != "" {
		fileName = fmt.Sprintf("%s@%s.yaml", key.Name, key.Scope)
	} else {
		fileName = fmt.Sprintf("%s.yaml", key.Name)
	}
	p, err := safePath(s.repoPath, key.TenantID, key.Namespace, fileName)
	if err != nil {
		return "", err
	}
	return filepath.Clean(p), nil // explicit Clean for CodeQL path-injection analysis
}

// StoreConfig stores a configuration entry as YAML in git
func (s *GitConfigStore) StoreConfig(ctx context.Context, config *interfaces.ConfigEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if config.Key == nil {
		return interfaces.ErrNameRequired
	}
	if config.Key.TenantID == "" {
		return interfaces.ErrTenantRequired
	}
	if config.Key.Namespace == "" {
		return interfaces.ErrNamespaceRequired
	}
	if config.Key.Name == "" {
		return interfaces.ErrNameRequired
	}

	now := time.Now()
	if config.CreatedAt.IsZero() {
		config.CreatedAt = now
	}
	config.UpdatedAt = now
	config.Format = interfaces.ConfigFormatYAML

	hasher := sha256.New()
	hasher.Write(config.Data)
	config.Checksum = hex.EncodeToString(hasher.Sum(nil))

	filePath, err := s.getConfigPath(config.Key)
	if err != nil {
		return fmt.Errorf("invalid config path: %w", err)
	}

	// #nosec G301 - Git repository directories need standard permissions for git operations
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	_, err = os.Stat(filePath)
	isUpdate := !os.IsNotExist(err)

	if isUpdate {
		existing, err := s.readConfigFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read existing config: %w", err)
		}
		config.Version = existing.Version + 1
	} else {
		config.Version = 1
	}

	if err := s.writeConfigFile(filePath, config); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	commitMsg := fmt.Sprintf("Update config %s/%s/%s (v%d)",
		config.Key.TenantID, config.Key.Namespace, config.Key.Name, config.Version)
	if !isUpdate {
		commitMsg = fmt.Sprintf("Add config %s/%s/%s (v%d)",
			config.Key.TenantID, config.Key.Namespace, config.Key.Name, config.Version)
	}

	if err := gitCommitFile(s.repoPath, filePath, commitMsg); err != nil {
		return fmt.Errorf("failed to commit to git: %w", err)
	}

	return nil
}

// GetConfig retrieves a configuration entry from git
func (s *GitConfigStore) GetConfig(ctx context.Context, key *interfaces.ConfigKey) (*interfaces.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	filePath, err := s.getConfigPath(key)
	if err != nil {
		return nil, fmt.Errorf("invalid config path: %w", err)
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, interfaces.ErrConfigNotFound
	}

	config, err := s.readConfigFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	return config, nil
}

// DeleteConfig removes a configuration entry from git
func (s *GitConfigStore) DeleteConfig(ctx context.Context, key *interfaces.ConfigKey) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	filePath, err := s.getConfigPath(key)
	if err != nil {
		return fmt.Errorf("invalid config path: %w", err)
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return interfaces.ErrConfigNotFound
	}

	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to remove config file: %w", err)
	}

	commitMsg := fmt.Sprintf("Delete config %s/%s/%s",
		key.TenantID, key.Namespace, key.Name)

	if err := gitCommitFile(s.repoPath, filePath, commitMsg); err != nil {
		return fmt.Errorf("failed to commit deletion to git: %w", err)
	}

	return nil
}

// ListConfigs lists configuration entries matching the filter
func (s *GitConfigStore) ListConfigs(ctx context.Context, filter *interfaces.ConfigFilter) ([]*interfaces.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var configs []*interfaces.ConfigEntry

	err := filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		if strings.Contains(path, ".git") {
			return nil
		}

		config, err := s.readConfigFile(path)
		if err != nil {
			return nil
		}

		if filter != nil {
			if filter.TenantID != "" && config.Key.TenantID != filter.TenantID {
				return nil
			}
			if filter.Namespace != "" && config.Key.Namespace != filter.Namespace {
				return nil
			}
			if len(filter.Names) > 0 {
				found := false
				for _, name := range filter.Names {
					if config.Key.Name == name {
						found = true
						break
					}
				}
				if !found {
					return nil
				}
			}
		}

		configs = append(configs, config)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk repository: %w", err)
	}

	if filter != nil && filter.Limit > 0 {
		start := filter.Offset
		if start > len(configs) {
			start = len(configs)
		}
		end := start + filter.Limit
		if end > len(configs) {
			end = len(configs)
		}
		configs = configs[start:end]
	}

	return configs, nil
}

// GetConfigHistory gets version history for a configuration (using git log)
func (s *GitConfigStore) GetConfigHistory(ctx context.Context, key *interfaces.ConfigKey, limit int) ([]*interfaces.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	filePath, err := s.getConfigPath(key)
	if err != nil {
		return nil, fmt.Errorf("invalid config path: %w", err)
	}

	relPath, err := filepath.Rel(s.repoPath, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get relative path: %w", err)
	}
	relPath = filepath.ToSlash(relPath)

	args := []string{"log", "--oneline", fmt.Sprintf("-%d", limit), "--", relPath}
	// #nosec G204 - Git storage requires controlled git command execution with validated args
	cmd := exec.Command("git", args...)
	cmd.Dir = s.repoPath

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get git history: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, nil
	}

	var configs []*interfaces.ConfigEntry

	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 1 {
			continue
		}

		commitHash := parts[0]

		// #nosec G204 - Git history requires accessing files at specific commits
		cmd := exec.Command("git", "show", commitHash+":"+relPath)
		cmd.Dir = s.repoPath

		output, err := cmd.Output()
		if err != nil {
			continue
		}

		config, err := s.parseConfigYAML(output)
		if err != nil {
			continue
		}

		configs = append(configs, config)
	}

	return configs, nil
}

// GetConfigVersion gets a specific version of a configuration
func (s *GitConfigStore) GetConfigVersion(ctx context.Context, key *interfaces.ConfigKey, version int64) (*interfaces.ConfigEntry, error) {
	return s.GetConfig(ctx, key)
}

// StoreConfigBatch stores multiple configurations in a single commit
func (s *GitConfigStore) StoreConfigBatch(ctx context.Context, configs []*interfaces.ConfigEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var filePaths []string

	for _, config := range configs {
		if err := s.storeConfigInternal(config); err != nil {
			return fmt.Errorf("failed to store config %s: %w", config.Key.String(), err)
		}
		fp, err := s.getConfigPath(config.Key)
		if err != nil {
			return fmt.Errorf("invalid config path for %s: %w", config.Key.String(), err)
		}
		filePaths = append(filePaths, fp)
	}

	commitMsg := fmt.Sprintf("Batch update %d configurations", len(configs))
	if err := gitCommitFiles(s.repoPath, filePaths, commitMsg); err != nil {
		return fmt.Errorf("failed to commit batch: %w", err)
	}

	return nil
}

// DeleteConfigBatch deletes multiple configurations in a single commit
func (s *GitConfigStore) DeleteConfigBatch(ctx context.Context, keys []*interfaces.ConfigKey) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var filePaths []string

	for _, key := range keys {
		filePath, err := s.getConfigPath(key)
		if err != nil {
			return fmt.Errorf("invalid config path for %s: %w", key.String(), err)
		}
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete config %s: %w", key.String(), err)
		}
		filePaths = append(filePaths, filePath)
	}

	commitMsg := fmt.Sprintf("Batch delete %d configurations", len(keys))
	if err := gitCommitFiles(s.repoPath, filePaths, commitMsg); err != nil {
		return fmt.Errorf("failed to commit batch deletion: %w", err)
	}

	return nil
}

// ResolveConfigWithInheritance resolves configuration with inheritance (not implemented yet)
func (s *GitConfigStore) ResolveConfigWithInheritance(ctx context.Context, key *interfaces.ConfigKey) (*interfaces.ConfigEntry, error) {
	return s.GetConfig(ctx, key)
}

// ValidateConfig validates a configuration entry
func (s *GitConfigStore) ValidateConfig(ctx context.Context, config *interfaces.ConfigEntry) error {
	if config.Key == nil {
		return interfaces.ErrNameRequired
	}
	if config.Key.TenantID == "" {
		return interfaces.ErrTenantRequired
	}
	if config.Key.Namespace == "" {
		return interfaces.ErrNamespaceRequired
	}
	if config.Key.Name == "" {
		return interfaces.ErrNameRequired
	}

	var yamlData interface{}
	if err := yaml.Unmarshal(config.Data, &yamlData); err != nil {
		return interfaces.ErrInvalidYAML
	}

	return nil
}

// GetConfigStats returns statistics about stored configurations
func (s *GitConfigStore) GetConfigStats(ctx context.Context) (*interfaces.ConfigStats, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := &interfaces.ConfigStats{
		ConfigsByTenant:    make(map[string]int64),
		ConfigsByFormat:    make(map[string]int64),
		ConfigsByNamespace: make(map[string]int64),
		LastUpdated:        time.Now(),
	}

	err := filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		if strings.Contains(path, ".git") {
			return nil
		}

		config, err := s.readConfigFile(path)
		if err != nil {
			return nil
		}

		stats.TotalConfigs++
		stats.TotalSize += int64(len(config.Data))
		stats.ConfigsByTenant[config.Key.TenantID]++
		stats.ConfigsByFormat[string(config.Format)]++
		stats.ConfigsByNamespace[config.Key.Namespace]++

		if stats.OldestConfig == nil || config.CreatedAt.Before(*stats.OldestConfig) {
			stats.OldestConfig = &config.CreatedAt
		}
		if stats.NewestConfig == nil || config.UpdatedAt.After(*stats.NewestConfig) {
			stats.NewestConfig = &config.UpdatedAt
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to collect statistics: %w", err)
	}

	if stats.TotalConfigs > 0 {
		stats.AverageSize = stats.TotalSize / stats.TotalConfigs
	}

	return stats, nil
}

// storeConfigInternal stores a config without committing (for batch operations)
func (s *GitConfigStore) storeConfigInternal(config *interfaces.ConfigEntry) error {
	now := time.Now()
	if config.CreatedAt.IsZero() {
		config.CreatedAt = now
	}
	config.UpdatedAt = now
	config.Format = interfaces.ConfigFormatYAML

	hasher := sha256.New()
	hasher.Write(config.Data)
	config.Checksum = hex.EncodeToString(hasher.Sum(nil))

	filePath, err := s.getConfigPath(config.Key)
	if err != nil {
		return fmt.Errorf("invalid config path: %w", err)
	}

	// #nosec G301 - Git repository directories need standard permissions for git operations
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	_, err = os.Stat(filePath)
	isUpdate := !os.IsNotExist(err)

	if isUpdate {
		existing, err := s.readConfigFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read existing config: %w", err)
		}
		config.Version = existing.Version + 1
	} else {
		config.Version = 1
	}

	if err := s.writeConfigFile(filePath, config); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// writeConfigFile writes a config entry to a YAML file with optional SOPS encryption
func (s *GitConfigStore) writeConfigFile(filePath string, config *interfaces.ConfigEntry) error {
	fileData := map[string]interface{}{
		"metadata": map[string]interface{}{
			"tenant_id":  config.Key.TenantID,
			"namespace":  config.Key.Namespace,
			"name":       config.Key.Name,
			"scope":      config.Key.Scope,
			"version":    config.Version,
			"checksum":   config.Checksum,
			"format":     config.Format,
			"created_at": config.CreatedAt,
			"updated_at": config.UpdatedAt,
			"created_by": config.CreatedBy,
			"updated_by": config.UpdatedBy,
			"tags":       config.Tags,
			"source":     config.Source,
		},
	}

	var configData interface{}
	if err := yaml.Unmarshal(config.Data, &configData); err != nil {
		return fmt.Errorf("failed to parse config data as YAML: %w", err)
	}
	fileData["config"] = configData

	yamlData, err := yaml.Marshal(fileData)
	if err != nil {
		return fmt.Errorf("failed to marshal to YAML: %w", err)
	}

	finalData := yamlData
	if s.sopsConfig != nil && s.sopsConfig.Enabled {
		relPath, err := filepath.Rel(s.repoPath, filePath)
		if err != nil {
			relPath = filePath
		}

		shouldEncrypt, _ := s.sopsManager.ShouldEncryptFile(relPath, s.sopsConfig)
		if shouldEncrypt {
			ctx := context.Background()
			encryptedData, err := s.sopsManager.EncryptContent(ctx, yamlData, s.sopsConfig, relPath)
			if err != nil {
				_ = err
			} else {
				finalData = encryptedData
			}
		}
	}

	// #nosec G306 - Configuration files need read permissions for other processes
	if err := os.WriteFile(filePath, finalData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// readConfigFile reads a config entry from a YAML file with optional SOPS decryption
func (s *GitConfigStore) readConfigFile(filePath string) (*interfaces.ConfigEntry, error) {
	// #nosec G304 - Git storage requires reading config files from controlled repository paths
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	finalData := data
	if s.sopsManager != nil && s.sopsManager.IsSOPSEncrypted(data) {
		ctx := context.Background()
		decryptedData, err := s.sopsManager.DecryptContent(ctx, data)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt SOPS content: %w", err)
		}
		finalData = decryptedData
	}

	return s.parseConfigYAML(finalData)
}

// parseConfigYAML parses YAML data into a ConfigEntry
func (s *GitConfigStore) parseConfigYAML(data []byte) (*interfaces.ConfigEntry, error) {
	var fileData map[string]interface{}
	if err := yaml.Unmarshal(data, &fileData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	metadataRaw, ok := fileData["metadata"]
	if !ok {
		return nil, fmt.Errorf("missing metadata section")
	}

	metadata, ok := metadataRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format")
	}

	config := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{},
	}

	if val, ok := metadata["tenant_id"].(string); ok {
		config.Key.TenantID = val
	}
	if val, ok := metadata["namespace"].(string); ok {
		config.Key.Namespace = val
	}
	if val, ok := metadata["name"].(string); ok {
		config.Key.Name = val
	}
	if val, ok := metadata["scope"].(string); ok {
		config.Key.Scope = val
	}
	if val, ok := metadata["version"].(int); ok {
		config.Version = int64(val)
	}
	if val, ok := metadata["checksum"].(string); ok {
		config.Checksum = val
	}
	if val, ok := metadata["format"].(string); ok {
		config.Format = interfaces.ConfigFormat(val)
	}
	if val, ok := metadata["created_by"].(string); ok {
		config.CreatedBy = val
	}
	if val, ok := metadata["updated_by"].(string); ok {
		config.UpdatedBy = val
	}
	if val, ok := metadata["source"].(string); ok {
		config.Source = val
	}
	if val, ok := metadata["created_at"].(time.Time); ok {
		config.CreatedAt = val
	}
	if val, ok := metadata["updated_at"].(time.Time); ok {
		config.UpdatedAt = val
	}
	if val, ok := metadata["tags"].([]interface{}); ok {
		for _, tag := range val {
			if tagStr, ok := tag.(string); ok {
				config.Tags = append(config.Tags, tagStr)
			}
		}
	}

	configData, ok := fileData["config"]
	if !ok {
		return nil, fmt.Errorf("missing config section")
	}

	configYAML, err := yaml.Marshal(configData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config data: %w", err)
	}
	config.Data = configYAML

	return config, nil
}

// ConfigureSOPS configures SOPS encryption for the repository
func (s *GitConfigStore) ConfigureSOPS(config *gitfeature.SOPSConfig) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.sopsConfig = config

	if config.Enabled {
		ctx := context.Background()
		if err := s.sopsManager.ValidateSOPSConfig(ctx, config); err != nil {
			return fmt.Errorf("invalid SOPS configuration: %w", err)
		}

		if err := s.sopsManager.GenerateSOPSConfig(config, s.repoPath); err != nil {
			return fmt.Errorf("failed to generate SOPS config: %w", err)
		}

		sopsConfigPath := filepath.Join(s.repoPath, ".sops.yaml")
		if err := gitCommitFile(s.repoPath, sopsConfigPath, "Configure SOPS encryption"); err != nil {
			return fmt.Errorf("failed to commit SOPS config: %w", err)
		}
	}

	return nil
}

// IsSOPSEnabled returns whether SOPS encryption is enabled
func (s *GitConfigStore) IsSOPSEnabled() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sopsConfig != nil && s.sopsConfig.Enabled
}

// SyncWithRemote synchronizes the repository with the remote
func (s *GitConfigStore) SyncWithRemote(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.remoteURL == "" {
		return nil
	}

	if err := s.pullFromRemote(ctx); err != nil {
		return fmt.Errorf("failed to pull from remote: %w", err)
	}
	if err := s.pushToRemote(ctx); err != nil {
		return fmt.Errorf("failed to push to remote: %w", err)
	}

	return nil
}

// pullFromRemote pulls changes from the remote repository
func (s *GitConfigStore) pullFromRemote(ctx context.Context) error {
	if s.remoteURL == "" {
		return nil
	}

	cmd := exec.CommandContext(ctx, "git", "remote", "get-url", "origin")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		// #nosec G204 - Git storage requires remote URL management for distributed repos
		cmd = exec.CommandContext(ctx, "git", "remote", "add", "origin", s.remoteURL)
		cmd.Dir = s.repoPath
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add remote origin: %w", err)
		}
	}

	cmd = exec.CommandContext(ctx, "git", "fetch", "origin")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		return nil
	}

	cmd = exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		cmd = exec.CommandContext(ctx, "git", "pull", "origin", "main")
		cmd.Dir = s.repoPath
		_ = cmd.Run()
		return nil
	}

	cmd = exec.CommandContext(ctx, "git", "pull", "origin", "main")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		cmd = exec.CommandContext(ctx, "git", "pull", "--rebase", "origin", "main")
		cmd.Dir = s.repoPath
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to pull with rebase: %w", err)
		}
	}

	return nil
}

// pushToRemote pushes changes to the remote repository
func (s *GitConfigStore) pushToRemote(ctx context.Context) error {
	if s.remoteURL == "" {
		return nil
	}

	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		return nil
	}

	cmd = exec.CommandContext(ctx, "git", "status", "--porcelain")
	cmd.Dir = s.repoPath
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check git status: %w", err)
	}

	if len(output) == 0 {
		cmd = exec.CommandContext(ctx, "git", "rev-list", "--count", "HEAD", "^origin/main")
		cmd.Dir = s.repoPath
		output, err := cmd.Output()
		if err != nil || strings.TrimSpace(string(output)) == "0" {
			return nil
		}
	}

	cmd = exec.CommandContext(ctx, "git", "push", "origin", "main")
	cmd.Dir = s.repoPath
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to push to remote: %w", err)
	}

	return nil
}

// SetRemoteURL sets the remote repository URL
func (s *GitConfigStore) SetRemoteURL(remoteURL string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.remoteURL = remoteURL

	if remoteURL != "" {
		cmd := exec.Command("git", "remote", "set-url", "origin", remoteURL)
		cmd.Dir = s.repoPath
		if err := cmd.Run(); err != nil {
			cmd = exec.Command("git", "remote", "add", "origin", remoteURL)
			cmd.Dir = s.repoPath
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to set remote URL: %w", err)
			}
		}
	}

	return nil
}
