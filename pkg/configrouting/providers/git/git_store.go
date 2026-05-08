// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package git provides a read-only ConfigStore backed by an external HTTPS git repository.
// Credentials are fetched from pkg/secrets at transport time and never stored in struct fields.
package git

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	gitstorage "github.com/cfgis/cfgms/features/config/git/storage"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/security"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ErrReadOnlySource is returned by all write methods — external git repos are never written to.
var ErrReadOnlySource = errors.New("git config store is read-only: external git sources cannot be written to")

// GitConfigStore wraps LocalRepositoryStore to provide a read-only cfgconfig.ConfigStore
// view of a single external HTTPS git repository for one mount-pointed tenant.
//
// Work directory layout: <workDir>/<tenantID>/<sha256(sourceURL)>/
// The SHA256 hash of the source URL prevents path collisions for multiple repos under the same tenant.
//
// Credentials are fetched from secretStore at transport time (clone, pull) and are
// never stored in any struct field.
type GitConfigStore struct {
	source      *pkgconfig.ConfigSourceInfo
	tenantID    string
	repoDir     string
	secretStore secretsiface.SecretStore
	logger      logging.Logger
}

// NewGitConfigStore constructs a GitConfigStore, cloning the remote repository into
// <workDir>/<tenantID>/<sha256(sourceURL)>/ on first construction.
//
// workDir must already exist before this function is called.
// tenantID is validated via security.ValidateAndCleanPath to prevent path traversal attacks.
// Credentials are fetched at transport time; the credential value is not retained in any field.
func NewGitConfigStore(
	ctx context.Context,
	source *pkgconfig.ConfigSourceInfo,
	tenantID string,
	secretStore secretsiface.SecretStore,
	workDir string,
	logger logging.Logger,
) (*GitConfigStore, error) {
	// Validate tenantID against workDir before constructing any paths.
	// ValidateAndCleanPath requires workDir to exist; callers must ensure this.
	if _, err := security.ValidateAndCleanPath(workDir, tenantID); err != nil {
		return nil, fmt.Errorf("invalid tenantID %q: %w", tenantID, err)
	}

	urlHash := fmt.Sprintf("%x", sha256.Sum256([]byte(source.URL)))
	repoDir := filepath.Join(workDir, tenantID, urlHash)

	if err := os.MkdirAll(repoDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create repo directory: %w", err)
	}

	s := &GitConfigStore{
		source:      source,
		tenantID:    tenantID,
		repoDir:     repoDir,
		secretStore: secretStore,
		logger:      logger,
	}

	// Clone only if the repo hasn't been cloned yet.
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); os.IsNotExist(err) {
		username, password, credErr := s.fetchCredential(ctx)
		if credErr != nil {
			return nil, fmt.Errorf("failed to fetch credential for clone: %w", credErr)
		}
		localStore := gitstorage.NewLocalRepositoryStore(username, password)
		cloneErr := localStore.Clone(ctx, source.URL, repoDir)
		if cloneErr != nil {
			stripped := sanitizeCredential(cloneErr, password)
			password = "" //nolint:ineffassign // zeroize before return
			return nil, fmt.Errorf("failed to clone %s: %w", logging.SanitizeLogValue(source.URL), stripped)
		}
		password = "" //nolint:ineffassign // zeroize after success
	}

	return s, nil
}

// SyncWithRemote pulls latest changes from the remote. On success it returns the
// post-pull HEAD SHA. On failure the store continues serving the previously cloned
// state (last-known-good); the error is logged with sanitized fields and returned.
// Error messages never contain credential material.
func (s *GitConfigStore) SyncWithRemote(ctx context.Context) (string, error) {
	username, password, err := s.fetchCredential(ctx)
	if err != nil {
		category := categorizeError(err)
		s.logger.Warn("git-store: sync credential fetch failed",
			"tenant_id", logging.SanitizeLogValue(s.tenantID),
			"url", logging.SanitizeLogValue(s.source.URL),
			"error_category", category,
		)
		return "", err
	}

	localStore := gitstorage.NewLocalRepositoryStore(username, password)
	pullErr := localStore.Pull(ctx, s.repoDir)
	if pullErr != nil {
		stripped := sanitizeCredential(pullErr, password)
		password = "" //nolint:ineffassign // zeroize before warn/return
		category := categorizeError(stripped)
		s.logger.Warn("git-store: sync pull failed",
			"tenant_id", logging.SanitizeLogValue(s.tenantID),
			"url", logging.SanitizeLogValue(s.source.URL),
			"error_category", category,
		)
		return "", stripped
	}
	password = "" //nolint:ineffassign // zeroize after success

	repo, openErr := gogit.PlainOpen(s.repoDir)
	if openErr != nil {
		return "", fmt.Errorf("sync: failed to open repo after pull: %w", openErr)
	}
	head, headErr := repo.Head()
	if headErr != nil {
		return "", fmt.Errorf("sync: failed to get HEAD after pull: %w", headErr)
	}
	return head.Hash().String(), nil
}

// --- cfgconfig.ConfigStore read methods ---

// GetConfig reads the config file at <repoDir>/<subPath>/<namespace>/<name>.yaml.
func (s *GitConfigStore) GetConfig(_ context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	fullPath, err := s.keyToPath(key)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(fullPath) // #nosec G304 — path validated by ValidateAndCleanPath
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cfgconfig.ErrConfigNotFound
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	info, _ := os.Stat(fullPath)
	entry := &cfgconfig.ConfigEntry{
		Key:    key,
		Data:   data,
		Format: cfgconfig.ConfigFormatYAML,
	}
	if info != nil {
		entry.UpdatedAt = info.ModTime()
		entry.CreatedAt = info.ModTime()
	}
	return entry, nil
}

// ListConfigs enumerates config files under <repoDir>/<subPath>/<filter.Namespace>/.
func (s *GitConfigStore) ListConfigs(_ context.Context, filter *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	base := s.repoDir
	if s.source.SubPath != "" {
		var err error
		base, err = security.ValidateAndCleanPath(s.repoDir, s.source.SubPath)
		if err != nil {
			return nil, fmt.Errorf("invalid subPath: %w", err)
		}
	}

	namespace := ""
	if filter != nil {
		namespace = filter.Namespace
	}

	searchDir := base
	if namespace != "" {
		var err error
		searchDir, err = security.ValidateAndCleanPath(base, namespace)
		if err != nil {
			return nil, fmt.Errorf("invalid namespace: %w", err)
		}
	}

	var entries []*cfgconfig.ConfigEntry
	err := filepath.Walk(searchDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, readErr := os.ReadFile(path) // #nosec G304 — Walk restricts to searchDir subtree
		if readErr != nil {
			return nil // skip unreadable files
		}

		rel, relErr := filepath.Rel(base, path)
		if relErr != nil {
			return nil
		}
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) < 2 {
			return nil
		}
		ns := parts[0]
		name := strings.TrimSuffix(parts[len(parts)-1], ".yaml")

		tenantID := ""
		if filter != nil {
			tenantID = filter.TenantID
		}
		entries = append(entries, &cfgconfig.ConfigEntry{
			Key: &cfgconfig.ConfigKey{
				TenantID:  tenantID,
				Namespace: ns,
				Name:      name,
			},
			Data:      data,
			Format:    cfgconfig.ConfigFormatYAML,
			UpdatedAt: info.ModTime(),
			CreatedAt: info.ModTime(),
		})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to list configs: %w", err)
	}
	return entries, nil
}

// GetConfigHistory returns commit history for the config file.
func (s *GitConfigStore) GetConfigHistory(ctx context.Context, key *cfgconfig.ConfigKey, limit int) ([]*cfgconfig.ConfigEntry, error) {
	relPath, err := s.keyToRelativePath(key)
	if err != nil {
		return nil, err
	}

	localStore := gitstorage.NewLocalRepositoryStore("", "")
	commits, err := localStore.GetHistory(ctx, s.repoDir, relPath, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get config history: %w", err)
	}

	entries := make([]*cfgconfig.ConfigEntry, 0, len(commits))
	for i, c := range commits {
		entries = append(entries, &cfgconfig.ConfigEntry{
			Key:       key,
			Data:      []byte(c.SHA),
			Format:    cfgconfig.ConfigFormatYAML,
			Version:   int64(i + 1),
			UpdatedAt: c.Timestamp,
			CreatedAt: c.Timestamp,
			UpdatedBy: c.Author.Name,
			CreatedBy: c.Author.Name,
		})
	}
	return entries, nil
}

// GetConfigVersion returns the config file content at a specific commit in history.
// version is 1-indexed (1 = most recent, 2 = one before that, etc.).
func (s *GitConfigStore) GetConfigVersion(ctx context.Context, key *cfgconfig.ConfigKey, version int64) (*cfgconfig.ConfigEntry, error) {
	if version < 1 {
		return nil, fmt.Errorf("version must be >= 1, got %d", version)
	}

	relPath, err := s.keyToRelativePath(key)
	if err != nil {
		return nil, err
	}

	localStore := gitstorage.NewLocalRepositoryStore("", "")
	commits, err := localStore.GetHistory(ctx, s.repoDir, relPath, int(version))
	if err != nil {
		return nil, fmt.Errorf("failed to get history for version: %w", err)
	}
	if int(version) > len(commits) {
		return nil, cfgconfig.ErrConfigNotFound
	}

	targetCommit := commits[version-1]
	repo, err := gogit.PlainOpen(s.repoDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open repo: %w", err)
	}
	commitObj, err := repo.CommitObject(plumbing.NewHash(targetCommit.SHA))
	if err != nil {
		return nil, fmt.Errorf("failed to get commit object: %w", err)
	}
	file, err := commitObj.File(relPath)
	if err != nil {
		return nil, fmt.Errorf("file not found at version %d: %w", version, err)
	}
	content, err := file.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to read file contents at version %d: %w", version, err)
	}

	return &cfgconfig.ConfigEntry{
		Key:       key,
		Data:      []byte(content),
		Format:    cfgconfig.ConfigFormatYAML,
		Version:   version,
		UpdatedAt: targetCommit.Timestamp,
		CreatedAt: targetCommit.Timestamp,
		UpdatedBy: targetCommit.Author.Name,
		CreatedBy: targetCommit.Author.Name,
	}, nil
}

// ResolveConfigWithInheritance delegates to GetConfig — inheritance resolution for
// external git sources is handled by the router layer, not the store.
func (s *GitConfigStore) ResolveConfigWithInheritance(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return s.GetConfig(ctx, key)
}

// ValidateConfig checks that the entry has a valid YAML format.
func (s *GitConfigStore) ValidateConfig(_ context.Context, config *cfgconfig.ConfigEntry) error {
	if config == nil {
		return fmt.Errorf("config entry is nil")
	}
	if config.Format != cfgconfig.ConfigFormatYAML {
		return cfgconfig.ErrInvalidFormat
	}
	return nil
}

// GetConfigStats computes basic stats by walking the repo directory.
func (s *GitConfigStore) GetConfigStats(_ context.Context) (*cfgconfig.ConfigStats, error) {
	stats := &cfgconfig.ConfigStats{
		ConfigsByTenant:    make(map[string]int64),
		ConfigsByFormat:    make(map[string]int64),
		ConfigsByNamespace: make(map[string]int64),
		LastUpdated:        time.Now(),
	}

	base := s.repoDir
	if s.source.SubPath != "" {
		var err error
		base, err = security.ValidateAndCleanPath(s.repoDir, s.source.SubPath)
		if err != nil {
			return nil, fmt.Errorf("invalid subPath for stats: %w", err)
		}
	}

	walkErr := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		stats.TotalConfigs++
		stats.TotalSize += info.Size()
		stats.ConfigsByFormat[string(cfgconfig.ConfigFormatYAML)]++
		stats.ConfigsByTenant[s.tenantID]++

		rel, relErr := filepath.Rel(base, path)
		if relErr == nil {
			parts := strings.Split(rel, string(filepath.Separator))
			if len(parts) >= 1 {
				stats.ConfigsByNamespace[parts[0]]++
			}
		}

		modTime := info.ModTime()
		if stats.OldestConfig == nil || modTime.Before(*stats.OldestConfig) {
			t := modTime
			stats.OldestConfig = &t
		}
		if stats.NewestConfig == nil || modTime.After(*stats.NewestConfig) {
			t := modTime
			stats.NewestConfig = &t
		}
		return nil
	})
	if walkErr != nil && !os.IsNotExist(walkErr) {
		return nil, fmt.Errorf("failed to walk config directory: %w", walkErr)
	}

	if stats.TotalConfigs > 0 {
		stats.AverageSize = stats.TotalSize / stats.TotalConfigs
	}
	return stats, nil
}

// --- cfgconfig.ConfigStore write methods — always return ErrReadOnlySource ---

func (s *GitConfigStore) StoreConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error {
	return ErrReadOnlySource
}

func (s *GitConfigStore) DeleteConfig(_ context.Context, _ *cfgconfig.ConfigKey) error {
	return ErrReadOnlySource
}

func (s *GitConfigStore) StoreConfigBatch(_ context.Context, _ []*cfgconfig.ConfigEntry) error {
	return ErrReadOnlySource
}

func (s *GitConfigStore) DeleteConfigBatch(_ context.Context, _ []*cfgconfig.ConfigKey) error {
	return ErrReadOnlySource
}

// --- path helpers ---

// keyToRelativePath builds the relative path within the repo for a ConfigKey.
// Result: <subPath>/<namespace>/<name>.yaml (subPath may be empty)
// Uses path.Join (always forward slashes) so the result is valid for both git
// tree operations (go-git always uses forward slashes) and security.ValidateAndCleanPath
// (filepath.Clean normalises forward slashes on all platforms).
func (s *GitConfigStore) keyToRelativePath(key *cfgconfig.ConfigKey) (string, error) {
	parts := []string{}
	if s.source.SubPath != "" {
		parts = append(parts, s.source.SubPath)
	}
	parts = append(parts, key.Namespace, key.Name+".yaml")
	return path.Join(parts...), nil
}

// keyToPath builds and validates the absolute filesystem path for a ConfigKey.
// Uses security.ValidateAndCleanPath to reject traversal attempts.
func (s *GitConfigStore) keyToPath(key *cfgconfig.ConfigKey) (string, error) {
	relPath, err := s.keyToRelativePath(key)
	if err != nil {
		return "", err
	}
	fullPath, err := security.ValidateAndCleanPath(s.repoDir, relPath)
	if err != nil {
		return "", fmt.Errorf("invalid config key path: %w", err)
	}
	return fullPath, nil
}

// --- credential and error helpers ---

// fetchCredential retrieves the HTTPS credential from secretStore at transport time.
// Returns empty strings when no CredentialRef is set. The credential value is never
// stored in any GitConfigStore field.
func (s *GitConfigStore) fetchCredential(ctx context.Context) (username, password string, err error) {
	if s.source.CredentialRef == "" {
		return "", "", nil
	}
	secret, err := s.secretStore.GetSecret(ctx, s.source.CredentialRef)
	if err != nil {
		return "", "", fmt.Errorf("failed to get credential %q: %w", s.source.CredentialRef, err)
	}
	return "x-access-token", secret.Value, nil
}

// sanitizeCredential removes occurrences of the credential value from an error's message.
// This prevents go-git transport errors from leaking credential material.
func sanitizeCredential(err error, credential string) error {
	if err == nil || credential == "" {
		return err
	}
	sanitized := strings.ReplaceAll(err.Error(), credential, "[REDACTED]")
	return errors.New(sanitized)
}

// categorizeError returns a coarse error category string suitable for structured logging.
// Raw error text is never included — only a category label to avoid leaking internals.
func categorizeError(err error) string {
	if err == nil {
		return "none"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "auth") || strings.Contains(msg, "credential") || strings.Contains(msg, "unauthorized"):
		return "authentication_failure"
	case strings.Contains(msg, "network") || strings.Contains(msg, "connect") || strings.Contains(msg, "dial") || strings.Contains(msg, "timeout"):
		return "network_failure"
	case strings.Contains(msg, "not found") || strings.Contains(msg, "no such"):
		return "not_found"
	default:
		return "unknown"
	}
}
