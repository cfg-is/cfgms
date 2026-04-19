// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// FlatFileConfigStore implements cfgconfig.ConfigStore using the local filesystem.
//
// File layout: <root>/<tenantID>/configs/<namespace>/<name>.<format>
//
// The entire ConfigEntry struct is JSON-encoded and written to the file; the
// file extension reflects the format of the Data field (.yaml or .json).
//
// Atomic writes: write to a temp file in the same directory, then os.Rename.
// This is crash-safe on Linux when both files are on the same filesystem. On
// Windows, renames across volumes may fail — keep root on a single filesystem.
type FlatFileConfigStore struct {
	root  string
	mutex sync.RWMutex
}

// NewFlatFileConfigStore creates a new FlatFileConfigStore rooted at root.
// The root directory is created (with MkdirAll) if it does not already exist.
func NewFlatFileConfigStore(root string) (*FlatFileConfigStore, error) {
	if err := os.MkdirAll(root, 0750); err != nil {
		return nil, fmt.Errorf("failed to create config root: %w", err)
	}
	return &FlatFileConfigStore{root: root}, nil
}

// safeJoin validates and joins path components to prevent directory traversal.
// Returns an error if the resulting path escapes base.
func safeJoin(base string, parts ...string) (string, error) {
	joined := filepath.Join(append([]string{base}, parts...)...)
	cleaned := filepath.Clean(joined)
	cleanBase := filepath.Clean(base)
	if cleaned != cleanBase &&
		!strings.HasPrefix(cleaned, cleanBase+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal detected in path components")
	}
	return cleaned, nil
}

// configExt returns the file extension for a given config format.
func configExt(format cfgconfig.ConfigFormat) string {
	switch format {
	case cfgconfig.ConfigFormatYAML:
		return "yaml"
	default:
		return "json"
	}
}

// configFileName returns the base filename for a config key.
func configFileName(key *cfgconfig.ConfigKey, format cfgconfig.ConfigFormat) string {
	name := key.Name
	if key.Scope != "" {
		name = key.Name + "@" + key.Scope
	}
	return name + "." + configExt(format)
}

// configDir returns the directory for a tenant's configs in the given namespace.
func (s *FlatFileConfigStore) configDir(tenantID, namespace string) (string, error) {
	return safeJoin(s.root, tenantID, "configs", namespace)
}

// configPath returns the filesystem path for a config entry with the given format.
func (s *FlatFileConfigStore) configPath(key *cfgconfig.ConfigKey, format cfgconfig.ConfigFormat) (string, error) {
	dir, err := s.configDir(key.TenantID, key.Namespace)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFileName(key, format)), nil
}

// findConfigFile locates the file for a config key, trying .yaml then .json.
// Returns ErrConfigNotFound if neither exists.
func (s *FlatFileConfigStore) findConfigFile(key *cfgconfig.ConfigKey) (string, error) {
	for _, format := range []cfgconfig.ConfigFormat{cfgconfig.ConfigFormatYAML, cfgconfig.ConfigFormatJSON} {
		dir, err := s.configDir(key.TenantID, key.Namespace)
		if err != nil {
			continue
		}
		path := filepath.Join(dir, configFileName(key, format))
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", cfgconfig.ErrConfigNotFound
}

// writeAtomic writes data to path atomically via a temp file in the same directory.
// The directory is created if it does not exist.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".tmp-cfg-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("atomic rename failed: %w", err)
	}
	success = true
	return nil
}

// dataChecksum computes a SHA-256 hex checksum of data.
func dataChecksum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// readConfigFile reads and unmarshals a config file. Must be called without holding mutex.
func (s *FlatFileConfigStore) readConfigFile(key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	path, err := s.findConfigFile(key)
	if err != nil {
		return nil, cfgconfig.ErrConfigNotFound
	}

	// #nosec G304 — path is validated by safeJoin inside findConfigFile
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cfgconfig.ErrConfigNotFound
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var entry cfgconfig.ConfigEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config entry: %w", err)
	}
	return &entry, nil
}

// StoreConfig stores a configuration entry atomically.
// If an entry already exists, its version is incremented and CreatedAt/CreatedBy are preserved.
func (s *FlatFileConfigStore) StoreConfig(ctx context.Context, config *cfgconfig.ConfigEntry) error {
	if config.Key == nil || config.Key.TenantID == "" {
		return cfgconfig.ErrTenantRequired
	}
	if config.Key.Namespace == "" {
		return cfgconfig.ErrNamespaceRequired
	}
	if config.Key.Name == "" {
		return cfgconfig.ErrNameRequired
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now().UTC()

	existing, _ := s.readConfigFile(config.Key)

	entry := *config
	if existing != nil {
		entry.Version = existing.Version + 1
		entry.CreatedAt = existing.CreatedAt
		entry.CreatedBy = existing.CreatedBy
	} else {
		entry.Version = 1
		// Preserve caller-supplied CreatedAt (e.g. rollback operations with
		// historic timestamps); fall back to now for new entries without one.
		if entry.CreatedAt.IsZero() {
			entry.CreatedAt = now
		}
	}
	entry.UpdatedAt = now
	entry.Checksum = dataChecksum(config.Data)

	if entry.Format == "" {
		entry.Format = cfgconfig.ConfigFormatJSON
	}

	// Remove old file if format changed
	if existing != nil && existing.Format != entry.Format {
		if oldPath, err := s.configPath(config.Key, existing.Format); err == nil {
			_ = os.Remove(oldPath)
		}
	}

	path, err := s.configPath(config.Key, entry.Format)
	if err != nil {
		return fmt.Errorf("invalid config key: %w", err)
	}

	raw, err := json.Marshal(&entry)
	if err != nil {
		return fmt.Errorf("failed to marshal config entry: %w", err)
	}

	if err := writeAtomic(path, raw); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

// GetConfig retrieves a configuration entry by key.
func (s *FlatFileConfigStore) GetConfig(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.readConfigFile(key)
}

// DeleteConfig removes a configuration entry.
func (s *FlatFileConfigStore) DeleteConfig(ctx context.Context, key *cfgconfig.ConfigKey) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	path, err := s.findConfigFile(key)
	if err != nil {
		return cfgconfig.ErrConfigNotFound
	}

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return cfgconfig.ErrConfigNotFound
		}
		return fmt.Errorf("failed to delete config: %w", err)
	}
	return nil
}

// ListConfigs returns all configuration entries matching the filter.
func (s *FlatFileConfigStore) ListConfigs(ctx context.Context, filter *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	searchRoot, err := s.listSearchRoot(filter)
	if err != nil {
		return nil, err
	}

	var results []*cfgconfig.ConfigEntry

	walkErr := filepath.WalkDir(searchRoot, func(path string, d os.DirEntry, ferr error) error {
		if ferr != nil {
			if os.IsNotExist(ferr) {
				return nil
			}
			return ferr
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".json" {
			return nil
		}

		// #nosec G304 — path originates from WalkDir rooted at s.root
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		var entry cfgconfig.ConfigEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil // skip malformed files
		}
		if applyConfigFilter(&entry, filter) {
			results = append(results, &entry)
		}
		return nil
	})
	if walkErr != nil && !os.IsNotExist(walkErr) {
		return nil, fmt.Errorf("failed to list configs: %w", walkErr)
	}

	sortConfigs(results, filter)
	results = paginateConfigs(results, filter)
	return results, nil
}

// listSearchRoot returns the directory to start the WalkDir from, based on filter.
func (s *FlatFileConfigStore) listSearchRoot(filter *cfgconfig.ConfigFilter) (string, error) {
	if filter == nil || filter.TenantID == "" {
		return s.root, nil
	}
	base, err := safeJoin(s.root, filter.TenantID, "configs")
	if err != nil {
		return "", fmt.Errorf("invalid tenant ID in filter: %w", err)
	}
	if filter.Namespace != "" {
		ns, err := safeJoin(base, filter.Namespace)
		if err != nil {
			return "", fmt.Errorf("invalid namespace in filter: %w", err)
		}
		return ns, nil
	}
	return base, nil
}

// applyConfigFilter returns true if the entry matches all filter criteria.
func applyConfigFilter(entry *cfgconfig.ConfigEntry, filter *cfgconfig.ConfigFilter) bool {
	if filter == nil {
		return true
	}
	if filter.TenantID != "" && (entry.Key == nil || entry.Key.TenantID != filter.TenantID) {
		return false
	}
	if filter.Namespace != "" && (entry.Key == nil || entry.Key.Namespace != filter.Namespace) {
		return false
	}
	if len(filter.Names) > 0 {
		found := false
		for _, n := range filter.Names {
			if entry.Key != nil && entry.Key.Name == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if filter.CreatedBy != "" && entry.CreatedBy != filter.CreatedBy {
		return false
	}
	if filter.UpdatedBy != "" && entry.UpdatedBy != filter.UpdatedBy {
		return false
	}
	if filter.CreatedAfter != nil && entry.CreatedAt.Before(*filter.CreatedAfter) {
		return false
	}
	if filter.CreatedBefore != nil && entry.CreatedAt.After(*filter.CreatedBefore) {
		return false
	}
	if filter.UpdatedAfter != nil && entry.UpdatedAt.Before(*filter.UpdatedAfter) {
		return false
	}
	if filter.UpdatedBefore != nil && entry.UpdatedAt.After(*filter.UpdatedBefore) {
		return false
	}
	for _, filterTag := range filter.Tags {
		found := false
		for _, tag := range entry.Tags {
			if tag == filterTag {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// sortConfigs sorts results according to the filter's SortBy and Order fields.
func sortConfigs(results []*cfgconfig.ConfigEntry, filter *cfgconfig.ConfigFilter) {
	if filter == nil || filter.SortBy == "" {
		return
	}
	ascending := filter.Order != "desc"
	sort.Slice(results, func(i, j int) bool {
		var less bool
		switch filter.SortBy {
		case "name":
			if results[i].Key != nil && results[j].Key != nil {
				less = results[i].Key.Name < results[j].Key.Name
			}
		case "updated_at":
			less = results[i].UpdatedAt.Before(results[j].UpdatedAt)
		case "version":
			less = results[i].Version < results[j].Version
		default: // "created_at"
			less = results[i].CreatedAt.Before(results[j].CreatedAt)
		}
		if ascending {
			return less
		}
		return !less
	})
}

// paginateConfigs applies offset and limit from the filter.
func paginateConfigs(results []*cfgconfig.ConfigEntry, filter *cfgconfig.ConfigFilter) []*cfgconfig.ConfigEntry {
	if filter == nil {
		return results
	}
	if filter.Offset > 0 {
		if filter.Offset >= len(results) {
			return nil
		}
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}
	return results
}

// GetConfigHistory returns the current entry as the only history item.
// The flat-file provider does not retain historical versions; only the
// current state is stored. Use git-sync if you need PR-based change history.
func (s *FlatFileConfigStore) GetConfigHistory(ctx context.Context, key *cfgconfig.ConfigKey, limit int) ([]*cfgconfig.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, err := s.readConfigFile(key)
	if err != nil {
		return nil, err
	}
	return []*cfgconfig.ConfigEntry{entry}, nil
}

// GetConfigVersion returns the current entry if its version matches; otherwise ErrConfigNotFound.
// The flat-file provider does not retain historical versions.
func (s *FlatFileConfigStore) GetConfigVersion(ctx context.Context, key *cfgconfig.ConfigKey, version int64) (*cfgconfig.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, err := s.readConfigFile(key)
	if err != nil {
		return nil, err
	}
	if entry.Version != version {
		return nil, fmt.Errorf("%w: version %d not available (current: %d)",
			cfgconfig.ErrConfigNotFound, version, entry.Version)
	}
	return entry, nil
}

// StoreConfigBatch stores multiple configuration entries, stopping on first error.
func (s *FlatFileConfigStore) StoreConfigBatch(ctx context.Context, configs []*cfgconfig.ConfigEntry) error {
	for _, config := range configs {
		if err := s.StoreConfig(ctx, config); err != nil {
			return fmt.Errorf("batch store failed at %v: %w", config.Key, err)
		}
	}
	return nil
}

// DeleteConfigBatch deletes multiple configuration entries, ignoring not-found entries.
func (s *FlatFileConfigStore) DeleteConfigBatch(ctx context.Context, keys []*cfgconfig.ConfigKey) error {
	for _, key := range keys {
		err := s.DeleteConfig(ctx, key)
		if err != nil && err != cfgconfig.ErrConfigNotFound {
			return fmt.Errorf("batch delete failed at %v: %w", key, err)
		}
	}
	return nil
}

// ResolveConfigWithInheritance resolves a config by walking up the tenant hierarchy.
// TenantIDs must be path-based (e.g., "root/msp-a/client-1"). The method returns
// the config at the most specific level, falling back to ancestors.
//
// Example resolution order for tenant "root/msp-a/client-1":
//  1. root/msp-a/client-1/configs/<namespace>/<name>
//  2. root/msp-a/configs/<namespace>/<name>
//  3. root/configs/<namespace>/<name>
func (s *FlatFileConfigStore) ResolveConfigWithInheritance(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	parts := strings.Split(key.TenantID, "/")

	for i := len(parts); i > 0; i-- {
		tenantID := strings.Join(parts[:i], "/")
		searchKey := &cfgconfig.ConfigKey{
			TenantID:  tenantID,
			Namespace: key.Namespace,
			Name:      key.Name,
			Scope:     key.Scope,
		}
		entry, err := s.readConfigFile(searchKey)
		if err == nil {
			return entry, nil
		}
	}
	return nil, cfgconfig.ErrConfigNotFound
}

// ValidateConfig validates the required fields of a configuration entry.
func (s *FlatFileConfigStore) ValidateConfig(ctx context.Context, config *cfgconfig.ConfigEntry) error {
	if config.Key == nil || config.Key.TenantID == "" {
		return cfgconfig.ErrTenantRequired
	}
	if config.Key.Namespace == "" {
		return cfgconfig.ErrNamespaceRequired
	}
	if config.Key.Name == "" {
		return cfgconfig.ErrNameRequired
	}
	if config.Format != "" &&
		config.Format != cfgconfig.ConfigFormatYAML &&
		config.Format != cfgconfig.ConfigFormatJSON {
		return cfgconfig.ErrInvalidFormat
	}
	if config.Checksum != "" && len(config.Data) > 0 {
		if config.Checksum != dataChecksum(config.Data) {
			return cfgconfig.ErrChecksumMismatch
		}
	}
	return nil
}

// GetConfigStats scans the root directory and returns aggregate statistics.
func (s *FlatFileConfigStore) GetConfigStats(ctx context.Context) (*cfgconfig.ConfigStats, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := &cfgconfig.ConfigStats{
		ConfigsByTenant:    make(map[string]int64),
		ConfigsByFormat:    make(map[string]int64),
		ConfigsByNamespace: make(map[string]int64),
		LastUpdated:        time.Now().UTC(),
	}

	var oldest, newest *time.Time

	walkErr := filepath.WalkDir(s.root, func(path string, d os.DirEntry, ferr error) error {
		if ferr != nil || d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".json" {
			return nil
		}

		// #nosec G304 — path from WalkDir rooted at s.root
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var entry cfgconfig.ConfigEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil
		}

		stats.TotalConfigs++
		stats.TotalSize += int64(len(raw))

		if entry.Key != nil {
			stats.ConfigsByTenant[entry.Key.TenantID]++
			stats.ConfigsByNamespace[entry.Key.Namespace]++
		}
		stats.ConfigsByFormat[string(entry.Format)]++

		if oldest == nil || entry.CreatedAt.Before(*oldest) {
			t := entry.CreatedAt
			oldest = &t
		}
		if newest == nil || entry.CreatedAt.After(*newest) {
			t := entry.CreatedAt
			newest = &t
		}
		return nil
	})
	if walkErr != nil && !os.IsNotExist(walkErr) {
		return nil, fmt.Errorf("failed to compute config stats: %w", walkErr)
	}

	stats.OldestConfig = oldest
	stats.NewestConfig = newest
	if stats.TotalConfigs > 0 {
		stats.AverageSize = stats.TotalSize / stats.TotalConfigs
	}
	return stats, nil
}
