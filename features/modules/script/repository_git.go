package script

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"gopkg.in/yaml.v3"
)

// GitScriptRepository implements ScriptRepository using the global git storage provider via ConfigStore
type GitScriptRepository struct {
	configStore interfaces.ConfigStore
	tenantID    string
	namespace   string // Namespace for scripts in storage (e.g., "scripts" or "scripts/templates")
	global      bool   // Whether this is the global template repository
}

// NewGitScriptRepository creates a new git-based script repository
func NewGitScriptRepository(storage interfaces.StorageProvider, tenantID string, global bool) (*GitScriptRepository, error) {
	// Create ConfigStore from provider
	configStore, err := storage.CreateConfigStore(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create config store: %w", err)
	}

	namespace := "scripts"
	if global {
		namespace = "scripts/templates"
	}

	return &GitScriptRepository{
		configStore: configStore,
		tenantID:    tenantID,
		namespace:   namespace,
		global:      global,
	}, nil
}

// Create creates a new script with initial version
func (r *GitScriptRepository) Create(script *VersionedScript) error {
	if err := script.Metadata.Validate(); err != nil {
		return fmt.Errorf("invalid script metadata: %w", err)
	}

	// Check if script already exists
	existing, err := r.Get(script.Metadata.ID, "")
	if err == nil && existing != nil {
		return fmt.Errorf("script %s already exists", script.Metadata.ID)
	}

	// Set timestamps
	now := time.Now()
	script.Metadata.CreatedAt = now
	script.Metadata.UpdatedAt = now

	// Calculate content hash
	script.Hash = r.calculateHash(script.Content)

	// Store script
	return r.storeScript(context.Background(), script)
}

// Get retrieves a script by ID and version (empty version = latest)
func (r *GitScriptRepository) Get(id string, version string) (*VersionedScript, error) {
	if version == "" {
		version = "latest"
	}

	key := &interfaces.ConfigKey{
		TenantID:  r.tenantID,
		Namespace: r.namespace,
		Name:      id,
		Scope:     version,
	}

	entry, err := r.configStore.GetConfig(context.Background(), key)
	if err != nil {
		return nil, fmt.Errorf("script not found: %s (version %s): %w", id, version, err)
	}

	// Parse script from YAML
	var script VersionedScript
	if err := yaml.Unmarshal(entry.Data, &script); err != nil {
		return nil, fmt.Errorf("failed to parse script: %w", err)
	}

	// Verify hash
	expectedHash := r.calculateHash(script.Content)
	if script.Hash != expectedHash {
		return nil, fmt.Errorf("script integrity check failed: hash mismatch")
	}

	return &script, nil
}

// List lists all scripts with optional filtering
func (r *GitScriptRepository) List(filter *ScriptFilter) ([]*ScriptMetadata, error) {
	// List all scripts in this namespace with scope="latest"
	configFilter := &interfaces.ConfigFilter{
		TenantID:  r.tenantID,
		Namespace: r.namespace,
		// We'll filter by scope="latest" after retrieval since ConfigFilter might not support scope
	}

	entries, err := r.configStore.ListConfigs(context.Background(), configFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list scripts: %w", err)
	}

	results := make([]*ScriptMetadata, 0)
	for _, entry := range entries {
		// Only process "latest" versions
		if entry.Key.Scope != "latest" {
			continue
		}

		// Parse script
		var script VersionedScript
		if err := yaml.Unmarshal(entry.Data, &script); err != nil {
			continue // Skip invalid scripts
		}

		// Apply user filter
		if filter != nil && !r.matchesFilter(script.Metadata, filter) {
			continue
		}

		results = append(results, script.Metadata)
	}

	// Sort by name
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	return results, nil
}

// Update creates a new version of an existing script
func (r *GitScriptRepository) Update(script *VersionedScript) error {
	if err := script.Metadata.Validate(); err != nil {
		return fmt.Errorf("invalid script metadata: %w", err)
	}

	// Check if script exists
	existing, err := r.Get(script.Metadata.ID, "")
	if err != nil {
		return fmt.Errorf("script %s not found: %w", script.Metadata.ID, err)
	}

	// Validate version increment
	if script.Metadata.Version.Compare(existing.Metadata.Version) <= 0 {
		return fmt.Errorf("new version %s must be greater than current version %s",
			script.Metadata.Version.String(), existing.Metadata.Version.String())
	}

	// Preserve creation time, update modification time
	script.Metadata.CreatedAt = existing.Metadata.CreatedAt
	script.Metadata.UpdatedAt = time.Now()

	// Calculate content hash
	script.Hash = r.calculateHash(script.Content)

	// Store new version
	return r.storeScript(context.Background(), script)
}

// Delete removes a script (all versions or specific version)
func (r *GitScriptRepository) Delete(id string, version string) error {
	ctx := context.Background()

	if version == "" {
		// Delete all versions - list all versions first
		versions, err := r.ListVersions(id)
		if err != nil {
			return fmt.Errorf("failed to list versions for deletion: %w", err)
		}

		// Delete each version
		for _, v := range versions {
			key := &interfaces.ConfigKey{
				TenantID:  r.tenantID,
				Namespace: r.namespace,
				Name:      id,
				Scope:     v.String(),
			}
			if err := r.configStore.DeleteConfig(ctx, key); err != nil {
				return fmt.Errorf("failed to delete version %s: %w", v.String(), err)
			}
		}

		// Delete "latest" pointer
		latestKey := &interfaces.ConfigKey{
			TenantID:  r.tenantID,
			Namespace: r.namespace,
			Name:      id,
			Scope:     "latest",
		}
		return r.configStore.DeleteConfig(ctx, latestKey)
	}

	// Delete specific version
	key := &interfaces.ConfigKey{
		TenantID:  r.tenantID,
		Namespace: r.namespace,
		Name:      id,
		Scope:     version,
	}

	if err := r.configStore.DeleteConfig(ctx, key); err != nil {
		return fmt.Errorf("failed to delete script version: %w", err)
	}

	// If we deleted the latest version, update the "latest" pointer
	latestKey := &interfaces.ConfigKey{
		TenantID:  r.tenantID,
		Namespace: r.namespace,
		Name:      id,
		Scope:     "latest",
	}

	latestEntry, err := r.configStore.GetConfig(ctx, latestKey)
	if err != nil {
		// Latest doesn't exist or error reading it
		return nil
	}

	// Check if the deleted version was the latest
	var latestScript VersionedScript
	if err := yaml.Unmarshal(latestEntry.Data, &latestScript); err == nil {
		if latestScript.Metadata.Version.String() == version {
			// We deleted the latest - find the new latest
			versions, err := r.ListVersions(id)
			if err != nil || len(versions) == 0 {
				// No versions left, delete the latest pointer
				return r.configStore.DeleteConfig(ctx, latestKey)
			}

			// Get the new latest version and update pointer
			newLatest, err := r.Get(id, versions[0].String())
			if err != nil {
				return fmt.Errorf("failed to get new latest version: %w", err)
			}

			return r.storeScript(ctx, newLatest)
		}
	}

	return nil
}

// ListVersions lists all versions of a script
func (r *GitScriptRepository) ListVersions(id string) ([]*Version, error) {
	// List all configs for this script
	filter := &interfaces.ConfigFilter{
		TenantID:  r.tenantID,
		Namespace: r.namespace,
		Names:     []string{id}, // Filter by script ID
	}

	entries, err := r.configStore.ListConfigs(context.Background(), filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}

	versions := make([]*Version, 0)
	for _, entry := range entries {
		// Skip "latest" scope
		if entry.Key.Scope == "latest" || entry.Key.Scope == "" {
			continue
		}

		// Parse version from scope
		version, err := ParseVersion(entry.Key.Scope)
		if err != nil {
			continue // Skip invalid versions
		}

		versions = append(versions, version)
	}

	// Sort versions in descending order (newest first)
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Compare(versions[j]) > 0
	})

	return versions, nil
}

// GetLatestVersion returns the latest version of a script
func (r *GitScriptRepository) GetLatestVersion(id string) (*Version, error) {
	script, err := r.Get(id, "latest")
	if err != nil {
		return nil, fmt.Errorf("failed to get latest version: %w", err)
	}

	return script.Metadata.Version, nil
}

// Rollback rolls back a script to a previous version
func (r *GitScriptRepository) Rollback(id string, version string) error {
	// Get the specified version
	script, err := r.Get(id, version)
	if err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	// Get current version
	currentVersion, err := r.GetLatestVersion(id)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Create a new version that's one patch higher than current
	newVersion := &Version{
		Major: currentVersion.Major,
		Minor: currentVersion.Minor,
		Patch: currentVersion.Patch + 1,
	}

	// Update metadata with new version
	script.Metadata.Version = newVersion
	script.Metadata.UpdatedAt = time.Now()
	script.Metadata.Description = fmt.Sprintf("[ROLLBACK] %s (rolled back from %s to %s)",
		script.Metadata.Description, currentVersion.String(), version)

	// Store as new version
	return r.storeScript(context.Background(), script)
}

// storeScript stores a script using ConfigStore
func (r *GitScriptRepository) storeScript(ctx context.Context, script *VersionedScript) error {
	// Serialize script to YAML
	data, err := yaml.Marshal(script)
	if err != nil {
		return fmt.Errorf("failed to serialize script: %w", err)
	}

	// Calculate checksum
	checksum := fmt.Sprintf("%x", sha256.Sum256(data))

	// Store versioned entry
	versionKey := &interfaces.ConfigKey{
		TenantID:  r.tenantID,
		Namespace: r.namespace,
		Name:      script.Metadata.ID,
		Scope:     script.Metadata.Version.String(),
	}

	versionEntry := &interfaces.ConfigEntry{
		Key:       versionKey,
		Data:      data,
		Format:    interfaces.ConfigFormatYAML,
		Checksum:  checksum,
		CreatedAt: script.Metadata.CreatedAt,
		UpdatedAt: script.Metadata.UpdatedAt,
		Tags:      script.Metadata.Tags,
		Source:    "script-repository",
		Metadata: map[string]interface{}{
			"script_id":      script.Metadata.ID,
			"script_name":    script.Metadata.Name,
			"script_version": script.Metadata.Version.String(),
			"category":       script.Metadata.Category,
			"platform":       script.Metadata.Platform,
			"shell":          string(script.Metadata.Shell),
			"author":         script.Metadata.Author,
		},
	}

	if err := r.configStore.StoreConfig(ctx, versionEntry); err != nil {
		return fmt.Errorf("failed to store script version: %w", err)
	}

	// Update "latest" pointer
	latestKey := &interfaces.ConfigKey{
		TenantID:  r.tenantID,
		Namespace: r.namespace,
		Name:      script.Metadata.ID,
		Scope:     "latest",
	}

	latestEntry := &interfaces.ConfigEntry{
		Key:       latestKey,
		Data:      data,
		Format:    interfaces.ConfigFormatYAML,
		Checksum:  checksum,
		CreatedAt: script.Metadata.CreatedAt,
		UpdatedAt: script.Metadata.UpdatedAt,
		Tags:      append(script.Metadata.Tags, "latest"),
		Source:    "script-repository",
		Metadata:  versionEntry.Metadata,
	}

	if err := r.configStore.StoreConfig(ctx, latestEntry); err != nil {
		return fmt.Errorf("failed to update latest version: %w", err)
	}

	return nil
}

// calculateHash calculates SHA256 hash of script content
func (r *GitScriptRepository) calculateHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash)
}

// matchesFilter checks if script metadata matches the filter
func (r *GitScriptRepository) matchesFilter(metadata *ScriptMetadata, filter *ScriptFilter) bool {
	if filter.Category != "" && metadata.Category != filter.Category {
		return false
	}

	if filter.Platform != "" {
		platformMatch := false
		for _, platform := range metadata.Platform {
			if platform == filter.Platform {
				platformMatch = true
				break
			}
		}
		if !platformMatch {
			return false
		}
	}

	if filter.Shell != "" && string(metadata.Shell) != filter.Shell {
		return false
	}

	if filter.Author != "" && metadata.Author != filter.Author {
		return false
	}

	if len(filter.Tags) > 0 {
		tagMatch := false
		for _, filterTag := range filter.Tags {
			for _, metaTag := range metadata.Tags {
				if filterTag == metaTag {
					tagMatch = true
					break
				}
			}
			if tagMatch {
				break
			}
		}
		if !tagMatch {
			return false
		}
	}

	return true
}
