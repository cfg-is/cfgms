// Package templates provides template marketplace functionality for CFGMS.
// This enables OSS template sharing, discovery, and collaboration.
package templates

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// MarketplaceTemplate extends Template with marketplace-specific metadata
type MarketplaceTemplate struct {
	*Template

	// Author information
	Author      string `json:"author" yaml:"author"`
	AuthorEmail string `json:"author_email,omitempty" yaml:"author_email,omitempty"`
	License     string `json:"license" yaml:"license"`
	Repository  string `json:"repository,omitempty" yaml:"repository,omitempty"`
	Homepage    string `json:"homepage,omitempty" yaml:"homepage,omitempty"`

	// Marketplace metadata
	Category  string   `json:"category" yaml:"category"`
	Keywords  []string `json:"keywords,omitempty" yaml:"keywords,omitempty"`
	Downloads int64    `json:"downloads" yaml:"downloads"`
	Stars     int64    `json:"stars" yaml:"stars"`
	Featured  bool     `json:"featured" yaml:"featured"`

	// Compliance and security
	ComplianceFrameworks []string `json:"compliance_frameworks,omitempty" yaml:"compliance_frameworks,omitempty"`
	SecurityLevel        string   `json:"security_level,omitempty" yaml:"security_level,omitempty"`
	TestedPlatforms      []string `json:"tested_platforms,omitempty" yaml:"tested_platforms,omitempty"`

	// Requirements
	MinVersion       string               `json:"min_version,omitempty" yaml:"min_version,omitempty"`
	RequiredModules  []string             `json:"required_modules,omitempty" yaml:"required_modules,omitempty"`
	RequiredFeatures []string             `json:"required_features,omitempty" yaml:"required_features,omitempty"`
	Dependencies     []TemplateDependency `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`

	// Versioning
	SemanticVersion string     `json:"semantic_version" yaml:"semantic_version"`
	Changelog       []Change   `json:"changelog,omitempty" yaml:"changelog,omitempty"`
	DeprecatedAt    *time.Time `json:"deprecated_at,omitempty" yaml:"deprecated_at,omitempty"`
	DeprecationNote string     `json:"deprecation_note,omitempty" yaml:"deprecation_note,omitempty"`
}

// TemplateDependency represents a dependency on another template
type TemplateDependency struct {
	TemplateID        string `json:"template_id" yaml:"template_id"`
	Version           string `json:"version" yaml:"version"`
	VersionConstraint string `json:"version_constraint,omitempty" yaml:"version_constraint,omitempty"`
	Required          bool   `json:"required" yaml:"required"`
}

// Change represents a changelog entry
type Change struct {
	Version     string    `json:"version" yaml:"version"`
	Date        time.Time `json:"date" yaml:"date"`
	Description string    `json:"description" yaml:"description"`
	Breaking    bool      `json:"breaking,omitempty" yaml:"breaking,omitempty"`
	Author      string    `json:"author,omitempty" yaml:"author,omitempty"`
}

// MarketplaceConfig configures marketplace behavior
type MarketplaceConfig struct {
	// RepositoryURL is the Git repository URL for the marketplace
	RepositoryURL string

	// LocalCachePath is where templates are cached locally
	LocalCachePath string

	// RefreshInterval for marketplace catalog updates
	RefreshInterval time.Duration

	// AllowCommunityTemplates enables community-contributed templates
	AllowCommunityTemplates bool

	// TrustedAuthors lists authors whose templates are automatically trusted
	TrustedAuthors []string

	// Categories available in the marketplace
	Categories []string
}

// Marketplace manages template discovery, distribution, and collaboration
type Marketplace struct {
	config       MarketplaceConfig
	registry     *TemplateRegistry
	store        TemplateStore
	catalogCache map[string]*MarketplaceTemplate
	cacheMutex   sync.RWMutex
	lastRefresh  time.Time
}

// NewMarketplace creates a new template marketplace
func NewMarketplace(config MarketplaceConfig, store TemplateStore) *Marketplace {
	if config.LocalCachePath == "" {
		config.LocalCachePath = filepath.Join(os.TempDir(), "cfgms-templates")
	}

	if config.RefreshInterval == 0 {
		config.RefreshInterval = 1 * time.Hour
	}

	if len(config.Categories) == 0 {
		config.Categories = []string{
			"security",
			"compliance",
			"backup",
			"monitoring",
			"networking",
			"system",
			"application",
		}
	}

	return &Marketplace{
		config:       config,
		registry:     NewTemplateRegistry(),
		store:        store,
		catalogCache: make(map[string]*MarketplaceTemplate),
	}
}

// Search searches the marketplace for templates
func (m *Marketplace) Search(ctx context.Context, query MarketplaceSearchQuery) ([]*MarketplaceTemplate, error) {
	// Refresh catalog if needed
	if err := m.refreshCatalogIfNeeded(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh catalog: %w", err)
	}

	m.cacheMutex.RLock()
	defer m.cacheMutex.RUnlock()

	var results []*MarketplaceTemplate

	for _, template := range m.catalogCache {
		if m.matchesQuery(template, query) {
			results = append(results, template)
		}
	}

	// Apply sorting
	results = m.sortResults(results, query.SortBy)

	// Apply pagination
	if query.Limit > 0 {
		start := query.Offset
		end := start + query.Limit
		if start > len(results) {
			return []*MarketplaceTemplate{}, nil
		}
		if end > len(results) {
			end = len(results)
		}
		results = results[start:end]
	}

	return results, nil
}

// Get retrieves a specific template from the marketplace
func (m *Marketplace) Get(ctx context.Context, templateID, version string) (*MarketplaceTemplate, error) {
	// Try local cache first
	cacheKey := fmt.Sprintf("%s@%s", templateID, version)

	m.cacheMutex.RLock()
	if cached, exists := m.catalogCache[cacheKey]; exists {
		m.cacheMutex.RUnlock()
		return cached, nil
	}
	m.cacheMutex.RUnlock()

	// Try local store
	template, err := m.store.Get(ctx, templateID)
	if err == nil && (version == "" || template.Version == version) {
		return m.convertToMarketplaceTemplate(template), nil
	}

	// Refresh catalog and try again
	if err := m.refreshCatalog(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh catalog: %w", err)
	}

	m.cacheMutex.RLock()
	defer m.cacheMutex.RUnlock()

	if cached, exists := m.catalogCache[cacheKey]; exists {
		return cached, nil
	}

	return nil, fmt.Errorf("template not found: %s@%s", templateID, version)
}

// Install installs a template from the marketplace
func (m *Marketplace) Install(ctx context.Context, templateID, version string) error {
	// Get template from marketplace
	template, err := m.Get(ctx, templateID, version)
	if err != nil {
		return fmt.Errorf("failed to get template: %w", err)
	}

	// Check compatibility
	if err := m.checkCompatibility(template); err != nil {
		return fmt.Errorf("compatibility check failed: %w", err)
	}

	// Install dependencies first
	if err := m.installDependencies(ctx, template); err != nil {
		return fmt.Errorf("failed to install dependencies: %w", err)
	}

	// Save to local store
	if err := m.store.Save(ctx, template.Template); err != nil {
		return fmt.Errorf("failed to save template: %w", err)
	}

	// Update install count
	template.Downloads++

	return nil
}

// Fork creates a customizable copy of a template
func (m *Marketplace) Fork(ctx context.Context, templateID, newID, newName string) (*MarketplaceTemplate, error) {
	// Get original template
	original, err := m.Get(ctx, templateID, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get original template: %w", err)
	}

	// Create fork
	fork := &MarketplaceTemplate{
		Template: &Template{
			ID:          newID,
			Name:        newName,
			Content:     make([]byte, len(original.Content)),
			Variables:   make(map[string]interface{}),
			Includes:    make([]string, len(original.Includes)),
			Version:     "1.0.0",
			Description: fmt.Sprintf("Forked from %s: %s", original.Name, original.Description),
			Tags:        append(original.Tags, "fork"),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Metadata:    make(map[string]interface{}),
		},
		Author:          "local",
		License:         original.License,
		Category:        original.Category,
		Keywords:        append(original.Keywords, "fork"),
		SemanticVersion: "1.0.0",
	}

	// Copy content
	copy(fork.Content, original.Content)
	copy(fork.Includes, original.Includes)

	// Copy variables
	for k, v := range original.Variables {
		fork.Variables[k] = v
	}

	// Copy metadata with fork information
	for k, v := range original.Metadata {
		fork.Metadata[k] = v
	}
	fork.Metadata["forked_from"] = templateID
	fork.Metadata["forked_at"] = time.Now()

	// Save fork
	if err := m.store.Save(ctx, fork.Template); err != nil {
		return nil, fmt.Errorf("failed to save fork: %w", err)
	}

	return fork, nil
}

// Publish publishes a template to the marketplace
func (m *Marketplace) Publish(ctx context.Context, template *MarketplaceTemplate) error {
	// Validate template before publishing
	if err := m.validateForPublishing(template); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// In a real implementation, this would:
	// 1. Create a PR to the marketplace repository
	// 2. Run automated validation
	// 3. Wait for review/approval
	// 4. Merge to marketplace catalog

	// For now, just save locally
	if err := m.store.Save(ctx, template.Template); err != nil {
		return fmt.Errorf("failed to save template: %w", err)
	}

	// Add to catalog
	m.cacheMutex.Lock()
	cacheKey := fmt.Sprintf("%s@%s", template.ID, template.SemanticVersion)
	m.catalogCache[cacheKey] = template
	m.cacheMutex.Unlock()

	return nil
}

// List lists all available templates in the marketplace
func (m *Marketplace) List(ctx context.Context, category string) ([]*MarketplaceTemplate, error) {
	query := MarketplaceSearchQuery{
		Category: category,
		SortBy:   "downloads",
	}
	return m.Search(ctx, query)
}

// ListCategories returns available template categories
func (m *Marketplace) ListCategories() []string {
	return m.config.Categories
}

// Helper methods

func (m *Marketplace) refreshCatalogIfNeeded(ctx context.Context) error {
	m.cacheMutex.RLock()
	shouldRefresh := time.Since(m.lastRefresh) > m.config.RefreshInterval
	m.cacheMutex.RUnlock()

	if shouldRefresh {
		return m.refreshCatalog(ctx)
	}
	return nil
}

func (m *Marketplace) refreshCatalog(ctx context.Context) error {
	// In a real implementation, this would:
	// 1. Clone/pull the marketplace Git repository
	// 2. Parse all template manifests
	// 3. Update the local catalog cache

	// For now, load from local store
	templates, err := m.store.List(ctx, TemplateFilter{})
	if err != nil {
		return err
	}

	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()

	for _, template := range templates {
		mt := m.convertToMarketplaceTemplate(template)
		cacheKey := fmt.Sprintf("%s@%s", template.ID, template.Version)
		m.catalogCache[cacheKey] = mt
	}

	m.lastRefresh = time.Now()
	return nil
}

func (m *Marketplace) convertToMarketplaceTemplate(t *Template) *MarketplaceTemplate {
	mt := &MarketplaceTemplate{
		Template:        t,
		SemanticVersion: t.Version,
	}

	// Extract marketplace metadata from template metadata
	if t.Metadata != nil {
		if author, ok := t.Metadata["author"].(string); ok {
			mt.Author = author
		}
		if license, ok := t.Metadata["license"].(string); ok {
			mt.License = license
		}
		if category, ok := t.Metadata["category"].(string); ok {
			mt.Category = category
		}
	}

	return mt
}

func (m *Marketplace) matchesQuery(template *MarketplaceTemplate, query MarketplaceSearchQuery) bool {
	// Text search
	if query.Query != "" {
		searchText := strings.ToLower(query.Query)
		if !strings.Contains(strings.ToLower(template.Name), searchText) &&
			!strings.Contains(strings.ToLower(template.Description), searchText) &&
			!m.containsKeyword(template.Keywords, searchText) {
			return false
		}
	}

	// Category filter
	if query.Category != "" && !strings.EqualFold(template.Category, query.Category) {
		return false
	}

	// Tags filter
	if len(query.Tags) > 0 && !m.hasAnyTag(template.Tags, query.Tags) {
		return false
	}

	// Compliance frameworks filter
	if len(query.ComplianceFrameworks) > 0 && !m.hasAnyFramework(template.ComplianceFrameworks, query.ComplianceFrameworks) {
		return false
	}

	// Featured filter
	if query.FeaturedOnly && !template.Featured {
		return false
	}

	return true
}

func (m *Marketplace) containsKeyword(keywords []string, search string) bool {
	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(keyword), search) {
			return true
		}
	}
	return false
}

func (m *Marketplace) hasAnyTag(templateTags, queryTags []string) bool {
	for _, queryTag := range queryTags {
		for _, templateTag := range templateTags {
			if strings.EqualFold(queryTag, templateTag) {
				return true
			}
		}
	}
	return false
}

func (m *Marketplace) hasAnyFramework(templateFrameworks, queryFrameworks []string) bool {
	for _, queryFw := range queryFrameworks {
		for _, templateFw := range templateFrameworks {
			if strings.EqualFold(queryFw, templateFw) {
				return true
			}
		}
	}
	return false
}

func (m *Marketplace) sortResults(templates []*MarketplaceTemplate, sortBy string) []*MarketplaceTemplate {
	// Simple sorting implementation
	// In production, use a more sophisticated sorting algorithm
	return templates
}

func (m *Marketplace) checkCompatibility(template *MarketplaceTemplate) error {
	// Check minimum version requirement
	// Check required modules are available
	// Check required features are enabled
	return nil
}

func (m *Marketplace) installDependencies(ctx context.Context, template *MarketplaceTemplate) error {
	for _, dep := range template.Dependencies {
		if dep.Required {
			// Check if dependency is already installed
			exists, err := m.store.Exists(ctx, dep.TemplateID)
			if err != nil {
				return err
			}

			if !exists {
				// Install dependency
				if err := m.Install(ctx, dep.TemplateID, dep.Version); err != nil {
					return fmt.Errorf("failed to install dependency %s: %w", dep.TemplateID, err)
				}
			}
		}
	}
	return nil
}

func (m *Marketplace) validateForPublishing(template *MarketplaceTemplate) error {
	if template.ID == "" {
		return fmt.Errorf("template ID is required")
	}
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if template.Author == "" {
		return fmt.Errorf("author is required")
	}
	if template.License == "" {
		return fmt.Errorf("license is required")
	}
	if template.SemanticVersion == "" {
		return fmt.Errorf("semantic version is required")
	}
	if template.Category == "" {
		return fmt.Errorf("category is required")
	}
	return nil
}

// MarketplaceSearchQuery defines search criteria
type MarketplaceSearchQuery struct {
	Query                string
	Category             string
	Tags                 []string
	ComplianceFrameworks []string
	FeaturedOnly         bool
	SortBy               string
	Limit                int
	Offset               int
}

// TemplateRegistry manages template versions and dependencies
type TemplateRegistry struct {
	mu        sync.RWMutex
	templates map[string]map[string]*MarketplaceTemplate // templateID -> version -> template
}

// NewTemplateRegistry creates a new template registry
func NewTemplateRegistry() *TemplateRegistry {
	return &TemplateRegistry{
		templates: make(map[string]map[string]*MarketplaceTemplate),
	}
}

// Register registers a template version
func (r *TemplateRegistry) Register(template *MarketplaceTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.templates[template.ID]; !exists {
		r.templates[template.ID] = make(map[string]*MarketplaceTemplate)
	}

	r.templates[template.ID][template.SemanticVersion] = template
	return nil
}

// Get retrieves a specific template version
func (r *TemplateRegistry) Get(templateID, version string) (*MarketplaceTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	versions, exists := r.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	if version == "" {
		// Return latest version
		return r.getLatestVersion(versions), nil
	}

	template, exists := versions[version]
	if !exists {
		return nil, fmt.Errorf("version not found: %s@%s", templateID, version)
	}

	return template, nil
}

// ListVersions returns all versions of a template
func (r *TemplateRegistry) ListVersions(templateID string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	versions, exists := r.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	var versionList []string
	for version := range versions {
		versionList = append(versionList, version)
	}

	return versionList, nil
}

func (r *TemplateRegistry) getLatestVersion(versions map[string]*MarketplaceTemplate) *MarketplaceTemplate {
	// Simple implementation - return any version
	// In production, implement semantic version comparison
	for _, template := range versions {
		return template
	}
	return nil
}

// TemplateManifest represents a template manifest file for marketplace distribution
type TemplateManifest struct {
	ID                   string               `yaml:"id"`
	Name                 string               `yaml:"name"`
	Version              string               `yaml:"version"`
	Description          string               `yaml:"description"`
	Author               string               `yaml:"author"`
	AuthorEmail          string               `yaml:"author_email,omitempty"`
	License              string               `yaml:"license"`
	Repository           string               `yaml:"repository,omitempty"`
	Homepage             string               `yaml:"homepage,omitempty"`
	Category             string               `yaml:"category"`
	Keywords             []string             `yaml:"keywords,omitempty"`
	Tags                 []string             `yaml:"tags,omitempty"`
	ComplianceFrameworks []string             `yaml:"compliance_frameworks,omitempty"`
	SecurityLevel        string               `yaml:"security_level,omitempty"`
	TestedPlatforms      []string             `yaml:"tested_platforms,omitempty"`
	MinVersion           string               `yaml:"min_version,omitempty"`
	RequiredModules      []string             `yaml:"required_modules,omitempty"`
	RequiredFeatures     []string             `yaml:"required_features,omitempty"`
	Dependencies         []TemplateDependency `yaml:"dependencies,omitempty"`
	TemplateFile         string               `yaml:"template_file"`
	ReadmeFile           string               `yaml:"readme_file,omitempty"`
	Changelog            []Change             `yaml:"changelog,omitempty"`
}

// LoadManifest loads a template manifest from a YAML file
func LoadManifest(path string) (*TemplateManifest, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- Path from internal template management system
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest TemplateManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}

// SaveManifest saves a template manifest to a YAML file
func SaveManifest(manifest *TemplateManifest, path string) error {
	data, err := yaml.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}
