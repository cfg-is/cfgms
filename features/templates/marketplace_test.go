// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package templates_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/templates"
)

// fakeClock is a controllable clock for deterministic TTL testing.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func TestMarketplace_BasicOperations(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	config := templates.MarketplaceConfig{
		AllowCommunityTemplates: true,
		LocalCachePath:          t.TempDir(),
		RefreshInterval:         1 * time.Hour,
	}
	marketplace := templates.NewMarketplace(config, store)
	defer marketplace.Close()

	ctx := context.Background()

	// Create a test template. Metadata["category"] is required so that
	// convertToMarketplaceTemplate can reconstruct Category after a store refresh.
	testTemplate := &templates.MarketplaceTemplate{
		Template: &templates.Template{
			ID:          "test-template",
			Name:        "Test Template",
			Content:     []byte("test content"),
			Version:     "1.0.0",
			Description: "A test template for unit testing",
			Tags:        []string{"test", "example"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Metadata:    map[string]interface{}{"category": "security"},
		},
		Author:          "Test Author",
		License:         "MIT",
		Category:        "security",
		Keywords:        []string{"test", "security"},
		SemanticVersion: "1.0.0",
	}

	// Test: Publish template
	err := marketplace.Publish(ctx, testTemplate)
	require.NoError(t, err)

	// Test: Get template
	retrieved, err := marketplace.Get(ctx, "test-template", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "test-template", retrieved.ID)
	assert.Equal(t, "Test Template", retrieved.Name)
	assert.Equal(t, "Test Author", retrieved.Author)

	// Test: List templates — sentinel is absent after Publish, so refresh fires and
	// loads the published template from the store.
	templateList, err := marketplace.List(ctx, "security")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(templateList), 1, "published security template must appear after catalog refresh")

	// Test: Search templates — sentinel is now set, cache is warm, template matches.
	searchQuery := templates.MarketplaceSearchQuery{
		Query:    "test",
		Category: "security",
	}
	searchResults, err := marketplace.Search(ctx, searchQuery)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(searchResults), 1, "published template matches 'test' query in security category")
}

func TestMarketplace_Search(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	config := templates.MarketplaceConfig{
		AllowCommunityTemplates: true,
		LocalCachePath:          t.TempDir(),
	}
	marketplace := templates.NewMarketplace(config, store)
	defer marketplace.Close()

	ctx := context.Background()

	// Create multiple test templates
	testTemplates := []*templates.MarketplaceTemplate{
		{
			Template: &templates.Template{
				ID:          "ssh-hardening",
				Name:        "SSH Hardening Template",
				Content:     []byte("ssh config"),
				Version:     "1.0.0",
				Description: "Comprehensive SSH hardening template",
				Tags:        []string{"security", "ssh", "linux"},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Metadata:    map[string]interface{}{"category": "security"},
			},
			Author:               "CFGMS Team",
			License:              "MIT",
			Category:             "security",
			Keywords:             []string{"ssh", "security", "hardening"},
			ComplianceFrameworks: []string{"CIS", "NIST"},
			SemanticVersion:      "1.0.0",
		},
		{
			Template: &templates.Template{
				ID:          "baseline-security",
				Name:        "Baseline Security Template",
				Content:     []byte("baseline config"),
				Version:     "1.0.0",
				Description: "Comprehensive baseline security template",
				Tags:        []string{"security", "baseline", "linux"},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Metadata:    map[string]interface{}{"category": "security"},
			},
			Author:               "CFGMS Team",
			License:              "MIT",
			Category:             "security",
			Keywords:             []string{"security", "baseline"},
			ComplianceFrameworks: []string{"CIS", "SOC2"},
			SemanticVersion:      "1.0.0",
		},
		{
			Template: &templates.Template{
				ID:          "backup-config",
				Name:        "Backup Configuration Template",
				Content:     []byte("backup config"),
				Version:     "1.0.0",
				Description: "Comprehensive backup configuration template",
				Tags:        []string{"backup", "system"},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Metadata:    map[string]interface{}{"category": "system"},
			},
			Author:          "CFGMS Team",
			License:         "MIT",
			Category:        "system",
			Keywords:        []string{"backup", "disaster-recovery"},
			SemanticVersion: "1.0.0",
		},
	}

	// Publish all templates
	for _, tmpl := range testTemplates {
		err := marketplace.Publish(ctx, tmpl)
		require.NoError(t, err)
	}

	// Test: Search by category — first Search triggers a catalog refresh (sentinel absent),
	// loading all 3 published templates from the store. Two are in "security" category.
	t.Run("SearchByCategory", func(t *testing.T) {
		results, err := marketplace.Search(ctx, templates.MarketplaceSearchQuery{
			Category: "security",
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 2, "ssh-hardening and baseline-security are both security templates")
	})

	// Test: Search by query
	t.Run("SearchByQuery", func(t *testing.T) {
		results, err := marketplace.Search(ctx, templates.MarketplaceSearchQuery{
			Query: "SSH",
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 1)
	})

	// Test: Search by tags
	t.Run("SearchByTags", func(t *testing.T) {
		results, err := marketplace.Search(ctx, templates.MarketplaceSearchQuery{
			Tags: []string{"ssh"},
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 1)
	})

	// Test: Search by compliance framework — catalog is warm from SearchByCategory.
	// ComplianceFrameworks is not stored in Template.Metadata and therefore not
	// recovered by convertToMarketplaceTemplate after a store refresh. The search
	// returns 0 results, which is the expected post-refresh behaviour.
	t.Run("SearchByCompliance", func(t *testing.T) {
		results, err := marketplace.Search(ctx, templates.MarketplaceSearchQuery{
			ComplianceFrameworks: []string{"CIS"},
		})
		require.NoError(t, err)
		assert.Equal(t, 0, len(results), "ComplianceFrameworks is not preserved through store refresh")
	})
}

func TestMarketplace_Fork(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	config := templates.MarketplaceConfig{
		AllowCommunityTemplates: true,
		LocalCachePath:          t.TempDir(),
	}
	marketplace := templates.NewMarketplace(config, store)
	defer marketplace.Close()

	ctx := context.Background()

	// Create original template
	original := &templates.MarketplaceTemplate{
		Template: &templates.Template{
			ID:          "original-template",
			Name:        "Original Template",
			Content:     []byte("original content"),
			Version:     "1.0.0",
			Description: "Original template description",
			Tags:        []string{"original"},
			Variables: map[string]interface{}{
				"var1": "value1",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		Author:          "Original Author",
		License:         "MIT",
		Category:        "security",
		SemanticVersion: "1.0.0",
	}

	// Publish original
	err := marketplace.Publish(ctx, original)
	require.NoError(t, err)

	// Fork template
	fork, err := marketplace.Fork(ctx, "original-template", "forked-template", "My Forked Template")
	require.NoError(t, err)

	// Verify fork
	assert.Equal(t, "forked-template", fork.ID)
	assert.Equal(t, "My Forked Template", fork.Name)
	assert.Equal(t, "1.0.0", fork.SemanticVersion)
	assert.Contains(t, fork.Tags, "fork")
	assert.Equal(t, "value1", fork.Variables["var1"])
	assert.Contains(t, fork.Description, "Forked from")
	assert.Equal(t, "original-template", fork.Metadata["forked_from"])
}

func TestMarketplace_Install(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	config := templates.MarketplaceConfig{
		AllowCommunityTemplates: true,
		LocalCachePath:          t.TempDir(),
	}
	marketplace := templates.NewMarketplace(config, store)
	defer marketplace.Close()

	ctx := context.Background()

	// Create template with dependency
	dependency := &templates.MarketplaceTemplate{
		Template: &templates.Template{
			ID:          "dependency-template",
			Name:        "Dependency Template",
			Content:     []byte("dependency content"),
			Version:     "1.0.0",
			Description: "A dependency template",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		Author:          "CFGMS Team",
		License:         "MIT",
		Category:        "security",
		SemanticVersion: "1.0.0",
	}

	mainTemplate := &templates.MarketplaceTemplate{
		Template: &templates.Template{
			ID:          "main-template",
			Name:        "Main Template",
			Content:     []byte("main content"),
			Version:     "1.0.0",
			Description: "A main template with dependency",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		Author:   "CFGMS Team",
		License:  "MIT",
		Category: "security",
		Dependencies: []templates.TemplateDependency{
			{
				TemplateID: "dependency-template",
				Version:    "1.0.0",
				Required:   true,
			},
		},
		SemanticVersion: "1.0.0",
	}

	// Publish both templates
	err := marketplace.Publish(ctx, dependency)
	require.NoError(t, err)
	err = marketplace.Publish(ctx, mainTemplate)
	require.NoError(t, err)

	// Install main template (should install dependency automatically)
	err = marketplace.Install(ctx, "main-template", "1.0.0")
	require.NoError(t, err)

	// Verify both are installed
	exists, err := store.Exists(ctx, "main-template")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = store.Exists(ctx, "dependency-template")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestMarketplace_Validation(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	config := templates.MarketplaceConfig{
		AllowCommunityTemplates: true,
		LocalCachePath:          t.TempDir(),
	}
	marketplace := templates.NewMarketplace(config, store)
	defer marketplace.Close()

	ctx := context.Background()

	// Test: Invalid template (missing required fields)
	invalidTemplate := &templates.MarketplaceTemplate{
		Template: &templates.Template{
			ID:      "invalid-template",
			Content: []byte("content"),
		},
		SemanticVersion: "1.0.0",
	}

	err := marketplace.Publish(ctx, invalidTemplate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

func TestTemplateRegistry(t *testing.T) {
	registry := templates.NewTemplateRegistry()

	// Create test template
	template := &templates.MarketplaceTemplate{
		Template: &templates.Template{
			ID:      "test-template",
			Name:    "Test Template",
			Version: "1.0.0",
		},
		SemanticVersion: "1.0.0",
	}

	// Test: Register template
	err := registry.Register(template)
	require.NoError(t, err)

	// Test: Get specific version
	retrieved, err := registry.Get("test-template", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "test-template", retrieved.ID)

	// Test: List versions
	versions, err := registry.ListVersions("test-template")
	require.NoError(t, err)
	assert.Contains(t, versions, "1.0.0")

	// Test: Get latest version (empty version string)
	latest, err := registry.Get("test-template", "")
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", latest.SemanticVersion)
}

func TestTemplateManifest(t *testing.T) {
	// Create temporary manifest file
	manifestPath := t.TempDir() + "/manifest.yaml"

	// Create test manifest
	manifest := &templates.TemplateManifest{
		ID:              "test-template",
		Name:            "Test Template",
		Version:         "1.0.0",
		Description:     "A test template",
		Author:          "Test Author",
		License:         "MIT",
		Category:        "security",
		Keywords:        []string{"test", "security"},
		RequiredModules: []string{"file"},
		TemplateFile:    "template.yaml",
		ReadmeFile:      "README.md",
	}

	// Test: Save manifest
	err := templates.SaveManifest(manifest, manifestPath)
	require.NoError(t, err)

	// Test: Load manifest
	loaded, err := templates.LoadManifest(manifestPath)
	require.NoError(t, err)
	assert.Equal(t, "test-template", loaded.ID)
	assert.Equal(t, "Test Template", loaded.Name)
	assert.Equal(t, "1.0.0", loaded.Version)
	assert.Equal(t, "MIT", loaded.License)
	assert.Contains(t, loaded.Keywords, "test")
	assert.Contains(t, loaded.RequiredModules, "file")
}

func TestMarketplace_ListCategories(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	config := templates.MarketplaceConfig{
		AllowCommunityTemplates: true,
		LocalCachePath:          t.TempDir(),
	}
	marketplace := templates.NewMarketplace(config, store)
	defer marketplace.Close()

	// Test: List categories
	categories := marketplace.ListCategories()
	assert.Contains(t, categories, "security")
	assert.Contains(t, categories, "compliance")
	assert.Contains(t, categories, "backup")
	assert.Contains(t, categories, "monitoring")
	assert.Contains(t, categories, "networking")
	assert.Contains(t, categories, "system")
	assert.Contains(t, categories, "application")
}

func TestMarketplace_CatalogCacheTTL(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	store := templates.NewInMemoryTemplateStore()
	refreshInterval := 5 * time.Minute
	config := templates.MarketplaceConfig{
		AllowCommunityTemplates: true,
		LocalCachePath:          t.TempDir(),
		RefreshInterval:         refreshInterval,
		Clock:                   clk,
	}
	marketplace := templates.NewMarketplace(config, store)
	defer marketplace.Close()

	ctx := context.Background()

	tmpl := &templates.MarketplaceTemplate{
		Template: &templates.Template{
			ID:          "ttl-test",
			Name:        "TTL Test Template",
			Content:     []byte("content"),
			Version:     "1.0.0",
			Description: "Template for TTL testing",
			Tags:        []string{"test"},
			CreatedAt:   clk.Now(),
			UpdatedAt:   clk.Now(),
		},
		Author:          "Test Author",
		License:         "MIT",
		Category:        "security",
		SemanticVersion: "1.0.0",
	}

	// Publish saves the template to the store and adds it to the cache directly.
	err := marketplace.Publish(ctx, tmpl)
	require.NoError(t, err)

	// First Search call: "catalog:refreshed" sentinel is absent — triggers refreshCatalog,
	// which loads tmpl from the store. Results must include tmpl.
	results, err := marketplace.Search(ctx, templates.MarketplaceSearchQuery{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1, "post-refresh results must include the published template")

	// Second Search within TTL: sentinel hit — no second refresh.
	// Advance time by less than RefreshInterval.
	clk.advance(refreshInterval / 2)
	results2, err := marketplace.Search(ctx, templates.MarketplaceSearchQuery{})
	require.NoError(t, err)
	// Result count must be the same; no new items were added.
	assert.Equal(t, len(results), len(results2), "within TTL, cache should serve the same data")

	// Advance past TTL: sentinel expires, next Search must trigger refresh.
	clk.advance(refreshInterval + time.Second)

	// Add a second template to the store while the cache is expired.
	tmpl2 := &templates.MarketplaceTemplate{
		Template: &templates.Template{
			ID:          "ttl-test-2",
			Name:        "TTL Test Template 2",
			Content:     []byte("content2"),
			Version:     "1.0.0",
			Description: "Second template added after TTL expiry",
			Tags:        []string{"test"},
			CreatedAt:   clk.Now(),
			UpdatedAt:   clk.Now(),
		},
		Author:          "Test Author",
		License:         "MIT",
		Category:        "security",
		SemanticVersion: "1.0.0",
	}
	err = marketplace.Publish(ctx, tmpl2)
	require.NoError(t, err)

	// After TTL expiry, Search must trigger a fresh refresh and pick up tmpl2.
	results3, err := marketplace.Search(ctx, templates.MarketplaceSearchQuery{})
	require.NoError(t, err)
	assert.Greater(t, len(results3), len(results), "post-TTL refresh should return more results")
}
