package transform

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// DefaultTransformRegistry provides a thread-safe implementation of TransformRegistry
//
// This registry uses a map for fast lookups and includes automatic validation
// and conflict detection. It supports hot-reloading of transforms and provides
// detailed metadata for discovery and documentation.
type DefaultTransformRegistry struct {
	// transforms stores all registered transforms by name
	transforms map[string]Transform

	// metadata caches transform metadata for fast access
	metadata map[string]TransformMetadata

	// categories indexes transforms by category for fast filtering
	categories map[TransformCategory][]string

	// tags indexes transforms by tags for fast searching
	tags map[string][]string

	// mutex protects concurrent access to the registry
	mutex sync.RWMutex

	// validationEnabled controls whether to validate transforms on registration
	validationEnabled bool
}

// NewDefaultTransformRegistry creates a new transform registry
func NewDefaultTransformRegistry() *DefaultTransformRegistry {
	return &DefaultTransformRegistry{
		transforms:        make(map[string]Transform),
		metadata:          make(map[string]TransformMetadata),
		categories:        make(map[TransformCategory][]string),
		tags:              make(map[string][]string),
		validationEnabled: true,
	}
}

// Register adds a transform to the registry
func (r *DefaultTransformRegistry) Register(transform Transform) error {
	if transform == nil {
		return fmt.Errorf("cannot register nil transform")
	}

	metadata := transform.GetMetadata()
	if metadata.Name == "" {
		return fmt.Errorf("transform must have a non-empty name")
	}

	// Validate the transform if validation is enabled
	if r.validationEnabled {
		if err := r.validateTransform(transform); err != nil {
			return fmt.Errorf("transform validation failed: %w", err)
		}
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check for name conflicts
	if _, exists := r.transforms[metadata.Name]; exists {
		return fmt.Errorf("transform with name '%s' is already registered", metadata.Name)
	}

	// Register the transform
	r.transforms[metadata.Name] = transform
	r.metadata[metadata.Name] = metadata

	// Update category index
	categoryTransforms := r.categories[metadata.Category]
	categoryTransforms = append(categoryTransforms, metadata.Name)
	r.categories[metadata.Category] = categoryTransforms

	// Update tag index
	for _, tag := range metadata.Tags {
		tagTransforms := r.tags[tag]
		tagTransforms = append(tagTransforms, metadata.Name)
		r.tags[tag] = tagTransforms
	}

	return nil
}

// Get retrieves a transform by name
func (r *DefaultTransformRegistry) Get(name string) (Transform, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	transform, exists := r.transforms[name]
	if !exists {
		return nil, fmt.Errorf("transform '%s' not found", name)
	}

	return transform, nil
}

// List returns all registered transforms
func (r *DefaultTransformRegistry) List() []Transform {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	transforms := make([]Transform, 0, len(r.transforms))
	for _, transform := range r.transforms {
		transforms = append(transforms, transform)
	}

	// Sort by name for consistent ordering
	sort.Slice(transforms, func(i, j int) bool {
		return transforms[i].GetMetadata().Name < transforms[j].GetMetadata().Name
	})

	return transforms
}

// ListByCategory returns transforms in a specific category
func (r *DefaultTransformRegistry) ListByCategory(category TransformCategory) []Transform {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	transformNames, exists := r.categories[category]
	if !exists {
		return []Transform{}
	}

	transforms := make([]Transform, 0, len(transformNames))
	for _, name := range transformNames {
		if transform, exists := r.transforms[name]; exists {
			transforms = append(transforms, transform)
		}
	}

	// Sort by name for consistent ordering
	sort.Slice(transforms, func(i, j int) bool {
		return transforms[i].GetMetadata().Name < transforms[j].GetMetadata().Name
	})

	return transforms
}

// Search finds transforms matching criteria
func (r *DefaultTransformRegistry) Search(criteria SearchCriteria) []Transform {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var results []Transform

	for _, transform := range r.transforms {
		if r.matchesCriteria(transform, criteria) {
			results = append(results, transform)
		}
	}

	// Sort by name for consistent ordering
	sort.Slice(results, func(i, j int) bool {
		return results[i].GetMetadata().Name < results[j].GetMetadata().Name
	})

	return results
}

// Unregister removes a transform from the registry
func (r *DefaultTransformRegistry) Unregister(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	transform, exists := r.transforms[name]
	if !exists {
		return fmt.Errorf("transform '%s' not found", name)
	}

	metadata := transform.GetMetadata()

	// Remove from main maps
	delete(r.transforms, name)
	delete(r.metadata, name)

	// Remove from category index
	if categoryTransforms, exists := r.categories[metadata.Category]; exists {
		r.categories[metadata.Category] = r.removeStringFromSlice(categoryTransforms, name)
	}

	// Remove from tag index
	for _, tag := range metadata.Tags {
		if tagTransforms, exists := r.tags[tag]; exists {
			r.tags[tag] = r.removeStringFromSlice(tagTransforms, name)
			// Clean up empty tag entries
			if len(r.tags[tag]) == 0 {
				delete(r.tags, tag)
			}
		}
	}

	return nil
}

// GetMetadata returns metadata for all registered transforms
func (r *DefaultTransformRegistry) GetMetadata() []TransformMetadata {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	metadata := make([]TransformMetadata, 0, len(r.metadata))
	for _, meta := range r.metadata {
		metadata = append(metadata, meta)
	}

	// Sort by name for consistent ordering
	sort.Slice(metadata, func(i, j int) bool {
		return metadata[i].Name < metadata[j].Name
	})

	return metadata
}

// Validate validates that all registered transforms are properly configured
func (r *DefaultTransformRegistry) Validate() error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var errors []string

	for name, transform := range r.transforms {
		if err := r.validateTransform(transform); err != nil {
			errors = append(errors, fmt.Sprintf("transform '%s': %v", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("transform validation errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// SetValidationEnabled controls whether transforms are validated on registration
func (r *DefaultTransformRegistry) SetValidationEnabled(enabled bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.validationEnabled = enabled
}

// GetStats returns registry statistics
func (r *DefaultTransformRegistry) GetStats() RegistryStats {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	stats := RegistryStats{
		TotalTransforms: len(r.transforms),
		Categories:      make(map[TransformCategory]int),
		Tags:            make(map[string]int),
	}

	for category, transforms := range r.categories {
		stats.Categories[category] = len(transforms)
	}

	for tag, transforms := range r.tags {
		stats.Tags[tag] = len(transforms)
	}

	return stats
}

// GetCategoryCounts returns the number of transforms in each category
func (r *DefaultTransformRegistry) GetCategoryCounts() map[TransformCategory]int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	counts := make(map[TransformCategory]int)
	for category, transforms := range r.categories {
		counts[category] = len(transforms)
	}

	return counts
}

// GetAvailableTags returns all available tags
func (r *DefaultTransformRegistry) GetAvailableTags() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	tags := make([]string, 0, len(r.tags))
	for tag := range r.tags {
		tags = append(tags, tag)
	}

	sort.Strings(tags)
	return tags
}

// validateTransform performs validation on a transform
func (r *DefaultTransformRegistry) validateTransform(transform Transform) error {
	metadata := transform.GetMetadata()

	// Validate metadata
	if metadata.Name == "" {
		return fmt.Errorf("transform name cannot be empty")
	}

	if metadata.Version == "" {
		return fmt.Errorf("transform version cannot be empty")
	}

	if metadata.Description == "" {
		return fmt.Errorf("transform description cannot be empty")
	}

	// Validate category
	if !r.isValidCategory(metadata.Category) {
		return fmt.Errorf("invalid transform category: %s", metadata.Category)
	}

	// Try to get schema (this validates the transform implements the interface correctly)
	_ = transform.GetSchema() // Validation that the interface is implemented correctly

	// Test basic validation (this ensures the Validate method works)
	if err := transform.Validate(nil); err != nil {
		// Only fail if the error is not about missing config
		// since we're testing with nil config
		if !strings.Contains(err.Error(), "config") && !strings.Contains(err.Error(), "nil") {
			return fmt.Errorf("transform validate method failed: %w", err)
		}
	}

	return nil
}

// matchesCriteria checks if a transform matches the search criteria
func (r *DefaultTransformRegistry) matchesCriteria(transform Transform, criteria SearchCriteria) bool {
	metadata := transform.GetMetadata()

	// Check category
	if criteria.Category != "" && metadata.Category != criteria.Category {
		return false
	}

	// Check name (substring match)
	if criteria.Name != "" && !strings.Contains(strings.ToLower(metadata.Name), strings.ToLower(criteria.Name)) {
		return false
	}

	// Check description (substring match)
	if criteria.Description != "" && !strings.Contains(strings.ToLower(metadata.Description), strings.ToLower(criteria.Description)) {
		return false
	}

	// Check author
	if criteria.Author != "" && !strings.Contains(strings.ToLower(metadata.Author), strings.ToLower(criteria.Author)) {
		return false
	}

	// Check tags (any of the criteria tags must match)
	if len(criteria.Tags) > 0 {
		hasMatchingTag := false
		for _, criteriaTag := range criteria.Tags {
			for _, transformTag := range metadata.Tags {
				if strings.EqualFold(criteriaTag, transformTag) {
					hasMatchingTag = true
					break
				}
			}
			if hasMatchingTag {
				break
			}
		}
		if !hasMatchingTag {
			return false
		}
	}

	// Check required capabilities (all criteria capabilities must be supported)
	if len(criteria.RequiredCapabilities) > 0 {
		for _, requiredCap := range criteria.RequiredCapabilities {
			found := false
			for _, transformCap := range metadata.RequiredCapabilities {
				if strings.EqualFold(requiredCap, transformCap) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	// Check chaining support
	if criteria.SupportsChaining != nil && metadata.SupportsChaining != *criteria.SupportsChaining {
		return false
	}

	return true
}

// isValidCategory checks if a category is valid
func (r *DefaultTransformRegistry) isValidCategory(category TransformCategory) bool {
	validCategories := []TransformCategory{
		CategoryString,
		CategoryData,
		CategoryPath,
		CategoryValidation,
		CategoryConversion,
		CategoryMath,
		CategoryTemplate,
		CategoryCustom,
		CategoryUtility,
	}

	for _, validCategory := range validCategories {
		if category == validCategory {
			return true
		}
	}

	return false
}

// removeStringFromSlice removes a string from a slice
func (r *DefaultTransformRegistry) removeStringFromSlice(slice []string, item string) []string {
	for i, v := range slice {
		if v == item {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// RegistryStats provides statistics about the transform registry
type RegistryStats struct {
	// TotalTransforms is the total number of registered transforms
	TotalTransforms int `json:"total_transforms"`

	// Categories shows the number of transforms in each category
	Categories map[TransformCategory]int `json:"categories"`

	// Tags shows the number of transforms for each tag
	Tags map[string]int `json:"tags"`
}

// Global registry instance for easy access
var (
	globalRegistry     *DefaultTransformRegistry
	globalRegistryOnce sync.Once
)

// GetGlobalRegistry returns the global transform registry instance
//
// This provides a singleton registry that can be used throughout the application.
// The registry is created once and reused for all subsequent calls.
func GetGlobalRegistry() TransformRegistry {
	globalRegistryOnce.Do(func() {
		globalRegistry = NewDefaultTransformRegistry()
	})
	return globalRegistry
}

// RegisterTransform is a convenience function to register a transform with the global registry
func RegisterTransform(transform Transform) error {
	return GetGlobalRegistry().Register(transform)
}

// GetTransform is a convenience function to get a transform from the global registry
func GetTransform(name string) (Transform, error) {
	return GetGlobalRegistry().Get(name)
}

// ListTransforms is a convenience function to list all transforms from the global registry
func ListTransforms() []Transform {
	return GetGlobalRegistry().List()
}

// ListTransformsByCategory is a convenience function to list transforms by category from the global registry
func ListTransformsByCategory(category TransformCategory) []Transform {
	return GetGlobalRegistry().ListByCategory(category)
}

// SearchTransforms is a convenience function to search transforms in the global registry
func SearchTransforms(criteria SearchCriteria) []Transform {
	return GetGlobalRegistry().Search(criteria)
}