package rbac

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cfgis/cfgms/api/proto/common"
)

// ScopeEngine evaluates resource-level permission scopes
type ScopeEngine struct{}

// NewScopeEngine creates a new scope evaluation engine
func NewScopeEngine() *ScopeEngine {
	return &ScopeEngine{}
}

// EvaluateScope checks if a resource is within the permitted scope
func (s *ScopeEngine) EvaluateScope(ctx context.Context, scope *common.PermissionScope, resourceID string, resourceAttributes map[string]string) (bool, string) {
	if scope == nil {
		return true, "no scope restrictions"
	}

	// Check explicit resource IDs
	if len(scope.ResourceIds) > 0 {
		for _, allowedID := range scope.ResourceIds {
			if resourceID == allowedID {
				return true, fmt.Sprintf("resource '%s' is explicitly allowed", resourceID)
			}
		}
		return false, fmt.Sprintf("resource '%s' is not in allowed resource list: %v", resourceID, scope.ResourceIds)
	}

	// Check resource patterns (wildcard matching)
	if len(scope.ResourcePatterns) > 0 {
		for _, pattern := range scope.ResourcePatterns {
			if s.matchesPattern(resourceID, pattern) {
				// Still need to check if it's not explicitly excluded
				if s.isExcluded(resourceID, scope.ExcludedResources) {
					return false, fmt.Sprintf("resource '%s' matches pattern '%s' but is explicitly excluded", resourceID, pattern)
				}
				return true, fmt.Sprintf("resource '%s' matches allowed pattern '%s'", resourceID, pattern)
			}
		}
		return false, fmt.Sprintf("resource '%s' does not match any allowed patterns: %v", resourceID, scope.ResourcePatterns)
	}

	// Check excluded resources (if no specific inclusions, check exclusions)
	if s.isExcluded(resourceID, scope.ExcludedResources) {
		return false, fmt.Sprintf("resource '%s' is explicitly excluded", resourceID)
	}

	// Check resource attributes
	if len(scope.ResourceAttributes) > 0 {
		for requiredKey, requiredValue := range scope.ResourceAttributes {
			actualValue, exists := resourceAttributes[requiredKey]
			if !exists {
				return false, fmt.Sprintf("resource missing required attribute '%s'", requiredKey)
			}
			if actualValue != requiredValue {
				return false, fmt.Sprintf("resource attribute '%s' has value '%s' but requires '%s'",
					requiredKey, actualValue, requiredValue)
			}
		}
		return true, "resource meets all attribute requirements"
	}

	// If no restrictions specified, allow access
	return true, "no scope restrictions applied"
}

// matchesPattern checks if a resource ID matches a pattern with wildcard support
func (s *ScopeEngine) matchesPattern(resourceID, pattern string) bool {
	// Handle simple wildcard patterns
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, resourceID)
		return matched
	}

	// Handle prefix patterns (ending with /)
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(resourceID, pattern)
	}

	// Exact match
	return resourceID == pattern
}

// isExcluded checks if a resource is in the excluded list
func (s *ScopeEngine) isExcluded(resourceID string, excludedResources []string) bool {
	for _, excluded := range excludedResources {
		if s.matchesPattern(resourceID, excluded) {
			return true
		}
	}
	return false
}

// ValidateScope validates that a permission scope is well-formed
func (s *ScopeEngine) ValidateScope(ctx context.Context, scope *common.PermissionScope) error {
	if scope == nil {
		return nil
	}

	// Validate resource patterns
	for _, pattern := range scope.ResourcePatterns {
		if pattern == "" {
			return fmt.Errorf("empty resource pattern not allowed")
		}

		// Check for invalid pattern syntax
		_, err := filepath.Match(pattern, "test")
		if err != nil {
			return fmt.Errorf("invalid resource pattern '%s': %v", pattern, err)
		}
	}

	// Validate excluded resource patterns
	for _, pattern := range scope.ExcludedResources {
		if pattern == "" {
			return fmt.Errorf("empty excluded resource pattern not allowed")
		}

		// Check for invalid pattern syntax
		_, err := filepath.Match(pattern, "test")
		if err != nil {
			return fmt.Errorf("invalid excluded resource pattern '%s': %v", pattern, err)
		}
	}

	// Validate that we don't have conflicting configurations
	if len(scope.ResourceIds) > 0 && len(scope.ResourcePatterns) > 0 {
		return fmt.Errorf("cannot specify both explicit resource IDs and resource patterns")
	}

	return nil
}

// CreateResourceScope creates a permission scope for specific resources
func (s *ScopeEngine) CreateResourceScope(resourceIDs []string, excludedIDs []string) *common.PermissionScope {
	return &common.PermissionScope{
		ResourceIds:       resourceIDs,
		ExcludedResources: excludedIDs,
	}
}

// CreatePatternScope creates a permission scope using wildcard patterns
func (s *ScopeEngine) CreatePatternScope(patterns []string, excludedPatterns []string) *common.PermissionScope {
	return &common.PermissionScope{
		ResourcePatterns:  patterns,
		ExcludedResources: excludedPatterns,
	}
}

// CreateAttributeScope creates a permission scope based on resource attributes
func (s *ScopeEngine) CreateAttributeScope(requiredAttributes map[string]string) *common.PermissionScope {
	return &common.PermissionScope{
		ResourceAttributes: requiredAttributes,
	}
}

// CreateCombinedScope creates a permission scope with multiple restrictions
func (s *ScopeEngine) CreateCombinedScope(
	resourceIDs []string,
	patterns []string,
	excludedResources []string,
	requiredAttributes map[string]string,
) *common.PermissionScope {
	return &common.PermissionScope{
		ResourceIds:        resourceIDs,
		ResourcePatterns:   patterns,
		ExcludedResources:  excludedResources,
		ResourceAttributes: requiredAttributes,
	}
}

// ComputeEffectiveScope combines multiple scopes using the most restrictive rules
func (s *ScopeEngine) ComputeEffectiveScope(ctx context.Context, scopes []*common.PermissionScope) (*common.PermissionScope, error) {
	if len(scopes) == 0 {
		return nil, nil
	}

	if len(scopes) == 1 {
		return scopes[0], nil
	}

	effective := &common.PermissionScope{
		ResourceIds:        make([]string, 0),
		ResourcePatterns:   make([]string, 0),
		ExcludedResources:  make([]string, 0),
		ResourceAttributes: make(map[string]string),
	}

	// Combine resource IDs (intersection - most restrictive)
	resourceIDSets := make([]map[string]bool, 0)
	for _, scope := range scopes {
		if len(scope.ResourceIds) > 0 {
			idSet := make(map[string]bool)
			for _, id := range scope.ResourceIds {
				idSet[id] = true
			}
			resourceIDSets = append(resourceIDSets, idSet)
		}
	}

	if len(resourceIDSets) > 0 {
		// Start with the first set
		intersection := resourceIDSets[0]

		// Intersect with remaining sets
		for i := 1; i < len(resourceIDSets); i++ {
			newIntersection := make(map[string]bool)
			for id := range intersection {
				if resourceIDSets[i][id] {
					newIntersection[id] = true
				}
			}
			intersection = newIntersection
		}

		// Convert back to slice
		for id := range intersection {
			effective.ResourceIds = append(effective.ResourceIds, id)
		}
	}

	// Combine resource patterns (union - if any scope allows a pattern)
	patternSet := make(map[string]bool)
	for _, scope := range scopes {
		for _, pattern := range scope.ResourcePatterns {
			patternSet[pattern] = true
		}
	}
	for pattern := range patternSet {
		effective.ResourcePatterns = append(effective.ResourcePatterns, pattern)
	}

	// Combine excluded resources (union - if any scope excludes, it's excluded)
	excludedSet := make(map[string]bool)
	for _, scope := range scopes {
		for _, excluded := range scope.ExcludedResources {
			excludedSet[excluded] = true
		}
	}
	for excluded := range excludedSet {
		effective.ExcludedResources = append(effective.ExcludedResources, excluded)
	}

	// Combine resource attributes (all must match - most restrictive)
	for _, scope := range scopes {
		for key, value := range scope.ResourceAttributes {
			if existingValue, exists := effective.ResourceAttributes[key]; exists {
				if existingValue != value {
					return nil, fmt.Errorf("conflicting resource attribute requirements: %s='%s' vs %s='%s'",
						key, existingValue, key, value)
				}
			} else {
				effective.ResourceAttributes[key] = value
			}
		}
	}

	return effective, nil
}
