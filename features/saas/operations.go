// Package saas operations implements normalized CRUD operations
// that provide a standardized interface across all SaaS providers.
//
// The normalized operations abstraction allows users to work with
// any SaaS API using consistent create, read, update, delete, and list
// operations without learning provider-specific APIs.
//
// Example usage:
//
//	// Create a user (works with Microsoft, Google, Salesforce, etc.)
//	result, err := provider.Create(ctx, "users", map[string]interface{}{
//		"name": "John Doe",
//		"email": "john@company.com",
//		"active": true,
//	})
//	
//	// List all users with pagination
//	result, err := provider.List(ctx, "users", map[string]interface{}{
//		"filter": "active eq true",
//		"limit": 50,
//	})
package saas

import (
	"context"
	"fmt"
	"strings"
)

// NormalizedOperations provides standardized CRUD operations for any SaaS provider
type NormalizedOperations struct {
	provider     Provider
	resourceMap  map[string]ResourceMapping
	fieldMap     map[string]map[string]string // resourceType -> field mappings
	operationMap map[string]OperationMapping
}

// ResourceMapping defines how normalized resource types map to provider-specific types
type ResourceMapping struct {
	// NormalizedType is the standard resource type (e.g., "users", "groups")
	NormalizedType string `json:"normalized_type"`
	
	// ProviderType is the provider-specific resource type
	ProviderType string `json:"provider_type"`
	
	// APIPath is the API endpoint path for this resource
	APIPath string `json:"api_path"`
	
	// IDField specifies which field contains the resource ID
	IDField string `json:"id_field"`
	
	// NameField specifies which field contains the resource name/display name
	NameField string `json:"name_field"`
	
	// SupportedOperations lists which CRUD operations are supported
	SupportedOperations []string `json:"supported_operations"`
	
	// RequiredFields lists fields required for create operations
	RequiredFields []string `json:"required_fields"`
	
	// ReadOnlyFields lists fields that cannot be modified
	ReadOnlyFields []string `json:"read_only_fields"`
}

// OperationMapping defines how normalized operations map to provider-specific operations
type OperationMapping struct {
	// NormalizedOperation is the standard operation (create, read, update, delete, list)
	NormalizedOperation string `json:"normalized_operation"`
	
	// HTTPMethod is the HTTP method to use
	HTTPMethod string `json:"http_method"`
	
	// URLTemplate is the URL pattern with placeholders
	URLTemplate string `json:"url_template"`
	
	// BodyTemplate defines the request body structure
	BodyTemplate map[string]interface{} `json:"body_template"`
	
	// ResponseMapping defines how to extract data from responses
	ResponseMapping ResponseMapping `json:"response_mapping"`
	
	// RequiredParams lists required parameters
	RequiredParams []string `json:"required_params"`
	
	// OptionalParams lists optional parameters
	OptionalParams []string `json:"optional_params"`
}

// ResponseMapping defines how to extract data from API responses
type ResponseMapping struct {
	// DataPath is the JSON path to the main data
	DataPath string `json:"data_path"`
	
	// ItemsPath is the JSON path to items in list responses
	ItemsPath string `json:"items_path"`
	
	// PaginationPath is the JSON path to pagination info
	PaginationPath string `json:"pagination_path"`
	
	// ErrorPath is the JSON path to error information
	ErrorPath string `json:"error_path"`
}

// NewNormalizedOperations creates a new normalized operations handler
func NewNormalizedOperations(provider Provider) *NormalizedOperations {
	return &NormalizedOperations{
		provider:     provider,
		resourceMap:  getDefaultResourceMappings(),
		fieldMap:     getDefaultFieldMappings(),
		operationMap: getDefaultOperationMappings(),
	}
}

// Create creates a new resource using normalized parameters
func (no *NormalizedOperations) Create(ctx context.Context, resourceType string, data map[string]interface{}) (*ProviderResult, error) {
	// Validate the resource type is supported
	mapping, exists := no.resourceMap[resourceType]
	if !exists {
		return nil, fmt.Errorf("resource type %s not supported", resourceType)
	}
	
	if !contains(mapping.SupportedOperations, "create") {
		return nil, fmt.Errorf("create operation not supported for resource type %s", resourceType)
	}
	
	// Validate required fields
	if err := no.validateRequiredFields(resourceType, data); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	
	// Transform normalized data to provider-specific format
	providerData, err := no.transformToProviderFormat(resourceType, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transform data: %w", err)
	}
	
	// Get operation mapping
	operation, exists := no.operationMap[resourceType+":create"]
	if !exists {
		// Fall back to generic create operation
		return no.genericCreate(ctx, mapping, providerData)
	}
	
	// Execute the create operation
	return no.executeOperation(ctx, operation, map[string]interface{}{
		"data": providerData,
	})
}

// Read retrieves a resource by ID
func (no *NormalizedOperations) Read(ctx context.Context, resourceType string, resourceID string) (*ProviderResult, error) {
	mapping, exists := no.resourceMap[resourceType]
	if !exists {
		return nil, fmt.Errorf("resource type %s not supported", resourceType)
	}
	
	if !contains(mapping.SupportedOperations, "read") {
		return nil, fmt.Errorf("read operation not supported for resource type %s", resourceType)
	}
	
	// Get operation mapping
	operation, exists := no.operationMap[resourceType+":read"]
	if !exists {
		// Fall back to generic read operation
		return no.genericRead(ctx, mapping, resourceID)
	}
	
	// Execute the read operation
	return no.executeOperation(ctx, operation, map[string]interface{}{
		"id": resourceID,
	})
}

// Update modifies an existing resource
func (no *NormalizedOperations) Update(ctx context.Context, resourceType string, resourceID string, data map[string]interface{}) (*ProviderResult, error) {
	mapping, exists := no.resourceMap[resourceType]
	if !exists {
		return nil, fmt.Errorf("resource type %s not supported", resourceType)
	}
	
	if !contains(mapping.SupportedOperations, "update") {
		return nil, fmt.Errorf("update operation not supported for resource type %s", resourceType)
	}
	
	// Remove read-only fields
	updateData := no.filterReadOnlyFields(resourceType, data)
	
	// Transform normalized data to provider-specific format
	providerData, err := no.transformToProviderFormat(resourceType, updateData)
	if err != nil {
		return nil, fmt.Errorf("failed to transform data: %w", err)
	}
	
	// Get operation mapping
	operation, exists := no.operationMap[resourceType+":update"]
	if !exists {
		// Fall back to generic update operation
		return no.genericUpdate(ctx, mapping, resourceID, providerData)
	}
	
	// Execute the update operation
	return no.executeOperation(ctx, operation, map[string]interface{}{
		"id":   resourceID,
		"data": providerData,
	})
}

// Delete removes a resource
func (no *NormalizedOperations) Delete(ctx context.Context, resourceType string, resourceID string) (*ProviderResult, error) {
	mapping, exists := no.resourceMap[resourceType]
	if !exists {
		return nil, fmt.Errorf("resource type %s not supported", resourceType)
	}
	
	if !contains(mapping.SupportedOperations, "delete") {
		return nil, fmt.Errorf("delete operation not supported for resource type %s", resourceType)
	}
	
	// Get operation mapping
	operation, exists := no.operationMap[resourceType+":delete"]
	if !exists {
		// Fall back to generic delete operation
		return no.genericDelete(ctx, mapping, resourceID)
	}
	
	// Execute the delete operation
	return no.executeOperation(ctx, operation, map[string]interface{}{
		"id": resourceID,
	})
}

// List retrieves multiple resources with optional filtering
func (no *NormalizedOperations) List(ctx context.Context, resourceType string, filters map[string]interface{}) (*ProviderResult, error) {
	mapping, exists := no.resourceMap[resourceType]
	if !exists {
		return nil, fmt.Errorf("resource type %s not supported", resourceType)
	}
	
	if !contains(mapping.SupportedOperations, "list") {
		return nil, fmt.Errorf("list operation not supported for resource type %s", resourceType)
	}
	
	// Transform normalized filters to provider-specific format
	providerFilters, err := no.transformFilters(resourceType, filters)
	if err != nil {
		return nil, fmt.Errorf("failed to transform filters: %w", err)
	}
	
	// Get operation mapping
	operation, exists := no.operationMap[resourceType+":list"]
	if !exists {
		// Fall back to generic list operation
		return no.genericList(ctx, mapping, providerFilters)
	}
	
	// Execute the list operation
	return no.executeOperation(ctx, operation, providerFilters)
}

// Generic operation implementations (fallbacks)

func (no *NormalizedOperations) genericCreate(ctx context.Context, mapping ResourceMapping, data map[string]interface{}) (*ProviderResult, error) {
	// Build URL
	url := strings.TrimSuffix(mapping.APIPath, "/")
	
	// Execute raw API call
	return no.provider.RawAPI(ctx, "POST", url, data)
}

func (no *NormalizedOperations) genericRead(ctx context.Context, mapping ResourceMapping, resourceID string) (*ProviderResult, error) {
	// Build URL
	url := strings.TrimSuffix(mapping.APIPath, "/") + "/" + resourceID
	
	// Execute raw API call
	return no.provider.RawAPI(ctx, "GET", url, nil)
}

func (no *NormalizedOperations) genericUpdate(ctx context.Context, mapping ResourceMapping, resourceID string, data map[string]interface{}) (*ProviderResult, error) {
	// Build URL
	url := strings.TrimSuffix(mapping.APIPath, "/") + "/" + resourceID
	
	// Execute raw API call (use PATCH for partial updates)
	return no.provider.RawAPI(ctx, "PATCH", url, data)
}

func (no *NormalizedOperations) genericDelete(ctx context.Context, mapping ResourceMapping, resourceID string) (*ProviderResult, error) {
	// Build URL
	url := strings.TrimSuffix(mapping.APIPath, "/") + "/" + resourceID
	
	// Execute raw API call
	return no.provider.RawAPI(ctx, "DELETE", url, nil)
}

func (no *NormalizedOperations) genericList(ctx context.Context, mapping ResourceMapping, filters map[string]interface{}) (*ProviderResult, error) {
	// Build URL with query parameters
	url := strings.TrimSuffix(mapping.APIPath, "/")
	
	// Add filters as query parameters (simplified)
	if len(filters) > 0 {
		// This would need more sophisticated query building
		url += "?"
		for key, value := range filters {
			url += fmt.Sprintf("%s=%v&", key, value)
		}
		url = strings.TrimSuffix(url, "&")
	}
	
	// Execute raw API call
	return no.provider.RawAPI(ctx, "GET", url, nil)
}

// executeOperation executes a configured operation mapping
func (no *NormalizedOperations) executeOperation(ctx context.Context, operation OperationMapping, params map[string]interface{}) (*ProviderResult, error) {
	// Build URL from template
	url := operation.URLTemplate
	for key, value := range params {
		placeholder := "{" + key + "}"
		url = strings.ReplaceAll(url, placeholder, fmt.Sprintf("%v", value))
	}
	
	// Build request body
	var body interface{}
	if operation.HTTPMethod != "GET" && operation.HTTPMethod != "DELETE" {
		if data, exists := params["data"]; exists {
			body = data
		}
	}
	
	// Execute raw API call
	return no.provider.RawAPI(ctx, operation.HTTPMethod, url, body)
}

// Helper functions

func (no *NormalizedOperations) validateRequiredFields(resourceType string, data map[string]interface{}) error {
	mapping, exists := no.resourceMap[resourceType]
	if !exists {
		return fmt.Errorf("resource type %s not found", resourceType)
	}
	
	for _, field := range mapping.RequiredFields {
		if _, exists := data[field]; !exists {
			return fmt.Errorf("required field %s is missing", field)
		}
	}
	
	return nil
}

func (no *NormalizedOperations) filterReadOnlyFields(resourceType string, data map[string]interface{}) map[string]interface{} {
	mapping, exists := no.resourceMap[resourceType]
	if !exists {
		return data
	}
	
	filtered := make(map[string]interface{})
	for key, value := range data {
		if !contains(mapping.ReadOnlyFields, key) {
			filtered[key] = value
		}
	}
	
	return filtered
}

func (no *NormalizedOperations) transformToProviderFormat(resourceType string, data map[string]interface{}) (map[string]interface{}, error) {
	fieldMappings, exists := no.fieldMap[resourceType]
	if !exists {
		// No field mapping, return data as-is
		return data, nil
	}
	
	transformed := make(map[string]interface{})
	for normalizedField, value := range data {
		if providerField, exists := fieldMappings[normalizedField]; exists {
			transformed[providerField] = value
		} else {
			// Field has no mapping, keep original name
			transformed[normalizedField] = value
		}
	}
	
	return transformed, nil
}

func (no *NormalizedOperations) transformFilters(resourceType string, filters map[string]interface{}) (map[string]interface{}, error) {
	// Transform filter field names using field mappings
	return no.transformToProviderFormat(resourceType, filters)
}

// Default mappings for common resource types

func getDefaultResourceMappings() map[string]ResourceMapping {
	return map[string]ResourceMapping{
		"users": {
			NormalizedType:      "users",
			ProviderType:        "user",
			APIPath:             "/users",
			IDField:             "id",
			NameField:           "name",
			SupportedOperations: []string{"create", "read", "update", "delete", "list"},
			RequiredFields:      []string{"name", "email"},
			ReadOnlyFields:      []string{"id", "created_at", "updated_at"},
		},
		"groups": {
			NormalizedType:      "groups",
			ProviderType:        "group",
			APIPath:             "/groups",
			IDField:             "id",
			NameField:           "name",
			SupportedOperations: []string{"create", "read", "update", "delete", "list"},
			RequiredFields:      []string{"name"},
			ReadOnlyFields:      []string{"id", "created_at", "updated_at"},
		},
		"organizations": {
			NormalizedType:      "organizations",
			ProviderType:        "organization",
			APIPath:             "/organizations",
			IDField:             "id",
			NameField:           "name",
			SupportedOperations: []string{"read", "update", "list"},
			RequiredFields:      []string{"name"},
			ReadOnlyFields:      []string{"id", "created_at", "updated_at"},
		},
		"projects": {
			NormalizedType:      "projects",
			ProviderType:        "project",
			APIPath:             "/projects",
			IDField:             "id",
			NameField:           "name",
			SupportedOperations: []string{"create", "read", "update", "delete", "list"},
			RequiredFields:      []string{"name"},
			ReadOnlyFields:      []string{"id", "created_at", "updated_at"},
		},
	}
}

func getDefaultFieldMappings() map[string]map[string]string {
	return map[string]map[string]string{
		"users": {
			"name":        "displayName",
			"email":       "mail",
			"username":    "userPrincipalName",
			"active":      "accountEnabled",
			"first_name":  "givenName",
			"last_name":   "surname",
			"phone":       "mobilePhone",
			"department":  "department",
			"title":       "jobTitle",
		},
		"groups": {
			"name":         "displayName",
			"description":  "description",
			"type":         "groupTypes",
			"email":        "mail",
			"visibility":   "visibility",
		},
	}
}

func getDefaultOperationMappings() map[string]OperationMapping {
	return map[string]OperationMapping{
		"users:create": {
			NormalizedOperation: "create",
			HTTPMethod:          "POST",
			URLTemplate:         "/users",
			RequiredParams:      []string{"data"},
		},
		"users:read": {
			NormalizedOperation: "read",
			HTTPMethod:          "GET",
			URLTemplate:         "/users/{id}",
			RequiredParams:      []string{"id"},
		},
		"users:update": {
			NormalizedOperation: "update",
			HTTPMethod:          "PATCH",
			URLTemplate:         "/users/{id}",
			RequiredParams:      []string{"id", "data"},
		},
		"users:delete": {
			NormalizedOperation: "delete",
			HTTPMethod:          "DELETE",
			URLTemplate:         "/users/{id}",
			RequiredParams:      []string{"id"},
		},
		"users:list": {
			NormalizedOperation: "list",
			HTTPMethod:          "GET",
			URLTemplate:         "/users",
			OptionalParams:      []string{"filter", "limit", "offset"},
		},
	}
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetResourceTypes returns all supported normalized resource types
func (no *NormalizedOperations) GetResourceTypes() []string {
	types := make([]string, 0, len(no.resourceMap))
	for resourceType := range no.resourceMap {
		types = append(types, resourceType)
	}
	return types
}

// GetResourceMapping returns the mapping for a specific resource type
func (no *NormalizedOperations) GetResourceMapping(resourceType string) (ResourceMapping, error) {
	mapping, exists := no.resourceMap[resourceType]
	if !exists {
		return ResourceMapping{}, fmt.Errorf("resource type %s not found", resourceType)
	}
	return mapping, nil
}

// AddResourceMapping adds a custom resource mapping
func (no *NormalizedOperations) AddResourceMapping(resourceType string, mapping ResourceMapping) {
	no.resourceMap[resourceType] = mapping
}

// AddFieldMapping adds a custom field mapping for a resource type
func (no *NormalizedOperations) AddFieldMapping(resourceType string, fieldMappings map[string]string) {
	if no.fieldMap[resourceType] == nil {
		no.fieldMap[resourceType] = make(map[string]string)
	}
	for normalizedField, providerField := range fieldMappings {
		no.fieldMap[resourceType][normalizedField] = providerField
	}
}

// AddOperationMapping adds a custom operation mapping
func (no *NormalizedOperations) AddOperationMapping(key string, mapping OperationMapping) {
	no.operationMap[key] = mapping
}

// ValidateData validates data against resource schema
func (no *NormalizedOperations) ValidateData(resourceType string, data map[string]interface{}) error {
	mapping, exists := no.resourceMap[resourceType]
	if !exists {
		return fmt.Errorf("resource type %s not supported", resourceType)
	}
	
	// Check required fields
	for _, field := range mapping.RequiredFields {
		if _, exists := data[field]; !exists {
			return fmt.Errorf("required field %s is missing", field)
		}
	}
	
	// Check for read-only fields in updates
	for _, field := range mapping.ReadOnlyFields {
		if _, exists := data[field]; exists {
			return fmt.Errorf("field %s is read-only and cannot be modified", field)
		}
	}
	
	return nil
}