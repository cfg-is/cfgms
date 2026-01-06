// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package examples provides example implementations of the API Module Framework
// showing how to create providers and use them with both normalized operations
// and raw API access.
package examples

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/cfgis/cfgms/features/saas"
)

// MicrosoftProvider implements the Provider interface for Microsoft Graph API
type MicrosoftProvider struct {
	*saas.BaseProvider
	baseURL string
}

// NewMicrosoftProvider creates a new Microsoft Graph provider
func NewMicrosoftProvider() saas.Provider {
	info := saas.ProviderInfo{
		Name:               "microsoft",
		DisplayName:        "Microsoft Graph",
		Version:            "1.0.0",
		Description:        "Microsoft Graph API provider for M365 services",
		SupportedAuthTypes: []string{"oauth2"},
		BaseURL:            "https://graph.microsoft.com/v1.0",
		DocumentationURL:   "https://docs.microsoft.com/en-us/graph/",
		Capabilities: saas.ProviderCapabilities{
			NormalizedOperations: []string{"create", "read", "update", "delete", "list"},
			RawAPISupport:        true,
			SchemaSupport:        false,
			PaginationSupport:    true,
			WebhookSupport:       true,
			BatchOperations:      true,
		},
	}

	httpClient := &http.Client{}

	return &MicrosoftProvider{
		BaseProvider: saas.NewBaseProvider(info, httpClient),
		baseURL:      "https://graph.microsoft.com/v1.0",
	}
}

// Authenticate performs OAuth2 authentication for Microsoft Graph
func (p *MicrosoftProvider) Authenticate(ctx context.Context, config saas.ProviderConfig, credStore saas.CredentialStore) error {
	// This would implement OAuth2 client credentials flow
	// For now, return success to demonstrate the pattern
	return nil
}

// IsAuthenticated checks if valid credentials exist
func (p *MicrosoftProvider) IsAuthenticated(ctx context.Context, credStore saas.CredentialStore) bool {
	tokenSet, err := credStore.GetTokenSet(p.GetInfo().Name)
	if err != nil {
		return false
	}
	return tokenSet != nil && tokenSet.IsValid(5*60) // 5 minute threshold
}

// RefreshAuth refreshes the access token
func (p *MicrosoftProvider) RefreshAuth(ctx context.Context, credStore saas.CredentialStore) error {
	// Implementation would refresh OAuth2 token
	return nil
}

// Normalized Operations

// Create creates a new resource
func (p *MicrosoftProvider) Create(ctx context.Context, resourceType string, data map[string]interface{}) (*saas.ProviderResult, error) {
	switch resourceType {
	case "users":
		return p.createUser(ctx, data)
	case "groups":
		return p.createGroup(ctx, data)
	default:
		return nil, fmt.Errorf("resource type %s not supported", resourceType)
	}
}

// Read retrieves a resource by ID
func (p *MicrosoftProvider) Read(ctx context.Context, resourceType string, resourceID string) (*saas.ProviderResult, error) {
	path := fmt.Sprintf("/%s/%s", resourceType, resourceID)
	return p.RawAPI(ctx, "GET", path, nil)
}

// Update modifies an existing resource
func (p *MicrosoftProvider) Update(ctx context.Context, resourceType string, resourceID string, data map[string]interface{}) (*saas.ProviderResult, error) {
	path := fmt.Sprintf("/%s/%s", resourceType, resourceID)
	return p.RawAPI(ctx, "PATCH", path, data)
}

// Delete removes a resource
func (p *MicrosoftProvider) Delete(ctx context.Context, resourceType string, resourceID string) (*saas.ProviderResult, error) {
	path := fmt.Sprintf("/%s/%s", resourceType, resourceID)
	return p.RawAPI(ctx, "DELETE", path, nil)
}

// List retrieves multiple resources
func (p *MicrosoftProvider) List(ctx context.Context, resourceType string, filters map[string]interface{}) (*saas.ProviderResult, error) {
	path := "/" + resourceType

	// Add OData query parameters
	queryParams := make([]string, 0)
	if filter, exists := filters["filter"]; exists {
		queryParams = append(queryParams, fmt.Sprintf("$filter=%v", filter))
	}
	if limit, exists := filters["limit"]; exists {
		queryParams = append(queryParams, fmt.Sprintf("$top=%v", limit))
	}
	if select_, exists := filters["select"]; exists {
		queryParams = append(queryParams, fmt.Sprintf("$select=%v", select_))
	}

	if len(queryParams) > 0 {
		path += "?" + strings.Join(queryParams, "&")
	}

	return p.RawAPI(ctx, "GET", path, nil)
}

// RawAPI executes a raw API call
func (p *MicrosoftProvider) RawAPI(ctx context.Context, method, path string, body interface{}) (*saas.ProviderResult, error) {
	// Build full URL (for actual implementation)
	_ = p.baseURL + path

	// This would make the actual HTTP request
	// For demonstration, return a mock successful result
	return &saas.ProviderResult{
		Success:    true,
		Data:       map[string]interface{}{"id": "mock-id", "displayName": "Mock Resource"},
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Metadata:   map[string]interface{}{"provider": "microsoft", "method": method, "path": path},
	}, nil
}

// GetAPISchema returns the OpenAPI schema (not implemented for this example)
func (p *MicrosoftProvider) GetAPISchema(ctx context.Context) (*saas.APISchema, error) {
	return nil, fmt.Errorf("API schema not available")
}

// GetSupportedResources returns supported resource types
func (p *MicrosoftProvider) GetSupportedResources() []saas.ResourceType {
	return []saas.ResourceType{
		{
			Name:                "users",
			DisplayName:         "Users",
			Description:         "Azure AD users",
			SupportedOperations: []string{"create", "read", "update", "delete", "list"},
			RequiredFields:      []string{"displayName", "userPrincipalName"},
			OptionalFields:      []string{"givenName", "surname", "jobTitle", "department"},
			ReadOnlyFields:      []string{"id", "createdDateTime"},
		},
		{
			Name:                "groups",
			DisplayName:         "Groups",
			Description:         "Azure AD groups",
			SupportedOperations: []string{"create", "read", "update", "delete", "list"},
			RequiredFields:      []string{"displayName"},
			OptionalFields:      []string{"description", "mailEnabled", "securityEnabled"},
			ReadOnlyFields:      []string{"id", "createdDateTime"},
		},
	}
}

// GetResourceSchema returns schema for a specific resource
func (p *MicrosoftProvider) GetResourceSchema(resourceType string) (*saas.ResourceSchema, error) {
	switch resourceType {
	case "users":
		return &saas.ResourceSchema{
			Type: "users",
			Properties: map[string]saas.PropertySchema{
				"id": {
					Type:        "string",
					Description: "Unique identifier",
					ReadOnly:    true,
				},
				"displayName": {
					Type:        "string",
					Description: "Display name",
				},
				"userPrincipalName": {
					Type:        "string",
					Format:      "email",
					Description: "User principal name (email)",
				},
				"givenName": {
					Type:        "string",
					Description: "First name",
				},
				"surname": {
					Type:        "string",
					Description: "Last name",
				},
			},
			Required: []string{"displayName", "userPrincipalName"},
		}, nil
	default:
		return nil, fmt.Errorf("schema not available for resource type: %s", resourceType)
	}
}

// ValidateResource validates resource data
func (p *MicrosoftProvider) ValidateResource(resourceType string, data map[string]interface{}) error {
	schema, err := p.GetResourceSchema(resourceType)
	if err != nil {
		return err
	}

	// Check required fields
	for _, field := range schema.Required {
		if _, exists := data[field]; !exists {
			return fmt.Errorf("required field %s is missing", field)
		}
	}

	return nil
}

// ValidateConfig validates provider configuration
func (p *MicrosoftProvider) ValidateConfig(config saas.ProviderConfig) error {
	if config.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	if config.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	return nil
}

// Helper methods for specific resource types

func (p *MicrosoftProvider) createUser(ctx context.Context, data map[string]interface{}) (*saas.ProviderResult, error) {
	// Transform normalized user data to Microsoft Graph format
	graphData := make(map[string]interface{})

	if displayName, exists := data["name"]; exists {
		graphData["displayName"] = displayName
	}
	if email, exists := data["email"]; exists {
		graphData["userPrincipalName"] = email
		graphData["mail"] = email
	}
	if firstName, exists := data["first_name"]; exists {
		graphData["givenName"] = firstName
	}
	if lastName, exists := data["last_name"]; exists {
		graphData["surname"] = lastName
	}
	if active, exists := data["active"]; exists {
		graphData["accountEnabled"] = active
	}

	// Add required password profile for new users
	graphData["passwordProfile"] = map[string]interface{}{
		"forceChangePasswordNextSignIn": true,
		"password":                      "TempPassword123!",
	}

	return p.RawAPI(ctx, "POST", "/users", graphData)
}

func (p *MicrosoftProvider) createGroup(ctx context.Context, data map[string]interface{}) (*saas.ProviderResult, error) {
	// Transform normalized group data to Microsoft Graph format
	graphData := make(map[string]interface{})

	if name, exists := data["name"]; exists {
		graphData["displayName"] = name
	}
	if description, exists := data["description"]; exists {
		graphData["description"] = description
	}

	// Set default group properties
	graphData["mailEnabled"] = false
	graphData["securityEnabled"] = true

	return p.RawAPI(ctx, "POST", "/groups", graphData)
}

// ExampleUsage demonstrates how to use the Microsoft provider
func ExampleUsage() {
	// Create provider registry
	registry := saas.NewProviderRegistry()

	// Register Microsoft provider
	microsoftProvider := NewMicrosoftProvider()
	if err := registry.RegisterProvider(microsoftProvider); err != nil {
		log.Printf("Failed to register Microsoft provider: %v", err)
		return
	}

	// Create universal authenticator (would need actual credential store)
	// authenticator := saas.NewUniversalAuthenticator(credStore, httpClient)

	// Example: Create a user using normalized operations
	ctx := context.Background()
	provider, _ := registry.GetProvider("microsoft")

	userData := map[string]interface{}{
		"name":       "John Doe",
		"email":      "john.doe@company.com",
		"first_name": "John",
		"last_name":  "Doe",
		"active":     true,
	}

	result, err := provider.Create(ctx, "users", userData)
	if err != nil {
		fmt.Printf("Error creating user: %v\n", err)
		return
	}

	fmt.Printf("User created successfully: %+v\n", result.Data)

	// Example: Raw API call for advanced operations
	customData := map[string]interface{}{
		"@odata.type":       "#microsoft.graph.user",
		"displayName":       "Jane Smith",
		"userPrincipalName": "jane.smith@company.com",
		"accountEnabled":    true,
		"passwordProfile": map[string]interface{}{
			"forceChangePasswordNextSignIn": true,
			"password":                      "TempPassword456!",
		},
	}

	rawResult, err := provider.RawAPI(ctx, "POST", "/users", customData)
	if err != nil {
		fmt.Printf("Error with raw API call: %v\n", err)
		return
	}

	fmt.Printf("Raw API call successful: %+v\n", rawResult.Data)
}

// WorkflowExample shows how the provider works with workflow nodes
func WorkflowExample() {
	// This would be used in a workflow configuration like:
	/*
		workflow:
		  steps:
		    - type: saas_action
		      provider: microsoft
		      operation: create
		      resource_type: users
		      data:
		        name: "${user.name}"
		        email: "${user.email}"
		        active: true

		    - type: api
		      provider: microsoft
		      method: POST
		      path: "/users/${previous.id}/memberOf/$ref"
		      body:
		        "@odata.id": "https://graph.microsoft.com/v1.0/groups/${group.id}"
	*/

	fmt.Println("Workflow example configuration shown in comments above")
}
