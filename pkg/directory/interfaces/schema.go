// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces - Directory Schema Normalization Layer
//
// This file implements the DefaultDirectorySchemaMapper: construction, default
// schema initialization, provider registration, field mapping (to/from normalized),
// and object conversion (User/Group) between provider and normalized formats.
//
// File organization:
//   - schema.go             — Mapper construction, field mapping, object conversion
//   - schema_types.go       — Type definitions, constants, and interface declarations
//   - schema_validation.go  — Object/field validation and conflict resolution
//   - schema_transformers.go — Built-in DataTransformer implementations
//   - schema_validators.go   — Built-in FieldValidator implementations

package interfaces

import (
	"fmt"
	"time"
)

// NewDirectorySchemaMapper creates a new schema mapper
func NewDirectorySchemaMapper() *DefaultDirectorySchemaMapper {
	mapper := &DefaultDirectorySchemaMapper{
		providerSchemas: make(map[string]*ProviderSchema),
		fieldMappings:   make(map[string]*FieldMappingSet),
		transformers:    make(map[string]DataTransformer),
		validators:      make(map[string]FieldValidator),
	}

	// Initialize with default normalized schema
	mapper.normalizedSchema = createDefaultNormalizedSchema()

	// Register built-in transformers
	mapper.registerBuiltinTransformers()

	// Register built-in validators
	mapper.registerBuiltinValidators()

	return mapper
}

// createDefaultNormalizedSchema creates the default normalized schema
func createDefaultNormalizedSchema() *NormalizedSchema {
	return &NormalizedSchema{
		UserSchema: &NormalizedObjectSchema{
			ObjectType: DirectoryObjectTypeUser,
			CoreFields: map[string]*NormalizedField{
				"id": {
					Name:        "id",
					Type:        FieldTypeString,
					Description: "Unique identifier",
					Required:    true,
					ReadOnly:    true,
					Searchable:  true,
				},
				"user_principal_name": {
					Name:        "user_principal_name",
					Type:        FieldTypeString,
					Description: "User principal name (UPN)",
					Required:    true,
					Searchable:  true,
					Format:      "email",
					Pattern:     `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
				},
				"display_name": {
					Name:        "display_name",
					Type:        FieldTypeString,
					Description: "Display name",
					Required:    true,
					Searchable:  true,
					Sortable:    true,
					MaxLength:   256,
				},
				"account_enabled": {
					Name:         "account_enabled",
					Type:         FieldTypeBoolean,
					Description:  "Is account enabled",
					Required:     true,
					DefaultValue: true,
				},
			},
			OptionalFields: map[string]*NormalizedField{
				"sam_account_name": {
					Name:        "sam_account_name",
					Type:        FieldTypeString,
					Description: "SAM account name (for AD compatibility)",
					Searchable:  true,
					MaxLength:   20,
				},
				"email_address": {
					Name:        "email_address",
					Type:        FieldTypeString,
					Description: "Primary email address",
					Searchable:  true,
					Format:      "email",
				},
				"phone_number": {
					Name:        "phone_number",
					Type:        FieldTypeString,
					Description: "Primary phone number",
					Format:      "phone",
				},
				"mobile_phone": {
					Name:        "mobile_phone",
					Type:        FieldTypeString,
					Description: "Mobile phone number",
					Format:      "phone",
				},
				"department": {
					Name:        "department",
					Type:        FieldTypeString,
					Description: "Department",
					Searchable:  true,
					Sortable:    true,
				},
				"job_title": {
					Name:        "job_title",
					Type:        FieldTypeString,
					Description: "Job title",
					Searchable:  true,
					Sortable:    true,
				},
				"manager": {
					Name:        "manager",
					Type:        FieldTypeString,
					Description: "Manager's ID",
					Searchable:  true,
				},
				"office_location": {
					Name:        "office_location",
					Type:        FieldTypeString,
					Description: "Office location",
					Searchable:  true,
				},
				"company": {
					Name:        "company",
					Type:        FieldTypeString,
					Description: "Company name",
					Searchable:  true,
				},
				"created": {
					Name:        "created",
					Type:        FieldTypeDateTime,
					Description: "Creation timestamp",
					ReadOnly:    true,
					Sortable:    true,
				},
				"modified": {
					Name:        "modified",
					Type:        FieldTypeDateTime,
					Description: "Last modified timestamp",
					ReadOnly:    true,
					Sortable:    true,
				},
			},
			Relationships: map[string]*Relationship{
				"groups": {
					Name:        "groups",
					Type:        RelationshipTypeMemberOf,
					TargetType:  DirectoryObjectTypeGroup,
					Cardinality: CardinalityManyToMany,
					Description: "Group memberships",
				},
				"manager_relationship": {
					Name:        "manager_relationship",
					Type:        RelationshipTypeReportsTo,
					TargetType:  DirectoryObjectTypeUser,
					Cardinality: CardinalityManyToOne,
					Description: "Manager relationship",
				},
			},
		},
		GroupSchema: &NormalizedObjectSchema{
			ObjectType: DirectoryObjectTypeGroup,
			CoreFields: map[string]*NormalizedField{
				"id": {
					Name:        "id",
					Type:        FieldTypeString,
					Description: "Unique identifier",
					Required:    true,
					ReadOnly:    true,
					Searchable:  true,
				},
				"name": {
					Name:        "name",
					Type:        FieldTypeString,
					Description: "Group name",
					Required:    true,
					Searchable:  true,
					Sortable:    true,
				},
				"display_name": {
					Name:        "display_name",
					Type:        FieldTypeString,
					Description: "Display name",
					Required:    true,
					Searchable:  true,
					Sortable:    true,
				},
				"group_type": {
					Name:         "group_type",
					Type:         FieldTypeString,
					Description:  "Group type",
					Required:     true,
					EnumValues:   []interface{}{"security", "distribution"},
					DefaultValue: "security",
				},
			},
			OptionalFields: map[string]*NormalizedField{
				"description": {
					Name:        "description",
					Type:        FieldTypeString,
					Description: "Group description",
					Searchable:  true,
				},
				"group_scope": {
					Name:        "group_scope",
					Type:        FieldTypeString,
					Description: "Group scope (AD concept)",
					EnumValues:  []interface{}{"domain_local", "global", "universal"},
				},
			},
			Relationships: map[string]*Relationship{
				"members": {
					Name:        "members",
					Type:        RelationshipTypeContains,
					TargetType:  DirectoryObjectTypeUser,
					Cardinality: CardinalityOneToMany,
					Description: "Group members",
				},
			},
		},
	}
}

// RegisterProviderSchema registers a provider schema
func (m *DefaultDirectorySchemaMapper) RegisterProviderSchema(providerName string, schema *ProviderSchema) error {
	if providerName == "" {
		return fmt.Errorf("provider name cannot be empty")
	}
	if schema == nil {
		return fmt.Errorf("schema cannot be nil")
	}

	m.providerSchemas[providerName] = schema
	m.fieldMappings[providerName] = schema.Mappings

	return nil
}

// GetNormalizedSchema returns the normalized schema for a provider
func (m *DefaultDirectorySchemaMapper) GetNormalizedSchema(providerName string) (*NormalizedSchema, error) {
	if _, exists := m.providerSchemas[providerName]; !exists {
		return nil, fmt.Errorf("provider schema not found: %s", providerName)
	}

	// Return the universal normalized schema
	return m.normalizedSchema, nil
}

// MapToNormalized maps provider data to normalized format
func (m *DefaultDirectorySchemaMapper) MapToNormalized(providerName string, objectType DirectoryObjectType, providerData map[string]interface{}) (map[string]interface{}, error) {
	mappings, exists := m.fieldMappings[providerName]
	if !exists {
		return nil, fmt.Errorf("no field mappings found for provider: %s", providerName)
	}

	var fieldMappings map[string]*FieldMapping
	switch objectType {
	case DirectoryObjectTypeUser:
		fieldMappings = mappings.UserMappings
	case DirectoryObjectTypeGroup:
		fieldMappings = mappings.GroupMappings
	case DirectoryObjectTypeOU:
		fieldMappings = mappings.OUMappings
	default:
		return nil, fmt.Errorf("unsupported object type: %s", objectType)
	}

	normalized := make(map[string]interface{})

	for providerField, value := range providerData {
		mapping, exists := fieldMappings[providerField]
		if !exists {
			// No mapping found, store in provider_attributes
			if normalized["provider_attributes"] == nil {
				normalized["provider_attributes"] = make(map[string]interface{})
			}
			normalized["provider_attributes"].(map[string]interface{})[providerField] = value
			continue
		}

		// Apply transformation if specified
		transformedValue := value
		if mapping.Transform != "" {
			transformer, exists := m.transformers[mapping.Transform]
			if !exists {
				return nil, fmt.Errorf("transformer not found: %s", mapping.Transform)
			}

			var err error
			transformedValue, err = transformer.Transform(value)
			if err != nil {
				return nil, fmt.Errorf("transformation failed for field %s: %w", providerField, err)
			}
		}

		normalized[mapping.NormalizedField] = transformedValue
	}

	// Set source provider
	normalized["source"] = providerName

	return normalized, nil
}

// MapFromNormalized maps normalized data to provider format
func (m *DefaultDirectorySchemaMapper) MapFromNormalized(providerName string, objectType DirectoryObjectType, normalizedData map[string]interface{}) (map[string]interface{}, error) {
	mappings, exists := m.fieldMappings[providerName]
	if !exists {
		return nil, fmt.Errorf("no field mappings found for provider: %s", providerName)
	}

	var fieldMappings map[string]*FieldMapping
	switch objectType {
	case DirectoryObjectTypeUser:
		fieldMappings = mappings.UserMappings
	case DirectoryObjectTypeGroup:
		fieldMappings = mappings.GroupMappings
	case DirectoryObjectTypeOU:
		fieldMappings = mappings.OUMappings
	default:
		return nil, fmt.Errorf("unsupported object type: %s", objectType)
	}

	providerData := make(map[string]interface{})

	for normalizedField, value := range normalizedData {
		// Skip metadata fields
		if normalizedField == "source" || normalizedField == "provider_attributes" {
			continue
		}

		// Find reverse mapping
		var mapping *FieldMapping
		var providerField string
		for pField, m := range fieldMappings {
			if m.NormalizedField == normalizedField && m.Bidirectional {
				mapping = m
				providerField = pField
				break
			}
		}

		if mapping == nil {
			continue // No reverse mapping available
		}

		// Apply reverse transformation if specified
		transformedValue := value
		if mapping.Transform != "" {
			transformer, exists := m.transformers[mapping.Transform]
			if !exists {
				return nil, fmt.Errorf("transformer not found: %s", mapping.Transform)
			}

			var err error
			transformedValue, err = transformer.Reverse(value)
			if err != nil {
				return nil, fmt.Errorf("reverse transformation failed for field %s: %w", normalizedField, err)
			}
		}

		providerData[providerField] = transformedValue
	}

	// Include provider-specific attributes
	if providerAttrs, exists := normalizedData["provider_attributes"]; exists {
		if attrs, ok := providerAttrs.(map[string]interface{}); ok {
			for key, value := range attrs {
				providerData[key] = value
			}
		}
	}

	return providerData, nil
}

// ConvertUserToNormalized converts provider user data to normalized DirectoryUser
func (m *DefaultDirectorySchemaMapper) ConvertUserToNormalized(providerName string, providerUser map[string]interface{}) (*DirectoryUser, error) {
	normalized, err := m.MapToNormalized(providerName, DirectoryObjectTypeUser, providerUser)
	if err != nil {
		return nil, err
	}

	user := &DirectoryUser{}

	// Map core fields
	if id, ok := normalized["id"].(string); ok {
		user.ID = id
	}
	if upn, ok := normalized["user_principal_name"].(string); ok {
		user.UserPrincipalName = upn
	}
	if sam, ok := normalized["sam_account_name"].(string); ok {
		user.SAMAccountName = sam
	}
	if displayName, ok := normalized["display_name"].(string); ok {
		user.DisplayName = displayName
	}
	if enabled, ok := normalized["account_enabled"].(bool); ok {
		user.AccountEnabled = enabled
	}

	// Map optional fields
	if email, ok := normalized["email_address"].(string); ok {
		user.EmailAddress = email
	}
	if phone, ok := normalized["phone_number"].(string); ok {
		user.PhoneNumber = phone
	}
	if mobile, ok := normalized["mobile_phone"].(string); ok {
		user.MobilePhone = mobile
	}
	if dept, ok := normalized["department"].(string); ok {
		user.Department = dept
	}
	if title, ok := normalized["job_title"].(string); ok {
		user.JobTitle = title
	}
	if manager, ok := normalized["manager"].(string); ok {
		user.Manager = manager
	}
	if office, ok := normalized["office_location"].(string); ok {
		user.OfficeLocation = office
	}
	if company, ok := normalized["company"].(string); ok {
		user.Company = company
	}

	// Map timestamps
	if created, ok := normalized["created"].(time.Time); ok {
		user.Created = &created
	}
	if modified, ok := normalized["modified"].(time.Time); ok {
		user.Modified = &modified
	}

	// Map provider-specific attributes
	if attrs, ok := normalized["provider_attributes"].(map[string]interface{}); ok {
		user.ProviderAttributes = attrs
	}

	// Set source
	if source, ok := normalized["source"].(string); ok {
		user.Source = source
	}

	return user, nil
}

// ConvertUserFromNormalized converts DirectoryUser to provider format
func (m *DefaultDirectorySchemaMapper) ConvertUserFromNormalized(providerName string, normalizedUser *DirectoryUser) (map[string]interface{}, error) {
	normalized := map[string]interface{}{
		"id":                  normalizedUser.ID,
		"user_principal_name": normalizedUser.UserPrincipalName,
		"display_name":        normalizedUser.DisplayName,
		"account_enabled":     normalizedUser.AccountEnabled,
	}

	// Add optional fields if present
	if normalizedUser.SAMAccountName != "" {
		normalized["sam_account_name"] = normalizedUser.SAMAccountName
	}
	if normalizedUser.EmailAddress != "" {
		normalized["email_address"] = normalizedUser.EmailAddress
	}
	if normalizedUser.PhoneNumber != "" {
		normalized["phone_number"] = normalizedUser.PhoneNumber
	}
	if normalizedUser.MobilePhone != "" {
		normalized["mobile_phone"] = normalizedUser.MobilePhone
	}
	if normalizedUser.Department != "" {
		normalized["department"] = normalizedUser.Department
	}
	if normalizedUser.JobTitle != "" {
		normalized["job_title"] = normalizedUser.JobTitle
	}
	if normalizedUser.Manager != "" {
		normalized["manager"] = normalizedUser.Manager
	}
	if normalizedUser.OfficeLocation != "" {
		normalized["office_location"] = normalizedUser.OfficeLocation
	}
	if normalizedUser.Company != "" {
		normalized["company"] = normalizedUser.Company
	}

	// Add timestamps
	if normalizedUser.Created != nil {
		normalized["created"] = *normalizedUser.Created
	}
	if normalizedUser.Modified != nil {
		normalized["modified"] = *normalizedUser.Modified
	}

	// Add provider-specific attributes
	if normalizedUser.ProviderAttributes != nil {
		normalized["provider_attributes"] = normalizedUser.ProviderAttributes
	}

	return m.MapFromNormalized(providerName, DirectoryObjectTypeUser, normalized)
}

// ConvertGroupToNormalized converts provider group data to normalized DirectoryGroup
func (m *DefaultDirectorySchemaMapper) ConvertGroupToNormalized(providerName string, providerGroup map[string]interface{}) (*DirectoryGroup, error) {
	normalized, err := m.MapToNormalized(providerName, DirectoryObjectTypeGroup, providerGroup)
	if err != nil {
		return nil, err
	}

	group := &DirectoryGroup{}

	// Map core fields
	if id, ok := normalized["id"].(string); ok {
		group.ID = id
	}
	if name, ok := normalized["name"].(string); ok {
		group.Name = name
	}
	if displayName, ok := normalized["display_name"].(string); ok {
		group.DisplayName = displayName
	}
	if groupType, ok := normalized["group_type"].(string); ok {
		group.GroupType = GroupType(groupType)
	}

	// Map optional fields
	if desc, ok := normalized["description"].(string); ok {
		group.Description = desc
	}
	if scope, ok := normalized["group_scope"].(string); ok {
		group.GroupScope = GroupScope(scope)
	}

	// Map timestamps
	if created, ok := normalized["created"].(time.Time); ok {
		group.Created = &created
	}
	if modified, ok := normalized["modified"].(time.Time); ok {
		group.Modified = &modified
	}

	// Map provider-specific attributes
	if attrs, ok := normalized["provider_attributes"].(map[string]interface{}); ok {
		group.ProviderAttributes = attrs
	}

	// Set source
	if source, ok := normalized["source"].(string); ok {
		group.Source = source
	}

	return group, nil
}

// ConvertGroupFromNormalized converts DirectoryGroup to provider format
func (m *DefaultDirectorySchemaMapper) ConvertGroupFromNormalized(providerName string, normalizedGroup *DirectoryGroup) (map[string]interface{}, error) {
	normalized := map[string]interface{}{
		"id":           normalizedGroup.ID,
		"name":         normalizedGroup.Name,
		"display_name": normalizedGroup.DisplayName,
		"group_type":   string(normalizedGroup.GroupType),
	}

	// Add optional fields if present
	if normalizedGroup.Description != "" {
		normalized["description"] = normalizedGroup.Description
	}
	if normalizedGroup.GroupScope != "" {
		normalized["group_scope"] = string(normalizedGroup.GroupScope)
	}

	// Add timestamps
	if normalizedGroup.Created != nil {
		normalized["created"] = *normalizedGroup.Created
	}
	if normalizedGroup.Modified != nil {
		normalized["modified"] = *normalizedGroup.Modified
	}

	// Add provider-specific attributes
	if normalizedGroup.ProviderAttributes != nil {
		normalized["provider_attributes"] = normalizedGroup.ProviderAttributes
	}

	return m.MapFromNormalized(providerName, DirectoryObjectTypeGroup, normalized)
}
