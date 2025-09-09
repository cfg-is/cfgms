// Package interfaces - Directory Schema Normalization Layer
//
// This file implements a schema normalization layer for cross-provider compatibility.
// It provides field mapping, data transformation, and validation to enable unified
// directory operations across Active Directory, Entra ID, and other providers.

package interfaces

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DirectorySchemaMapper provides schema mapping and normalization capabilities
type DirectorySchemaMapper interface {
	// Schema Operations
	GetNormalizedSchema(providerName string) (*NormalizedSchema, error)
	RegisterProviderSchema(providerName string, schema *ProviderSchema) error
	
	// Field Mapping
	MapToNormalized(providerName string, objectType DirectoryObjectType, providerData map[string]interface{}) (map[string]interface{}, error)
	MapFromNormalized(providerName string, objectType DirectoryObjectType, normalizedData map[string]interface{}) (map[string]interface{}, error)
	
	// Object Conversion
	ConvertUserToNormalized(providerName string, providerUser map[string]interface{}) (*DirectoryUser, error)
	ConvertUserFromNormalized(providerName string, normalizedUser *DirectoryUser) (map[string]interface{}, error)
	ConvertGroupToNormalized(providerName string, providerGroup map[string]interface{}) (*DirectoryGroup, error)
	ConvertGroupFromNormalized(providerName string, normalizedGroup *DirectoryGroup) (map[string]interface{}, error)
	
	// Validation
	ValidateNormalizedObject(objectType DirectoryObjectType, data map[string]interface{}) error
	ValidateProviderObject(providerName string, objectType DirectoryObjectType, data map[string]interface{}) error
	
	// Conflict Resolution
	ResolveConflicts(conflicts []FieldConflict) (map[string]interface{}, error)
}

// DefaultDirectorySchemaMapper is the default implementation
type DefaultDirectorySchemaMapper struct {
	providerSchemas   map[string]*ProviderSchema
	normalizedSchema  *NormalizedSchema
	fieldMappings     map[string]*FieldMappingSet
	transformers      map[string]DataTransformer
	validators        map[string]FieldValidator
}

// NormalizedSchema defines the universal schema for directory objects
type NormalizedSchema struct {
	UserSchema  *NormalizedObjectSchema `json:"user_schema"`
	GroupSchema *NormalizedObjectSchema `json:"group_schema"`
	OUSchema    *NormalizedObjectSchema `json:"ou_schema"`
}

// NormalizedObjectSchema defines the schema for a normalized object type
type NormalizedObjectSchema struct {
	ObjectType      DirectoryObjectType          `json:"object_type"`
	CoreFields      map[string]*NormalizedField  `json:"core_fields"`      // Essential fields present in all providers
	OptionalFields  map[string]*NormalizedField  `json:"optional_fields"`  // Optional fields that may not exist in all providers
	ExtensionFields map[string]*NormalizedField  `json:"extension_fields"` // Provider-specific extensions
	Relationships   map[string]*Relationship     `json:"relationships"`    // Object relationships
	Constraints     []*ObjectConstraint          `json:"constraints"`      // Object-level constraints
}

// NormalizedField defines a field in the normalized schema
type NormalizedField struct {
	Name         string             `json:"name"`                    // Field name
	Type         FieldType          `json:"type"`                    // Data type
	Description  string             `json:"description"`             // Field description
	Required     bool               `json:"required"`                // Is field required
	ReadOnly     bool               `json:"read_only"`               // Is field read-only
	Searchable   bool               `json:"searchable"`              // Can field be searched
	Sortable     bool               `json:"sortable"`                // Can field be used for sorting
	Format       string             `json:"format,omitempty"`        // Format specification (e.g., email, phone)
	MaxLength    int                `json:"max_length,omitempty"`    // Maximum field length
	MinLength    int                `json:"min_length,omitempty"`    // Minimum field length
	Pattern      string             `json:"pattern,omitempty"`       // Regex validation pattern
	DefaultValue interface{}        `json:"default_value,omitempty"` // Default value
	EnumValues   []interface{}      `json:"enum_values,omitempty"`   // Valid enum values
	Validation   *FieldValidation   `json:"validation,omitempty"`    // Validation rules
}

// FieldType represents the data type of a field
type FieldType string

const (
	FieldTypeString    FieldType = "string"
	FieldTypeInteger   FieldType = "integer"
	FieldTypeBoolean   FieldType = "boolean"
	FieldTypeDateTime  FieldType = "datetime"
	FieldTypeArray     FieldType = "array"
	FieldTypeObject    FieldType = "object"
	FieldTypeBinary    FieldType = "binary"
)

// FieldValidation defines validation rules for a field
type FieldValidation struct {
	Pattern       string        `json:"pattern,omitempty"`         // Regex pattern
	MinValue      interface{}   `json:"min_value,omitempty"`       // Minimum value
	MaxValue      interface{}   `json:"max_value,omitempty"`       // Maximum value
	CustomRules   []string      `json:"custom_rules,omitempty"`    // Custom validation rule names
}

// Relationship defines relationships between directory objects
type Relationship struct {
	Name         string              `json:"name"`           // Relationship name
	Type         RelationshipType    `json:"type"`           // Relationship type
	TargetType   DirectoryObjectType `json:"target_type"`    // Target object type
	Cardinality  Cardinality         `json:"cardinality"`    // Relationship cardinality
	Required     bool                `json:"required"`       // Is relationship required
	Description  string              `json:"description"`    // Relationship description
}

// RelationshipType represents the type of relationship
type RelationshipType string

const (
	RelationshipTypeContains   RelationshipType = "contains"   // Parent contains child
	RelationshipTypeMemberOf   RelationshipType = "member_of"  // Object is member of group
	RelationshipTypeManages    RelationshipType = "manages"    // Manager relationship
	RelationshipTypeReportsTo  RelationshipType = "reports_to" // Reporting relationship
)

// Cardinality represents relationship cardinality
type Cardinality string

const (
	CardinalityOneToOne   Cardinality = "1:1"
	CardinalityOneToMany  Cardinality = "1:N"
	CardinalityManyToOne  Cardinality = "N:1"
	CardinalityManyToMany Cardinality = "N:N"
)

// ObjectConstraint defines constraints on directory objects
type ObjectConstraint struct {
	Name        string    `json:"name"`                  // Constraint name
	Type        string    `json:"type"`                  // Constraint type (unique, dependency, etc.)
	Fields      []string  `json:"fields"`                // Fields involved in constraint
	Condition   string    `json:"condition,omitempty"`   // Constraint condition
	Message     string    `json:"message"`               // Error message when constraint is violated
}

// ProviderSchema defines the schema for a specific directory provider
type ProviderSchema struct {
	ProviderName    string                           `json:"provider_name"`
	UserSchema      *ProviderObjectSchema            `json:"user_schema"`
	GroupSchema     *ProviderObjectSchema            `json:"group_schema"`
	OUSchema        *ProviderObjectSchema            `json:"ou_schema,omitempty"`
	Mappings        *FieldMappingSet                 `json:"mappings"`          // Field mappings to normalized schema
	Transformers    map[string]string                `json:"transformers"`      // Data transformation rules
	Capabilities    *SchemaCapabilities              `json:"capabilities"`      // Provider-specific capabilities
}

// ProviderObjectSchema defines the schema for a provider-specific object type
type ProviderObjectSchema struct {
	ObjectType      DirectoryObjectType       `json:"object_type"`
	Fields          map[string]*ProviderField `json:"fields"`
	RequiredFields  []string                  `json:"required_fields"`
	UniqueFields    []string                  `json:"unique_fields"`
	SearchableFields []string                 `json:"searchable_fields"`
	Constraints     []*ObjectConstraint       `json:"constraints,omitempty"`
}

// ProviderField defines a field in a provider-specific schema
type ProviderField struct {
	Name            string        `json:"name"`
	ProviderType    string        `json:"provider_type"`        // Provider-specific type (e.g., "ADsPath", "objectGUID")
	NormalizedType  FieldType     `json:"normalized_type"`      // Mapped normalized type
	Syntax          string        `json:"syntax,omitempty"`     // Provider syntax (LDAP syntax, etc.)
	MultiValued     bool          `json:"multi_valued"`         // Is field multi-valued
	SystemOnly      bool          `json:"system_only"`          // Is field system-only
	Constructed     bool          `json:"constructed"`          // Is field constructed/computed
	Description     string        `json:"description"`
}

// FieldMappingSet contains all field mappings between provider and normalized schemas
type FieldMappingSet struct {
	UserMappings  map[string]*FieldMapping `json:"user_mappings"`
	GroupMappings map[string]*FieldMapping `json:"group_mappings"`
	OUMappings    map[string]*FieldMapping `json:"ou_mappings,omitempty"`
}

// FieldMapping defines how to map between provider and normalized fields
type FieldMapping struct {
	NormalizedField string                 `json:"normalized_field"`      // Normalized field name
	ProviderField   string                 `json:"provider_field"`        // Provider field name
	Transform       string                 `json:"transform,omitempty"`   // Transformation function name
	DefaultValue    interface{}            `json:"default_value,omitempty"` // Default value if not present
	ConditionalMappings []*ConditionalMapping `json:"conditional_mappings,omitempty"` // Conditional mappings
	Bidirectional   bool                   `json:"bidirectional"`         // Can map in both directions
}

// ConditionalMapping defines conditional field mapping based on other field values
type ConditionalMapping struct {
	Condition       string      `json:"condition"`        // Condition to check
	ProviderField   string      `json:"provider_field"`   // Provider field to use if condition matches
	Transform       string      `json:"transform,omitempty"` // Optional transformation
	DefaultValue    interface{} `json:"default_value,omitempty"` // Default value
}

// SchemaCapabilities defines provider-specific schema capabilities
type SchemaCapabilities struct {
	SupportsCustomAttributes bool     `json:"supports_custom_attributes"`
	SupportsExtensionSchema  bool     `json:"supports_extension_schema"`
	MaxAttributeLength       int      `json:"max_attribute_length"`
	SupportedDataTypes       []string `json:"supported_data_types"`
	NamingContexts          []string `json:"naming_contexts,omitempty"`
}

// DataTransformer interface for data transformation
type DataTransformer interface {
	Transform(input interface{}) (interface{}, error)
	Reverse(input interface{}) (interface{}, error)
	GetDescription() string
}

// FieldValidator interface for field validation
type FieldValidator interface {
	Validate(field *NormalizedField, value interface{}) error
	GetDescription() string
}

// FieldConflict represents a conflict between different provider representations
type FieldConflict struct {
	FieldName      string                 `json:"field_name"`
	NormalizedName string                 `json:"normalized_name"`
	Conflicts      map[string]interface{} `json:"conflicts"`      // provider -> value
	Resolution     ConflictResolution     `json:"resolution"`
}

// ConflictResolution defines how to resolve field conflicts
type ConflictResolution struct {
	Strategy     string      `json:"strategy"`      // Resolution strategy
	PreferredProvider string  `json:"preferred_provider,omitempty"` // Provider to prefer
	CustomValue  interface{} `json:"custom_value,omitempty"`       // Custom resolved value
}

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
					Name:        "account_enabled",
					Type:        FieldTypeBoolean,
					Description: "Is account enabled",
					Required:    true,
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
					Name:        "group_type",
					Type:        FieldTypeString,
					Description: "Group type",
					Required:    true,
					EnumValues:  []interface{}{"security", "distribution"},
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
		"id":                   normalizedUser.ID,
		"user_principal_name":  normalizedUser.UserPrincipalName,
		"display_name":         normalizedUser.DisplayName,
		"account_enabled":      normalizedUser.AccountEnabled,
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

// ValidateNormalizedObject validates a normalized object against the schema
func (m *DefaultDirectorySchemaMapper) ValidateNormalizedObject(objectType DirectoryObjectType, data map[string]interface{}) error {
	var schema *NormalizedObjectSchema
	
	switch objectType {
	case DirectoryObjectTypeUser:
		schema = m.normalizedSchema.UserSchema
	case DirectoryObjectTypeGroup:
		schema = m.normalizedSchema.GroupSchema
	case DirectoryObjectTypeOU:
		schema = m.normalizedSchema.OUSchema
	default:
		return fmt.Errorf("unsupported object type: %s", objectType)
	}
	
	if schema == nil {
		return fmt.Errorf("schema not found for object type: %s", objectType)
	}
	
	// Check required fields
	allFields := make(map[string]*NormalizedField)
	for name, field := range schema.CoreFields {
		allFields[name] = field
	}
	for name, field := range schema.OptionalFields {
		allFields[name] = field
	}
	
	for name, field := range allFields {
		value, exists := data[name]
		
		if field.Required && !exists {
			return fmt.Errorf("required field missing: %s", name)
		}
		
		if exists && value != nil {
			if err := m.validateField(field, value); err != nil {
				return fmt.Errorf("validation failed for field %s: %w", name, err)
			}
		}
	}
	
	return nil
}

// validateField validates a single field value
func (m *DefaultDirectorySchemaMapper) validateField(field *NormalizedField, value interface{}) error {
	// Type validation
	if err := m.validateFieldType(field.Type, value); err != nil {
		return err
	}
	
	// Format validation
	if field.Format != "" {
		if err := m.validateFieldFormat(field.Format, value); err != nil {
			return err
		}
	}
	
	// Pattern validation
	if field.Pattern != "" {
		if str, ok := value.(string); ok {
			matched, err := regexp.MatchString(field.Pattern, str)
			if err != nil {
				return fmt.Errorf("invalid pattern: %w", err)
			}
			if !matched {
				return fmt.Errorf("value does not match pattern %s", field.Pattern)
			}
		}
	}
	
	// Length validation
	if field.MaxLength > 0 || field.MinLength > 0 {
		if str, ok := value.(string); ok {
			length := len(str)
			if field.MaxLength > 0 && length > field.MaxLength {
				return fmt.Errorf("value exceeds maximum length %d", field.MaxLength)
			}
			if field.MinLength > 0 && length < field.MinLength {
				return fmt.Errorf("value below minimum length %d", field.MinLength)
			}
		}
	}
	
	// Enum validation
	if len(field.EnumValues) > 0 {
		found := false
		for _, enumValue := range field.EnumValues {
			if reflect.DeepEqual(value, enumValue) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("value not in allowed enum values: %v", field.EnumValues)
		}
	}
	
	// Custom validation
	if field.Validation != nil && len(field.Validation.CustomRules) > 0 {
		for _, ruleName := range field.Validation.CustomRules {
			if validator, exists := m.validators[ruleName]; exists {
				if err := validator.Validate(field, value); err != nil {
					return fmt.Errorf("custom validation failed (%s): %w", ruleName, err)
				}
			}
		}
	}
	
	return nil
}

// validateFieldType validates the data type of a field value
func (m *DefaultDirectorySchemaMapper) validateFieldType(fieldType FieldType, value interface{}) error {
	switch fieldType {
	case FieldTypeString:
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
	case FieldTypeInteger:
		switch value.(type) {
		case int, int32, int64, uint, uint32, uint64:
			// Valid integer types
		default:
			return fmt.Errorf("expected integer, got %T", value)
		}
	case FieldTypeBoolean:
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected boolean, got %T", value)
		}
	case FieldTypeDateTime:
		if _, ok := value.(time.Time); !ok {
			return fmt.Errorf("expected datetime, got %T", value)
		}
	case FieldTypeArray:
		if reflect.TypeOf(value).Kind() != reflect.Slice {
			return fmt.Errorf("expected array, got %T", value)
		}
	case FieldTypeObject:
		if reflect.TypeOf(value).Kind() != reflect.Map {
			return fmt.Errorf("expected object, got %T", value)
		}
	}
	
	return nil
}

// validateFieldFormat validates field format constraints
func (m *DefaultDirectorySchemaMapper) validateFieldFormat(format string, value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("format validation requires string value")
	}
	
	switch format {
	case "email":
		pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return fmt.Errorf("invalid email pattern: %w", err)
		}
		if !matched {
			return fmt.Errorf("invalid email format")
		}
	case "phone":
		// Basic phone number validation (can be enhanced)
		pattern := `^\+?[\d\s\-\(\)]+$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return fmt.Errorf("invalid phone pattern: %w", err)
		}
		if !matched {
			return fmt.Errorf("invalid phone format")
		}
	}
	
	return nil
}

// ValidateProviderObject validates a provider object against its schema
func (m *DefaultDirectorySchemaMapper) ValidateProviderObject(providerName string, objectType DirectoryObjectType, data map[string]interface{}) error {
	schema, exists := m.providerSchemas[providerName]
	if !exists {
		return fmt.Errorf("provider schema not found: %s", providerName)
	}
	
	var objectSchema *ProviderObjectSchema
	switch objectType {
	case DirectoryObjectTypeUser:
		objectSchema = schema.UserSchema
	case DirectoryObjectTypeGroup:
		objectSchema = schema.GroupSchema
	case DirectoryObjectTypeOU:
		objectSchema = schema.OUSchema
	default:
		return fmt.Errorf("unsupported object type: %s", objectType)
	}
	
	if objectSchema == nil {
		return fmt.Errorf("object schema not found for type: %s", objectType)
	}
	
	// Check required fields
	for _, fieldName := range objectSchema.RequiredFields {
		if _, exists := data[fieldName]; !exists {
			return fmt.Errorf("required field missing: %s", fieldName)
		}
	}
	
	// Validate field types (basic validation)
	for fieldName, value := range data {
		if field, exists := objectSchema.Fields[fieldName]; exists {
			if value != nil && field.ProviderType != "" {
				// TODO: Implement provider-specific type validation
				// Each provider (AD, Azure, etc.) has different data types and constraints
				// that should be validated based on field.ProviderType
				_ = field.ProviderType // Acknowledge need for future validation implementation
			}
		}
	}
	
	return nil
}

// ResolveConflicts resolves conflicts between different provider representations
func (m *DefaultDirectorySchemaMapper) ResolveConflicts(conflicts []FieldConflict) (map[string]interface{}, error) {
	resolved := make(map[string]interface{})
	
	for _, conflict := range conflicts {
		switch conflict.Resolution.Strategy {
		case "prefer_provider":
			if conflict.Resolution.PreferredProvider != "" {
				if value, exists := conflict.Conflicts[conflict.Resolution.PreferredProvider]; exists {
					resolved[conflict.NormalizedName] = value
				}
			}
		case "custom_value":
			if conflict.Resolution.CustomValue != nil {
				resolved[conflict.NormalizedName] = conflict.Resolution.CustomValue
			}
		case "merge":
			// Implement merge strategy (e.g., concatenate strings, merge arrays)
			merged := m.mergeConflictValues(conflict.Conflicts)
			resolved[conflict.NormalizedName] = merged
		case "newest":
			// Choose the value from the provider with the most recent timestamp
			// This would require timestamp metadata in the conflicts
		default:
			return nil, fmt.Errorf("unsupported conflict resolution strategy: %s", conflict.Resolution.Strategy)
		}
	}
	
	return resolved, nil
}

// mergeConflictValues merges conflicting values
func (m *DefaultDirectorySchemaMapper) mergeConflictValues(conflicts map[string]interface{}) interface{} {
	// Simple merge strategy - concatenate strings or return first non-nil value
	var result interface{}
	var stringValues []string
	
	for provider, value := range conflicts {
		if result == nil {
			result = value
		}
		
		if str, ok := value.(string); ok && str != "" {
			stringValues = append(stringValues, fmt.Sprintf("%s: %s", provider, str))
		}
	}
	
	// If we have multiple string values, concatenate them
	if len(stringValues) > 1 {
		return strings.Join(stringValues, "; ")
	}
	
	return result
}

// Built-in transformers and validators

// registerBuiltinTransformers registers built-in data transformers
func (m *DefaultDirectorySchemaMapper) registerBuiltinTransformers() {
	m.transformers["to_lowercase"] = &ToLowercaseTransformer{}
	m.transformers["to_uppercase"] = &ToUppercaseTransformer{}
	m.transformers["trim_spaces"] = &TrimSpacesTransformer{}
	m.transformers["parse_boolean"] = &ParseBooleanTransformer{}
	m.transformers["format_phone"] = &FormatPhoneTransformer{}
	m.transformers["normalize_email"] = &NormalizeEmailTransformer{}
	m.transformers["parse_timestamp"] = &ParseTimestampTransformer{}
}

// registerBuiltinValidators registers built-in field validators
func (m *DefaultDirectorySchemaMapper) registerBuiltinValidators() {
	m.validators["non_empty"] = &NonEmptyValidator{}
	m.validators["email_format"] = &EmailFormatValidator{}
	m.validators["phone_format"] = &PhoneFormatValidator{}
	m.validators["alphanumeric"] = &AlphanumericValidator{}
}

// Built-in transformer implementations

type ToLowercaseTransformer struct{}

func (t *ToLowercaseTransformer) Transform(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		return strings.ToLower(str), nil
	}
	return input, nil
}

func (t *ToLowercaseTransformer) Reverse(input interface{}) (interface{}, error) {
	return input, nil // Lowercasing is not reversible
}

func (t *ToLowercaseTransformer) GetDescription() string {
	return "Converts string to lowercase"
}

type ToUppercaseTransformer struct{}

func (t *ToUppercaseTransformer) Transform(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		return strings.ToUpper(str), nil
	}
	return input, nil
}

func (t *ToUppercaseTransformer) Reverse(input interface{}) (interface{}, error) {
	return input, nil // Uppercasing is not reversible
}

func (t *ToUppercaseTransformer) GetDescription() string {
	return "Converts string to uppercase"
}

type TrimSpacesTransformer struct{}

func (t *TrimSpacesTransformer) Transform(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		return strings.TrimSpace(str), nil
	}
	return input, nil
}

func (t *TrimSpacesTransformer) Reverse(input interface{}) (interface{}, error) {
	return input, nil // Trimming is not reversible
}

func (t *TrimSpacesTransformer) GetDescription() string {
	return "Trims whitespace from string"
}

type ParseBooleanTransformer struct{}

func (t *ParseBooleanTransformer) Transform(input interface{}) (interface{}, error) {
	switch v := input.(type) {
	case string:
		return strconv.ParseBool(strings.ToLower(v))
	case bool:
		return v, nil
	case int:
		return v != 0, nil
	default:
		return false, fmt.Errorf("cannot convert %T to boolean", input)
	}
}

func (t *ParseBooleanTransformer) Reverse(input interface{}) (interface{}, error) {
	if b, ok := input.(bool); ok {
		if b {
			return "true", nil
		}
		return "false", nil
	}
	return input, nil
}

func (t *ParseBooleanTransformer) GetDescription() string {
	return "Converts various formats to boolean"
}

type FormatPhoneTransformer struct{}

func (t *FormatPhoneTransformer) Transform(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		// Simple phone formatting - remove non-digits and add standard formatting
		digits := regexp.MustCompile(`\D`).ReplaceAllString(str, "")
		if len(digits) == 10 {
			return fmt.Sprintf("(%s) %s-%s", digits[0:3], digits[3:6], digits[6:10]), nil
		} else if len(digits) == 11 && digits[0] == '1' {
			return fmt.Sprintf("+1 (%s) %s-%s", digits[1:4], digits[4:7], digits[7:11]), nil
		}
		return str, nil // Return original if can't format
	}
	return input, nil
}

func (t *FormatPhoneTransformer) Reverse(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		// Extract digits only
		return regexp.MustCompile(`\D`).ReplaceAllString(str, ""), nil
	}
	return input, nil
}

func (t *FormatPhoneTransformer) GetDescription() string {
	return "Formats phone numbers to standard format"
}

type NormalizeEmailTransformer struct{}

func (t *NormalizeEmailTransformer) Transform(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		return strings.ToLower(strings.TrimSpace(str)), nil
	}
	return input, nil
}

func (t *NormalizeEmailTransformer) Reverse(input interface{}) (interface{}, error) {
	return input, nil // Email normalization is not reversible
}

func (t *NormalizeEmailTransformer) GetDescription() string {
	return "Normalizes email addresses (lowercase, trim)"
}

type ParseTimestampTransformer struct{}

func (t *ParseTimestampTransformer) Transform(input interface{}) (interface{}, error) {
	switch v := input.(type) {
	case string:
		// Try common timestamp formats
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
			"01/02/2006 15:04:05",
		}
		
		for _, format := range formats {
			if t, err := time.Parse(format, v); err == nil {
				return t, nil
			}
		}
		return nil, fmt.Errorf("unable to parse timestamp: %s", v)
	case time.Time:
		return v, nil
	case int64:
		// Assume Unix timestamp
		return time.Unix(v, 0), nil
	default:
		return nil, fmt.Errorf("unsupported timestamp type: %T", input)
	}
}

func (t *ParseTimestampTransformer) Reverse(input interface{}) (interface{}, error) {
	if ts, ok := input.(time.Time); ok {
		return ts.Format(time.RFC3339), nil
	}
	return input, nil
}

func (t *ParseTimestampTransformer) GetDescription() string {
	return "Parses timestamps from various formats"
}

// Built-in validator implementations

type NonEmptyValidator struct{}

func (v *NonEmptyValidator) Validate(field *NormalizedField, value interface{}) error {
	if str, ok := value.(string); ok {
		if strings.TrimSpace(str) == "" {
			return fmt.Errorf("field cannot be empty")
		}
	}
	return nil
}

func (v *NonEmptyValidator) GetDescription() string {
	return "Validates that string fields are not empty"
}

type EmailFormatValidator struct{}

func (v *EmailFormatValidator) Validate(field *NormalizedField, value interface{}) error {
	if str, ok := value.(string); ok {
		pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return fmt.Errorf("email validation error: %w", err)
		}
		if !matched {
			return fmt.Errorf("invalid email format")
		}
	}
	return nil
}

func (v *EmailFormatValidator) GetDescription() string {
	return "Validates email address format"
}

type PhoneFormatValidator struct{}

func (v *PhoneFormatValidator) Validate(field *NormalizedField, value interface{}) error {
	if str, ok := value.(string); ok {
		pattern := `^\+?[\d\s\-\(\)\.]+$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return fmt.Errorf("phone validation error: %w", err)
		}
		if !matched {
			return fmt.Errorf("invalid phone format")
		}
	}
	return nil
}

func (v *PhoneFormatValidator) GetDescription() string {
	return "Validates phone number format"
}

type AlphanumericValidator struct{}

func (v *AlphanumericValidator) Validate(field *NormalizedField, value interface{}) error {
	if str, ok := value.(string); ok {
		pattern := `^[a-zA-Z0-9]+$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return fmt.Errorf("alphanumeric validation error: %w", err)
		}
		if !matched {
			return fmt.Errorf("field must contain only alphanumeric characters")
		}
	}
	return nil
}

func (v *AlphanumericValidator) GetDescription() string {
	return "Validates that field contains only alphanumeric characters"
}