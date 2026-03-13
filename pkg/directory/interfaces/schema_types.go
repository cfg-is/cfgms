// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces - Directory Schema Type Definitions
//
// This file contains all type definitions, constants, and interface declarations
// for the schema normalization layer. These are the contracts used by the mapper
// implementation and its callers.

package interfaces

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
	providerSchemas  map[string]*ProviderSchema
	normalizedSchema *NormalizedSchema
	fieldMappings    map[string]*FieldMappingSet
	transformers     map[string]DataTransformer
	validators       map[string]FieldValidator
}

// NormalizedSchema defines the universal schema for directory objects
type NormalizedSchema struct {
	UserSchema  *NormalizedObjectSchema `json:"user_schema"`
	GroupSchema *NormalizedObjectSchema `json:"group_schema"`
	OUSchema    *NormalizedObjectSchema `json:"ou_schema"`
}

// NormalizedObjectSchema defines the schema for a normalized object type
type NormalizedObjectSchema struct {
	ObjectType      DirectoryObjectType         `json:"object_type"`
	CoreFields      map[string]*NormalizedField `json:"core_fields"`      // Essential fields present in all providers
	OptionalFields  map[string]*NormalizedField `json:"optional_fields"`  // Optional fields that may not exist in all providers
	ExtensionFields map[string]*NormalizedField `json:"extension_fields"` // Provider-specific extensions
	Relationships   map[string]*Relationship    `json:"relationships"`    // Object relationships
	Constraints     []*ObjectConstraint         `json:"constraints"`      // Object-level constraints
}

// NormalizedField defines a field in the normalized schema
type NormalizedField struct {
	Name         string           `json:"name"`                    // Field name
	Type         FieldType        `json:"type"`                    // Data type
	Description  string           `json:"description"`             // Field description
	Required     bool             `json:"required"`                // Is field required
	ReadOnly     bool             `json:"read_only"`               // Is field read-only
	Searchable   bool             `json:"searchable"`              // Can field be searched
	Sortable     bool             `json:"sortable"`                // Can field be used for sorting
	Format       string           `json:"format,omitempty"`        // Format specification (e.g., email, phone)
	MaxLength    int              `json:"max_length,omitempty"`    // Maximum field length
	MinLength    int              `json:"min_length,omitempty"`    // Minimum field length
	Pattern      string           `json:"pattern,omitempty"`       // Regex validation pattern
	DefaultValue interface{}      `json:"default_value,omitempty"` // Default value
	EnumValues   []interface{}    `json:"enum_values,omitempty"`   // Valid enum values
	Validation   *FieldValidation `json:"validation,omitempty"`    // Validation rules
}

// FieldType represents the data type of a field
type FieldType string

const (
	FieldTypeString   FieldType = "string"
	FieldTypeInteger  FieldType = "integer"
	FieldTypeBoolean  FieldType = "boolean"
	FieldTypeDateTime FieldType = "datetime"
	FieldTypeArray    FieldType = "array"
	FieldTypeObject   FieldType = "object"
	FieldTypeBinary   FieldType = "binary"
)

// FieldValidation defines validation rules for a field
type FieldValidation struct {
	Pattern     string      `json:"pattern,omitempty"`      // Regex pattern
	MinValue    interface{} `json:"min_value,omitempty"`    // Minimum value
	MaxValue    interface{} `json:"max_value,omitempty"`    // Maximum value
	CustomRules []string    `json:"custom_rules,omitempty"` // Custom validation rule names
}

// Relationship defines relationships between directory objects
type Relationship struct {
	Name        string              `json:"name"`        // Relationship name
	Type        RelationshipType    `json:"type"`        // Relationship type
	TargetType  DirectoryObjectType `json:"target_type"` // Target object type
	Cardinality Cardinality         `json:"cardinality"` // Relationship cardinality
	Required    bool                `json:"required"`    // Is relationship required
	Description string              `json:"description"` // Relationship description
}

// RelationshipType represents the type of relationship
type RelationshipType string

const (
	RelationshipTypeContains  RelationshipType = "contains"   // Parent contains child
	RelationshipTypeMemberOf  RelationshipType = "member_of"  // Object is member of group
	RelationshipTypeManages   RelationshipType = "manages"    // Manager relationship
	RelationshipTypeReportsTo RelationshipType = "reports_to" // Reporting relationship
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
	Name      string   `json:"name"`                // Constraint name
	Type      string   `json:"type"`                // Constraint type (unique, dependency, etc.)
	Fields    []string `json:"fields"`              // Fields involved in constraint
	Condition string   `json:"condition,omitempty"` // Constraint condition
	Message   string   `json:"message"`             // Error message when constraint is violated
}

// ProviderSchema defines the schema for a specific directory provider
type ProviderSchema struct {
	ProviderName string                `json:"provider_name"`
	UserSchema   *ProviderObjectSchema `json:"user_schema"`
	GroupSchema  *ProviderObjectSchema `json:"group_schema"`
	OUSchema     *ProviderObjectSchema `json:"ou_schema,omitempty"`
	Mappings     *FieldMappingSet      `json:"mappings"`     // Field mappings to normalized schema
	Transformers map[string]string     `json:"transformers"` // Data transformation rules
	Capabilities *SchemaCapabilities   `json:"capabilities"` // Provider-specific capabilities
}

// ProviderObjectSchema defines the schema for a provider-specific object type
type ProviderObjectSchema struct {
	ObjectType       DirectoryObjectType       `json:"object_type"`
	Fields           map[string]*ProviderField `json:"fields"`
	RequiredFields   []string                  `json:"required_fields"`
	UniqueFields     []string                  `json:"unique_fields"`
	SearchableFields []string                  `json:"searchable_fields"`
	Constraints      []*ObjectConstraint       `json:"constraints,omitempty"`
}

// ProviderField defines a field in a provider-specific schema
type ProviderField struct {
	Name           string    `json:"name"`
	ProviderType   string    `json:"provider_type"`    // Provider-specific type (e.g., "ADsPath", "objectGUID")
	NormalizedType FieldType `json:"normalized_type"`  // Mapped normalized type
	Syntax         string    `json:"syntax,omitempty"` // Provider syntax (LDAP syntax, etc.)
	MultiValued    bool      `json:"multi_valued"`     // Is field multi-valued
	SystemOnly     bool      `json:"system_only"`      // Is field system-only
	Constructed    bool      `json:"constructed"`      // Is field constructed/computed
	Description    string    `json:"description"`
}

// FieldMappingSet contains all field mappings between provider and normalized schemas
type FieldMappingSet struct {
	UserMappings  map[string]*FieldMapping `json:"user_mappings"`
	GroupMappings map[string]*FieldMapping `json:"group_mappings"`
	OUMappings    map[string]*FieldMapping `json:"ou_mappings,omitempty"`
}

// FieldMapping defines how to map between provider and normalized fields
type FieldMapping struct {
	NormalizedField     string                `json:"normalized_field"`               // Normalized field name
	ProviderField       string                `json:"provider_field"`                 // Provider field name
	Transform           string                `json:"transform,omitempty"`            // Transformation function name
	DefaultValue        interface{}           `json:"default_value,omitempty"`        // Default value if not present
	ConditionalMappings []*ConditionalMapping `json:"conditional_mappings,omitempty"` // Conditional mappings
	Bidirectional       bool                  `json:"bidirectional"`                  // Can map in both directions
}

// ConditionalMapping defines conditional field mapping based on other field values
type ConditionalMapping struct {
	Condition     string      `json:"condition"`               // Condition to check
	ProviderField string      `json:"provider_field"`          // Provider field to use if condition matches
	Transform     string      `json:"transform,omitempty"`     // Optional transformation
	DefaultValue  interface{} `json:"default_value,omitempty"` // Default value
}

// SchemaCapabilities defines provider-specific schema capabilities
type SchemaCapabilities struct {
	SupportsCustomAttributes bool     `json:"supports_custom_attributes"`
	SupportsExtensionSchema  bool     `json:"supports_extension_schema"`
	MaxAttributeLength       int      `json:"max_attribute_length"`
	SupportedDataTypes       []string `json:"supported_data_types"`
	NamingContexts           []string `json:"naming_contexts,omitempty"`
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
	Conflicts      map[string]interface{} `json:"conflicts"` // provider -> value
	Resolution     ConflictResolution     `json:"resolution"`
}

// ConflictResolution defines how to resolve field conflicts
type ConflictResolution struct {
	Strategy          string      `json:"strategy"`                     // Resolution strategy
	PreferredProvider string      `json:"preferred_provider,omitempty"` // Provider to prefer
	CustomValue       interface{} `json:"custom_value,omitempty"`       // Custom resolved value
}
