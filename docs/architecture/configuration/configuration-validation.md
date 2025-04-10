# Configuration Validation

## Overview

Configuration validation is the process of ensuring that configurations meet the required schema and constraints before they are applied. CFGMS uses a comprehensive validation system that includes schema validation, constraint checking, and dependency validation.

## Schema Validation

Schema validation ensures that configurations conform to a defined schema, including required fields, data types, and value constraints.

```yaml
# /cfgms/system/meta/schemas/endpoint.yaml
type: object
required:
  - name
  - version
  - applies_to
properties:
  name:
    type: string
  version:
    type: string
  applies_to:
    type: object
    properties:
      dna:
        type: object
        additionalProperties:
          type: string
```

### Implementation

```go
type ConfigValidator struct {
    schemas map[string]*Schema
}

func (v *ConfigValidator) Validate(cfg *Config) error {
    schema := v.schemas[cfg.Type]
    if schema == nil {
        return ErrSchemaNotFound
    }
    
    return schema.Validate(cfg.Data)
}
```

### Schema Validation Rules

1. **Required Fields** - All required fields must be present
2. **Data Types** - Fields must have the correct data type
3. **Value Constraints** - Values must meet any constraints (e.g., min/max, pattern)
4. **Nested Objects** - Nested objects must also conform to their schema
5. **Arrays** - Array items must conform to their schema

## Constraint Checking

Constraint checking ensures that configurations meet business rules and constraints that cannot be expressed in the schema.

```go
type ConstraintChecker struct {
    constraints []Constraint
}

type Constraint interface {
    Check(cfg *Config) error
}

type PasswordPolicyConstraint struct {
    MinLength int
    RequireSpecial bool
    RequireNumbers bool
}

func (c *PasswordPolicyConstraint) Check(cfg *Config) error {
    password := cfg.GetString("password")
    if len(password) < c.MinLength {
        return fmt.Errorf("password must be at least %d characters", c.MinLength)
    }
    
    if c.RequireSpecial && !strings.ContainsAny(password, "!@#$%^&*()") {
        return fmt.Errorf("password must contain special characters")
    }
    
    if c.RequireNumbers && !strings.ContainsAny(password, "0123456789") {
        return fmt.Errorf("password must contain numbers")
    }
    
    return nil
}
```

### Constraint Types

1. **Value Constraints** - Constraints on individual values
2. **Relationship Constraints** - Constraints on relationships between values
3. **Business Rule Constraints** - Constraints based on business rules
4. **Security Constraints** - Constraints based on security requirements

## Dependency Validation

Dependency validation ensures that all required dependencies are satisfied before a configuration is applied.

```go
type DependencyValidator struct {
    store ConfigStorage
}

func (v *DependencyValidator) Validate(cfg *Config) error {
    deps := cfg.GetDependencies()
    
    for _, dep := range deps {
        if !v.store.Exists(dep) {
            return fmt.Errorf("dependency %s not found", dep)
        }
    }
    
    return nil
}
```

### Dependency Types

1. **Module Dependencies** - Dependencies on other modules
2. **Resource Dependencies** - Dependencies on resources (e.g., files, services)
3. **Configuration Dependencies** - Dependencies on other configurations
4. **External Dependencies** - Dependencies on external systems

## Validation Process

The complete validation process involves:

1. **Schema Validation** - Validate against the schema
2. **Constraint Checking** - Check business rules and constraints
3. **Dependency Validation** - Validate dependencies
4. **Error Reporting** - Report validation errors with clear messages

## Error Handling

Validation errors are reported with clear messages that help users understand and fix the issues.

```go
type ValidationError struct {
    Path    string
    Message string
    Context map[string]interface{}
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

func (v *ConfigValidator) ValidateWithContext(cfg *Config) []ValidationError {
    var errors []ValidationError
    
    // Schema validation
    if err := v.validateSchema(cfg); err != nil {
        errors = append(errors, ValidationError{
            Path:    "schema",
            Message: err.Error(),
        })
    }
    
    // Constraint checking
    if err := v.checkConstraints(cfg); err != nil {
        errors = append(errors, ValidationError{
            Path:    "constraints",
            Message: err.Error(),
        })
    }
    
    // Dependency validation
    if err := v.validateDependencies(cfg); err != nil {
        errors = append(errors, ValidationError{
            Path:    "dependencies",
            Message: err.Error(),
        })
    }
    
    return errors
}
```

### Error Types

1. **Schema Errors** - Errors related to schema validation
2. **Constraint Errors** - Errors related to constraint checking
3. **Dependency Errors** - Errors related to dependency validation
4. **Syntax Errors** - Errors related to configuration syntax

## Version Information

- **Document Version:** 1.0
- **Last Updated:** 2024-04-07
- **Status:** Draft
