# Interface Definitions

This document describes the core interfaces used throughout the CFGMS system, explaining their purpose, design, and usage.

## Core Interfaces

### Module Interface

The Module interface is the core interface for all modules in CFGMS:

```go
// Module defines the interface that all modules must implement.
type Module interface {
    // Name returns the name of the module.
    Name() string

    // Description returns a description of the module.
    Description() string

    // Get returns the current configuration of the resource.
    Get(ctx context.Context, req *GetRequest) (*GetResponse, error)

    // Set configures the resource to match the specified configuration.
    Set(ctx context.Context, req *SetRequest) (*SetResponse, error)

    // Test validates if the current state matches the prescribed state.
    Test(ctx context.Context, req *TestRequest) (*TestResponse, error)

    // Monitor returns a monitor for the resource, if supported.
    Monitor(ctx context.Context, req *MonitorRequest) (Monitor, error)
}

// GetRequest represents a request to get the current configuration.
type GetRequest struct {
    // ResourceID is the ID of the resource.
    ResourceID string

    // Options contains additional options for the get operation.
    Options map[string]interface{}
}

// GetResponse represents a response from a get operation.
type GetResponse struct {
    // Configuration is the current configuration of the resource.
    Configuration []byte

    // Metadata contains additional metadata about the configuration.
    Metadata map[string]interface{}
}

// SetRequest represents a request to set the configuration.
type SetRequest struct {
    // ResourceID is the ID of the resource.
    ResourceID string

    // Configuration is the desired configuration.
    Configuration []byte

    // Options contains additional options for the set operation.
    Options map[string]interface{}
}

// SetResponse represents a response from a set operation.
type SetResponse struct {
    // Success indicates whether the operation was successful.
    Success bool

    // Message contains a message about the operation.
    Message string

    // Metadata contains additional metadata about the operation.
    Metadata map[string]interface{}
}

// TestRequest represents a request to test the configuration.
type TestRequest struct {
    // ResourceID is the ID of the resource.
    ResourceID string

    // Configuration is the desired configuration.
    Configuration []byte

    // Options contains additional options for the test operation.
    Options map[string]interface{}
}

// TestResponse represents a response from a test operation.
type TestResponse struct {
    // Success indicates whether the test was successful.
    Success bool

    // Message contains a message about the test.
    Message string

    // Details contains detailed information about the test.
    Details map[string]interface{}
}

// MonitorRequest represents a request to create a monitor.
type MonitorRequest struct {
    // ResourceID is the ID of the resource.
    ResourceID string

    // Options contains additional options for the monitor.
    Options map[string]interface{}
}

// Monitor defines the interface for resource monitors.
type Monitor interface {
    // Start starts the monitor.
    Start(ctx context.Context) error

    // Stop stops the monitor.
    Stop(ctx context.Context) error

    // Events returns a channel that receives events from the monitor.
    Events() <-chan Event
}

// Event represents an event from a monitor.
type Event struct {
    // Type is the type of the event.
    Type string

    // ResourceID is the ID of the resource.
    ResourceID string

    // Data contains additional data about the event.
    Data map[string]interface{}

    // Timestamp is the time the event occurred.
    Timestamp time.Time
}
```

### Storage Interface

The Storage interface is used for storing and retrieving configurations:

```go
// Storage defines the interface for configuration storage.
type Storage interface {
    // Get retrieves a configuration.
    Get(ctx context.Context, path string) ([]byte, error)

    // Put stores a configuration.
    Put(ctx context.Context, path string, data []byte) error

    // Delete deletes a configuration.
    Delete(ctx context.Context, path string) error

    // List lists configurations at a path.
    List(ctx context.Context, path string) ([]string, error)

    // Exists checks if a configuration exists.
    Exists(ctx context.Context, path string) (bool, error)

    // Watch watches for changes to configurations.
    Watch(ctx context.Context, path string) (<-chan Event, error)
}
```

### Workflow Interface

The Workflow interface is used for defining and executing workflows:

```go
// Workflow defines the interface for workflows.
type Workflow interface {
    // Name returns the name of the workflow.
    Name() string

    // Description returns a description of the workflow.
    Description() string

    // Execute executes the workflow.
    Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error)

    // Validate validates the workflow.
    Validate(ctx context.Context, req *ValidateRequest) (*ValidateResponse, error)
}

// ExecuteRequest represents a request to execute a workflow.
type ExecuteRequest struct {
    // Input contains the input for the workflow.
    Input map[string]interface{}

    // Options contains additional options for the execution.
    Options map[string]interface{}
}

// ExecuteResponse represents a response from a workflow execution.
type ExecuteResponse struct {
    // Success indicates whether the execution was successful.
    Success bool

    // Output contains the output from the workflow.
    Output map[string]interface{}

    // Message contains a message about the execution.
    Message string
}

// ValidateRequest represents a request to validate a workflow.
type ValidateRequest struct {
    // Input contains the input for the workflow.
    Input map[string]interface{}
}

// ValidateResponse represents a response from a workflow validation.
type ValidateResponse struct {
    // Valid indicates whether the workflow is valid.
    Valid bool

    // Errors contains any validation errors.
    Errors []string
}
```

### Tenant Interface

The Tenant interface is used for managing tenants:

```go
// Tenant defines the interface for tenant management.
type Tenant interface {
    // ID returns the ID of the tenant.
    ID() string

    // Parent returns the parent of the tenant, if any.
    Parent() string

    // Children returns the children of the tenant.
    Children() []string

    // Path returns the path of the tenant.
    Path() string

    // Config returns the configuration of the tenant.
    Config() map[string]interface{}

    // SetConfig sets the configuration of the tenant.
    SetConfig(config map[string]interface{}) error
}

// TenantManager defines the interface for tenant management.
type TenantManager interface {
    // Create creates a tenant.
    Create(ctx context.Context, req *CreateTenantRequest) (*CreateTenantResponse, error)

    // Delete deletes a tenant.
    Delete(ctx context.Context, req *DeleteTenantRequest) (*DeleteTenantResponse, error)

    // Get gets a tenant.
    Get(ctx context.Context, req *GetTenantRequest) (*GetTenantResponse, error)

    // List lists tenants.
    List(ctx context.Context, req *ListTenantsRequest) (*ListTenantsResponse, error)

    // Update updates a tenant.
    Update(ctx context.Context, req *UpdateTenantRequest) (*UpdateTenantResponse, error)
}

// CreateTenantRequest represents a request to create a tenant.
type CreateTenantRequest struct {
    // ID is the ID of the tenant.
    ID string

    // Parent is the parent of the tenant, if any.
    Parent string

    // Config is the configuration of the tenant.
    Config map[string]interface{}
}

// CreateTenantResponse represents a response from a tenant creation.
type CreateTenantResponse struct {
    // Tenant is the created tenant.
    Tenant Tenant
}

// DeleteTenantRequest represents a request to delete a tenant.
type DeleteTenantRequest struct {
    // ID is the ID of the tenant.
    ID string
}

// DeleteTenantResponse represents a response from a tenant deletion.
type DeleteTenantResponse struct {
    // Success indicates whether the deletion was successful.
    Success bool
}

// GetTenantRequest represents a request to get a tenant.
type GetTenantRequest struct {
    // ID is the ID of the tenant.
    ID string
}

// GetTenantResponse represents a response from a tenant retrieval.
type GetTenantResponse struct {
    // Tenant is the retrieved tenant.
    Tenant Tenant
}

// ListTenantsRequest represents a request to list tenants.
type ListTenantsRequest struct {
    // Parent is the parent of the tenants to list, if any.
    Parent string
}

// ListTenantsResponse represents a response from a tenant listing.
type ListTenantsResponse struct {
    // Tenants are the listed tenants.
    Tenants []Tenant
}

// UpdateTenantRequest represents a request to update a tenant.
type UpdateTenantRequest struct {
    // ID is the ID of the tenant.
    ID string

    // Config is the new configuration of the tenant.
    Config map[string]interface{}
}

// UpdateTenantResponse represents a response from a tenant update.
type UpdateTenantResponse struct {
    // Tenant is the updated tenant.
    Tenant Tenant
}
```

## Interface Design Principles

CFGMS interfaces are designed according to the following principles:

1. **Small and Focused**: Interfaces are small and focused on a single responsibility
2. **Stable**: Interfaces are stable and rarely change
3. **Well-documented**: Interfaces are well-documented
4. **Consistent**: Interfaces follow consistent naming and design patterns
5. **Testable**: Interfaces are designed for testability

## Interface Usage

Interfaces are used in CFGMS as follows:

1. **Dependency Injection**: Dependencies are injected using interfaces
2. **Mocking**: Interfaces are used for mocking in tests
3. **Pluggability**: Interfaces enable pluggable implementations
4. **Abstraction**: Interfaces provide abstraction over implementation details
5. **Composition**: Interfaces enable composition of functionality

## Version Information

- **Version**: 1.0
- **Last Updated**: 2024-04-07
- **Status**: Draft 