// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package saas workflow implements workflow engine integration
// for SaaS provider operations in CFGMS.
//
// This module provides workflow node types that enable users to:
//   - Use normalized SaaS operations in workflows (saas_action nodes)
//   - Execute raw API calls when normalization doesn't cover use cases (api nodes)
//   - Chain SaaS operations together in complex workflows
//   - Handle authentication automatically
//   - Process results and errors consistently
//
// Example workflow configuration:
//
//	workflow:
//	  steps:
//	    - type: saas_action
//	      provider: microsoft
//	      operation: create
//	      resource_type: users
//	      data:
//	        name: "${user.name}"
//	        email: "${user.email}"
//	        active: true
//
//	    - type: api
//	      provider: microsoft
//	      method: POST
//	      path: "/users/${previous.id}/memberOf/$ref"
//	      body:
//	        "@odata.id": "https://graph.microsoft.com/v1.0/groups/${group.id}"
package saas

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/workflow"
)

// SaaSActionNode implements a workflow node for normalized SaaS operations
type SaaSActionNode struct {
	*workflow.BaseNode

	// Provider specifies which SaaS provider to use
	Provider string `yaml:"provider" json:"provider"`

	// Operation specifies the normalized operation (create, read, update, delete, list)
	Operation string `yaml:"operation" json:"operation"`

	// ResourceType specifies the resource type (users, groups, etc.)
	ResourceType string `yaml:"resource_type" json:"resource_type"`

	// ResourceID for read, update, delete operations
	ResourceID string `yaml:"resource_id,omitempty" json:"resource_id,omitempty"`

	// Data contains the operation data (for create/update operations)
	Data map[string]interface{} `yaml:"data,omitempty" json:"data,omitempty"`

	// Filters contains filtering criteria (for list operations)
	Filters map[string]interface{} `yaml:"filters,omitempty" json:"filters,omitempty"`

	// Config contains additional configuration
	Config SaaSActionConfig `yaml:"config,omitempty" json:"config,omitempty"`

	// Internal fields
	registry   *ProviderRegistry
	operations *NormalizedOperations
}

// SaaSActionConfig contains additional configuration for SaaS actions
type SaaSActionConfig struct {
	// RetryAttempts specifies how many times to retry failed operations
	RetryAttempts int `yaml:"retry_attempts,omitempty" json:"retry_attempts,omitempty"`

	// IgnoreErrors indicates whether to continue workflow on errors
	IgnoreErrors bool `yaml:"ignore_errors,omitempty" json:"ignore_errors,omitempty"`

	// OutputMapping specifies how to map operation results to workflow variables
	OutputMapping map[string]string `yaml:"output_mapping,omitempty" json:"output_mapping,omitempty"`

	// Authentication override (if different from provider default)
	Authentication *AuthConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`
}

// APINode implements a workflow node for raw API calls
type APINode struct {
	*workflow.BaseNode

	// Provider specifies which SaaS provider to use
	Provider string `yaml:"provider" json:"provider"`

	// Method specifies the HTTP method
	Method string `yaml:"method" json:"method"`

	// Path specifies the API path (can include variables)
	Path string `yaml:"path" json:"path"`

	// Body contains the request body (for POST/PUT/PATCH)
	Body interface{} `yaml:"body,omitempty" json:"body,omitempty"`

	// Headers contains additional HTTP headers
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// Config contains additional configuration
	Config APINodeConfig `yaml:"config,omitempty" json:"config,omitempty"`

	// Internal fields
	registry *ProviderRegistry
}

// APINodeConfig contains additional configuration for API nodes
type APINodeConfig struct {
	// RetryAttempts specifies how many times to retry failed requests
	RetryAttempts int `yaml:"retry_attempts,omitempty" json:"retry_attempts,omitempty"`

	// IgnoreErrors indicates whether to continue workflow on errors
	IgnoreErrors bool `yaml:"ignore_errors,omitempty" json:"ignore_errors,omitempty"`

	// ResponseMapping specifies how to extract data from responses
	ResponseMapping map[string]string `yaml:"response_mapping,omitempty" json:"response_mapping,omitempty"`

	// Authentication override (if different from provider default)
	Authentication *AuthConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// ExpectedStatusCodes lists acceptable HTTP status codes
	ExpectedStatusCodes []int `yaml:"expected_status_codes,omitempty" json:"expected_status_codes,omitempty"`
}

// NewSaaSActionNode creates a new SaaS action workflow node
func NewSaaSActionNode(registry *ProviderRegistry) *SaaSActionNode {
	return &SaaSActionNode{
		BaseNode: &workflow.BaseNode{},
		registry: registry,
	}
}

// NewAPINode creates a new API workflow node
func NewAPINode(registry *ProviderRegistry) *APINode {
	return &APINode{
		BaseNode: &workflow.BaseNode{},
		registry: registry,
	}
}

// Execute implements the workflow.Node interface for SaaSActionNode
func (n *SaaSActionNode) Execute(ctx context.Context, input workflow.NodeInput) (workflow.NodeOutput, error) {
	// Get the provider
	provider, err := n.registry.GetProvider(n.Provider)
	if err != nil {
		if n.Config.IgnoreErrors {
			return workflow.NodeOutput{
				Success: false,
				Data:    make(map[string]interface{}),
				Error:   err.Error(),
			}, nil
		}
		return workflow.NodeOutput{}, fmt.Errorf("failed to get provider %s: %w", n.Provider, err)
	}

	// Initialize normalized operations if not already done
	if n.operations == nil {
		n.operations = NewNormalizedOperations(provider)
	}

	// Substitute variables in data, resource_id, and filters
	data, err := n.substituteVariables(n.Data, input.Data)
	if err != nil {
		return workflow.NodeOutput{}, fmt.Errorf("failed to substitute variables in data: %w", err)
	}

	resourceID, err := n.substituteString(n.ResourceID, input.Data)
	if err != nil {
		return workflow.NodeOutput{}, fmt.Errorf("failed to substitute variables in resource_id: %w", err)
	}

	filters, err := n.substituteVariables(n.Filters, input.Data)
	if err != nil {
		return workflow.NodeOutput{}, fmt.Errorf("failed to substitute variables in filters: %w", err)
	}

	// Execute the normalized operation
	var result *ProviderResult
	switch n.Operation {
	case "create":
		if dataMap, ok := data.(map[string]interface{}); ok {
			result, err = n.operations.Create(ctx, n.ResourceType, dataMap)
		} else {
			err = fmt.Errorf("data must be a map[string]interface{} for create operation")
		}
	case "read":
		result, err = n.operations.Read(ctx, n.ResourceType, resourceID)
	case "update":
		if dataMap, ok := data.(map[string]interface{}); ok {
			result, err = n.operations.Update(ctx, n.ResourceType, resourceID, dataMap)
		} else {
			err = fmt.Errorf("data must be a map[string]interface{} for update operation")
		}
	case "delete":
		result, err = n.operations.Delete(ctx, n.ResourceType, resourceID)
	case "list":
		if filtersMap, ok := filters.(map[string]interface{}); ok {
			result, err = n.operations.List(ctx, n.ResourceType, filtersMap)
		} else {
			err = fmt.Errorf("filters must be a map[string]interface{} for list operation")
		}
	default:
		err = fmt.Errorf("unsupported operation: %s", n.Operation)
	}

	if err != nil {
		if n.Config.IgnoreErrors {
			return workflow.NodeOutput{
				Success: false,
				Data:    make(map[string]interface{}),
				Error:   err.Error(),
			}, nil
		}
		return workflow.NodeOutput{}, fmt.Errorf("SaaS operation failed: %w", err)
	}

	// Apply output mapping if configured
	outputData := result.Data
	if len(n.Config.OutputMapping) > 0 {
		outputData = n.applyOutputMapping(result, n.Config.OutputMapping)
	}

	// Convert outputData to map[string]interface{} if needed
	var outputMap map[string]interface{}
	if dataMap, ok := outputData.(map[string]interface{}); ok {
		outputMap = dataMap
	} else {
		outputMap = make(map[string]interface{})
		outputMap["result"] = outputData
	}

	// Add status code to metadata
	metadata := make(map[string]interface{})
	if result.Metadata != nil {
		metadata = result.Metadata
	}
	metadata["status_code"] = result.StatusCode

	return workflow.NodeOutput{
		Success:  result.Success,
		Data:     outputMap,
		Metadata: metadata,
	}, nil
}

// Execute implements the workflow.Node interface for APINode
func (n *APINode) Execute(ctx context.Context, input workflow.NodeInput) (workflow.NodeOutput, error) {
	// Get the provider
	provider, err := n.registry.GetProvider(n.Provider)
	if err != nil {
		if n.Config.IgnoreErrors {
			return workflow.NodeOutput{
				Success: false,
				Data:    make(map[string]interface{}),
				Error:   err.Error(),
			}, nil
		}
		return workflow.NodeOutput{}, fmt.Errorf("failed to get provider %s: %w", n.Provider, err)
	}

	// Substitute variables in path and body
	path, err := n.substituteString(n.Path, input.Data)
	if err != nil {
		return workflow.NodeOutput{}, fmt.Errorf("failed to substitute variables in path: %w", err)
	}

	var body interface{}
	if n.Body != nil {
		body, err = n.substituteVariables(n.Body, input.Data)
		if err != nil {
			return workflow.NodeOutput{}, fmt.Errorf("failed to substitute variables in body: %w", err)
		}
	}

	// Execute the raw API call
	result, err := provider.RawAPI(ctx, n.Method, path, body)
	if err != nil {
		if n.Config.IgnoreErrors {
			return workflow.NodeOutput{
				Success: false,
				Data:    make(map[string]interface{}),
				Error:   err.Error(),
			}, nil
		}
		return workflow.NodeOutput{}, fmt.Errorf("API call failed: %w", err)
	}

	// Check if status code is expected
	if len(n.Config.ExpectedStatusCodes) > 0 {
		if !contains(convertToStringSlice(n.Config.ExpectedStatusCodes), fmt.Sprintf("%d", result.StatusCode)) {
			if n.Config.IgnoreErrors {
				// Convert result.Data to map[string]interface{}
				var outputMap map[string]interface{}
				if dataMap, ok := result.Data.(map[string]interface{}); ok {
					outputMap = dataMap
				} else {
					outputMap = make(map[string]interface{})
					outputMap["result"] = result.Data
				}

				// Add status code to metadata
				metadata := make(map[string]interface{})
				metadata["status_code"] = result.StatusCode

				return workflow.NodeOutput{
					Success:  false,
					Data:     outputMap,
					Error:    fmt.Sprintf("unexpected status code: %d", result.StatusCode),
					Metadata: metadata,
				}, nil
			}
			return workflow.NodeOutput{}, fmt.Errorf("unexpected status code: %d", result.StatusCode)
		}
	}

	// Apply response mapping if configured
	outputData := result.Data
	if len(n.Config.ResponseMapping) > 0 {
		outputData = n.applyResponseMapping(result, n.Config.ResponseMapping)
	}

	// Convert outputData to map[string]interface{} if needed
	var outputMap map[string]interface{}
	if dataMap, ok := outputData.(map[string]interface{}); ok {
		outputMap = dataMap
	} else {
		outputMap = make(map[string]interface{})
		outputMap["result"] = outputData
	}

	// Add status code and headers to metadata
	metadata := make(map[string]interface{})
	if result.Metadata != nil {
		metadata = result.Metadata
	}
	metadata["status_code"] = result.StatusCode
	if result.Headers != nil {
		metadata["headers"] = result.Headers
	}

	return workflow.NodeOutput{
		Success:  result.Success,
		Data:     outputMap,
		Metadata: metadata,
	}, nil
}

// GetType returns the node type for SaaSActionNode
func (n *SaaSActionNode) GetType() string {
	return "saas_action"
}

// GetType returns the node type for APINode
func (n *APINode) GetType() string {
	return "api"
}

// Validate validates the node configuration for SaaSActionNode
func (n *SaaSActionNode) Validate() error {
	if n.Provider == "" {
		return fmt.Errorf("provider is required")
	}

	if n.Operation == "" {
		return fmt.Errorf("operation is required")
	}

	if n.ResourceType == "" {
		return fmt.Errorf("resource_type is required")
	}

	// Validate operation-specific requirements
	switch n.Operation {
	case "read", "delete":
		if n.ResourceID == "" {
			return fmt.Errorf("resource_id is required for %s operation", n.Operation)
		}
	case "create":
		if len(n.Data) == 0 {
			return fmt.Errorf("data is required for %s operation", n.Operation)
		}
	case "update":
		if n.ResourceID == "" {
			return fmt.Errorf("resource_id is required for %s operation", n.Operation)
		}
		if len(n.Data) == 0 {
			return fmt.Errorf("data is required for %s operation", n.Operation)
		}
	}

	// Validate supported operations
	supportedOps := []string{"create", "read", "update", "delete", "list"}
	if !contains(supportedOps, n.Operation) {
		return fmt.Errorf("unsupported operation: %s", n.Operation)
	}

	return nil
}

// Validate validates the node configuration for APINode
func (n *APINode) Validate() error {
	if n.Provider == "" {
		return fmt.Errorf("provider is required")
	}

	if n.Method == "" {
		return fmt.Errorf("method is required")
	}

	if n.Path == "" {
		return fmt.Errorf("path is required")
	}

	// Validate HTTP method
	supportedMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	if !contains(supportedMethods, strings.ToUpper(n.Method)) {
		return fmt.Errorf("unsupported HTTP method: %s", n.Method)
	}

	return nil
}

// Helper methods for variable substitution

func (n *SaaSActionNode) substituteVariables(data interface{}, variables map[string]interface{}) (interface{}, error) {
	return substituteVariablesRecursive(data, variables)
}

func (n *SaaSActionNode) substituteString(str string, variables map[string]interface{}) (string, error) {
	if str == "" {
		return str, nil
	}

	result := str
	for key, value := range variables {
		placeholder := "${" + key + "}"
		result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%v", value))
	}

	return result, nil
}

func (n *APINode) substituteVariables(data interface{}, variables map[string]interface{}) (interface{}, error) {
	return substituteVariablesRecursive(data, variables)
}

func (n *APINode) substituteString(str string, variables map[string]interface{}) (string, error) {
	if str == "" {
		return str, nil
	}

	result := str
	for key, value := range variables {
		placeholder := "${" + key + "}"
		result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%v", value))
	}

	return result, nil
}

// substituteVariablesRecursive recursively substitutes variables in complex data structures
func substituteVariablesRecursive(data interface{}, variables map[string]interface{}) (interface{}, error) {
	switch v := data.(type) {
	case string:
		result := v
		for key, value := range variables {
			placeholder := "${" + key + "}"
			result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%v", value))
		}
		return result, nil

	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			substituted, err := substituteVariablesRecursive(value, variables)
			if err != nil {
				return nil, err
			}
			result[key] = substituted
		}
		return result, nil

	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			substituted, err := substituteVariablesRecursive(value, variables)
			if err != nil {
				return nil, err
			}
			result[i] = substituted
		}
		return result, nil

	default:
		// Return value as-is for other types
		return data, nil
	}
}

// applyOutputMapping applies output mapping configuration to results
func (n *SaaSActionNode) applyOutputMapping(result *ProviderResult, mapping map[string]string) map[string]interface{} {
	output := make(map[string]interface{})

	// Extract data from result based on mapping
	for outputKey, sourcePath := range mapping {
		value := extractValueByPath(result.Data, sourcePath)
		if value != nil {
			output[outputKey] = value
		}
	}

	return output
}

// applyResponseMapping applies response mapping configuration to API results
func (n *APINode) applyResponseMapping(result *ProviderResult, mapping map[string]string) map[string]interface{} {
	output := make(map[string]interface{})

	// Extract data from result based on mapping
	for outputKey, sourcePath := range mapping {
		value := extractValueByPath(result.Data, sourcePath)
		if value != nil {
			output[outputKey] = value
		}
	}

	return output
}

// extractValueByPath extracts a value from nested data using a dot-notation path
func extractValueByPath(data interface{}, path string) interface{} {
	if path == "" {
		return data
	}

	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var exists bool
			current, exists = v[part]
			if !exists {
				return nil
			}
		case []interface{}:
			// Handle array access (simplified)
			if part == "0" && len(v) > 0 {
				current = v[0]
			} else {
				return nil
			}
		default:
			return nil
		}
	}

	return current
}

// convertToStringSlice converts []int to []string for helper function compatibility
func convertToStringSlice(ints []int) []string {
	strings := make([]string, len(ints))
	for i, v := range ints {
		strings[i] = fmt.Sprintf("%d", v)
	}
	return strings
}

// WorkflowNodeFactory creates workflow nodes for SaaS operations
type WorkflowNodeFactory struct {
	registry *ProviderRegistry
}

// NewWorkflowNodeFactory creates a new workflow node factory
func NewWorkflowNodeFactory(registry *ProviderRegistry) *WorkflowNodeFactory {
	return &WorkflowNodeFactory{
		registry: registry,
	}
}

// CreateNode creates a workflow node of the specified type
func (f *WorkflowNodeFactory) CreateNode(nodeType string, config map[string]interface{}) (workflow.Node, error) {
	switch nodeType {
	case "saas_action":
		node := NewSaaSActionNode(f.registry)
		if err := f.configureNode(node, config); err != nil {
			return nil, fmt.Errorf("failed to configure saas_action node: %w", err)
		}
		return node, nil

	case "api":
		node := NewAPINode(f.registry)
		if err := f.configureNode(node, config); err != nil {
			return nil, fmt.Errorf("failed to configure api node: %w", err)
		}
		return node, nil

	default:
		return nil, fmt.Errorf("unsupported node type: %s", nodeType)
	}
}

// configureNode configures a node with the provided configuration
func (f *WorkflowNodeFactory) configureNode(node interface{}, config map[string]interface{}) error {
	// Convert config to JSON and back to populate the struct
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := json.Unmarshal(configJSON, node); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

// RegisterWorkflowNodes registers SaaS workflow nodes with the workflow engine
// Note: This function is disabled until workflow.Engine.RegisterNodeType is implemented
func RegisterWorkflowNodes(engine interface{}, registry *ProviderRegistry) error {
	// factory := NewWorkflowNodeFactory(registry)

	// TODO: Implement when workflow.Engine.RegisterNodeType is available
	// engine.RegisterNodeType("saas_action", func(config map[string]interface{}) (workflow.Node, error) {
	//	return factory.CreateNode("saas_action", config)
	// })

	// engine.RegisterNodeType("api", func(config map[string]interface{}) (workflow.Node, error) {
	//	return factory.CreateNode("api", config)
	// })

	return nil
}

// SaaSWorkflowHelper provides utility functions for SaaS workflows
type SaaSWorkflowHelper struct {
	registry *ProviderRegistry
}

// NewSaaSWorkflowHelper creates a new SaaS workflow helper
func NewSaaSWorkflowHelper(registry *ProviderRegistry) *SaaSWorkflowHelper {
	return &SaaSWorkflowHelper{
		registry: registry,
	}
}

// ValidateWorkflow validates a workflow containing SaaS operations
func (h *SaaSWorkflowHelper) ValidateWorkflow(workflowDef map[string]interface{}) error {
	steps, exists := workflowDef["steps"].([]interface{})
	if !exists {
		return fmt.Errorf("workflow must contain steps")
	}

	for i, step := range steps {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			return fmt.Errorf("step %d is not a valid object", i)
		}

		nodeType, exists := stepMap["type"].(string)
		if !exists {
			return fmt.Errorf("step %d missing type", i)
		}

		switch nodeType {
		case "saas_action":
			if err := h.validateSaaSActionStep(stepMap); err != nil {
				return fmt.Errorf("invalid saas_action step %d: %w", i, err)
			}
		case "api":
			if err := h.validateAPIStep(stepMap); err != nil {
				return fmt.Errorf("invalid api step %d: %w", i, err)
			}
		}
	}

	return nil
}

func (h *SaaSWorkflowHelper) validateSaaSActionStep(step map[string]interface{}) error {
	provider, exists := step["provider"].(string)
	if !exists || provider == "" {
		return fmt.Errorf("provider is required")
	}

	if !h.registry.HasProvider(provider) {
		return fmt.Errorf("provider %s is not registered", provider)
	}

	operation, exists := step["operation"].(string)
	if !exists || operation == "" {
		return fmt.Errorf("operation is required")
	}

	resourceType, exists := step["resource_type"].(string)
	if !exists || resourceType == "" {
		return fmt.Errorf("resource_type is required")
	}

	return nil
}

func (h *SaaSWorkflowHelper) validateAPIStep(step map[string]interface{}) error {
	provider, exists := step["provider"].(string)
	if !exists || provider == "" {
		return fmt.Errorf("provider is required")
	}

	if !h.registry.HasProvider(provider) {
		return fmt.Errorf("provider %s is not registered", provider)
	}

	method, exists := step["method"].(string)
	if !exists || method == "" {
		return fmt.Errorf("method is required")
	}

	path, exists := step["path"].(string)
	if !exists || path == "" {
		return fmt.Errorf("path is required")
	}

	return nil
}
