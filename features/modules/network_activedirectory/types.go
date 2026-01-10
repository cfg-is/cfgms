// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package network_activedirectory

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
)

// ADModuleConfig represents the configuration for Active Directory module operations
type ADModuleConfig struct {
	// Connection settings
	DomainController string `yaml:"domain_controller,omitempty"` // Specific DC, or auto-discover
	Domain           string `yaml:"domain"`                      // AD domain name
	Port             int    `yaml:"port,omitempty"`              // LDAP port (389/636)
	UseTLS           bool   `yaml:"use_tls"`                     // Use LDAPS

	// Multi-domain and multi-forest support
	TrustedDomains  []string `yaml:"trusted_domains,omitempty"`   // List of trusted domain names
	ForestRoot      string   `yaml:"forest_root,omitempty"`       // Forest root domain
	GlobalCatalogDC string   `yaml:"global_catalog_dc,omitempty"` // Global Catalog DC for forest searches
	CrossDomainAuth bool     `yaml:"cross_domain_auth"`           // Enable cross-domain authentication

	// Authentication
	AuthMethod string `yaml:"auth_method"`        // "kerberos", "ntlm", "simple"
	Username   string `yaml:"username,omitempty"` // Service account username
	Password   string `yaml:"password,omitempty"` // Service account password

	// Search configuration
	SearchBase string `yaml:"search_base,omitempty"` // Base DN for searches
	PageSize   int    `yaml:"page_size,omitempty"`   // LDAP page size

	// Operation settings
	OperationType string   `yaml:"operation_type"` // "read", "read_write"
	ObjectTypes   []string `yaml:"object_types"`   // Which object types to manage

	// Performance settings
	MaxConnections int           `yaml:"max_connections,omitempty"` // Connection pool size
	RequestTimeout time.Duration `yaml:"request_timeout,omitempty"` // Request timeout

	// Managed fields - controls which fields Set() will modify
	ManagedFieldsList []string `yaml:"managed_fields,omitempty"`
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *ADModuleConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"domain":         c.Domain,
		"use_tls":        c.UseTLS,
		"auth_method":    c.AuthMethod,
		"operation_type": c.OperationType,
		"object_types":   c.ObjectTypes,
	}

	if c.DomainController != "" {
		result["domain_controller"] = c.DomainController
	}
	if c.Port > 0 {
		result["port"] = c.Port
	}
	if c.Username != "" {
		result["username"] = c.Username
	}
	if c.SearchBase != "" {
		result["search_base"] = c.SearchBase
	}
	if c.PageSize > 0 {
		result["page_size"] = c.PageSize
	}
	if c.MaxConnections > 0 {
		result["max_connections"] = c.MaxConnections
	}
	if c.RequestTimeout > 0 {
		result["request_timeout"] = c.RequestTimeout
	}
	if len(c.TrustedDomains) > 0 {
		result["trusted_domains"] = c.TrustedDomains
	}
	if c.ForestRoot != "" {
		result["forest_root"] = c.ForestRoot
	}
	if c.GlobalCatalogDC != "" {
		result["global_catalog_dc"] = c.GlobalCatalogDC
	}
	if c.CrossDomainAuth {
		result["cross_domain_auth"] = c.CrossDomainAuth
	}

	return result
}

// ToYAML serializes the configuration to YAML
func (c *ADModuleConfig) ToYAML() ([]byte, error) {
	// Create a copy without sensitive fields for serialization
	safe := *c
	safe.Password = "[REDACTED]"
	return yaml.Marshal(safe)
}

// FromYAML deserializes YAML data into the configuration
func (c *ADModuleConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *ADModuleConfig) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}

	if c.AuthMethod == "" {
		return fmt.Errorf("auth_method is required")
	}

	if c.AuthMethod != "kerberos" && c.AuthMethod != "ntlm" && c.AuthMethod != "simple" {
		return fmt.Errorf("invalid auth_method: %s (must be 'kerberos', 'ntlm', or 'simple')", c.AuthMethod)
	}

	if c.OperationType == "" {
		return fmt.Errorf("operation_type is required")
	}

	if c.OperationType != "read" && c.OperationType != "read_write" {
		return fmt.Errorf("invalid operation_type: %s (must be 'read' or 'read_write')", c.OperationType)
	}

	if len(c.ObjectTypes) == 0 {
		return fmt.Errorf("at least one object_type must be specified")
	}

	// Validate object types
	validTypes := map[string]bool{
		"user":                true,
		"group":               true,
		"organizational_unit": true,
		"computer":            true,
		"gpo":                 true,
		"group_policy":        true,
		"domain_trust":        true,
		"trust":               true,
	}

	for _, objType := range c.ObjectTypes {
		if !validTypes[objType] {
			return fmt.Errorf("invalid object_type: %s", objType)
		}
	}

	return nil
}

// GetManagedFields returns the list of fields this configuration manages
func (c *ADModuleConfig) GetManagedFields() []string {
	if len(c.ManagedFieldsList) > 0 {
		return c.ManagedFieldsList
	}

	// Default managed fields
	fields := []string{
		"domain",
		"auth_method",
		"operation_type",
		"object_types",
	}

	if c.DomainController != "" {
		fields = append(fields, "domain_controller")
	}
	if c.SearchBase != "" {
		fields = append(fields, "search_base")
	}

	return fields
}

// ADQueryResult represents the result of an AD query operation
type ADQueryResult struct {
	// Query metadata
	QueryType    string        `json:"query_type"`    // "user", "group", "ou", "computer"
	ObjectID     string        `json:"object_id"`     // Requested object ID
	Success      bool          `json:"success"`       // Whether query succeeded
	ExecutedAt   time.Time     `json:"executed_at"`   // When query was executed
	ResponseTime time.Duration `json:"response_time"` // How long query took

	// Results
	User           *interfaces.DirectoryUser       `json:"user,omitempty"`
	Group          *interfaces.DirectoryGroup      `json:"group,omitempty"`
	OU             *interfaces.OrganizationalUnit  `json:"ou,omitempty"`
	Users          []interfaces.DirectoryUser      `json:"users,omitempty"`
	Groups         []interfaces.DirectoryGroup     `json:"groups,omitempty"`
	OUs            []interfaces.OrganizationalUnit `json:"ous,omitempty"`
	GenericObject  *interfaces.DirectoryUser       `json:"generic_object,omitempty"`
	GenericObjects []map[string]interface{}        `json:"generic_objects,omitempty"`

	// Pagination
	TotalCount int    `json:"total_count"`          // Total available results
	HasMore    bool   `json:"has_more"`             // More results available
	NextToken  string `json:"next_token,omitempty"` // Pagination token

	// Error information
	Error     string `json:"error,omitempty"`      // Error message if failed
	ErrorCode string `json:"error_code,omitempty"` // Specific error code
}

// AsMap implements modules.ConfigState interface
func (r *ADQueryResult) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"query_type":    r.QueryType,
		"object_id":     r.ObjectID,
		"success":       r.Success,
		"executed_at":   r.ExecutedAt,
		"response_time": r.ResponseTime,
		"total_count":   r.TotalCount,
		"has_more":      r.HasMore,
	}

	if r.NextToken != "" {
		result["next_token"] = r.NextToken
	}
	if r.Error != "" {
		result["error"] = r.Error
	}
	if r.ErrorCode != "" {
		result["error_code"] = r.ErrorCode
	}

	// Add result objects
	if r.User != nil {
		result["user"] = r.User
	}
	if r.Group != nil {
		result["group"] = r.Group
	}
	if r.OU != nil {
		result["ou"] = r.OU
	}
	if len(r.Users) > 0 {
		result["users"] = r.Users
	}
	if len(r.Groups) > 0 {
		result["groups"] = r.Groups
	}
	if len(r.OUs) > 0 {
		result["ous"] = r.OUs
	}
	if r.GenericObject != nil {
		result["generic_object"] = r.GenericObject
	}
	if len(r.GenericObjects) > 0 {
		result["generic_objects"] = r.GenericObjects
	}

	return result
}

// ToYAML implements modules.ConfigState interface
func (r *ADQueryResult) ToYAML() ([]byte, error) {
	return yaml.Marshal(r)
}

// FromYAML implements modules.ConfigState interface
func (r *ADQueryResult) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, r)
}

// Validate implements modules.ConfigState interface
func (r *ADQueryResult) Validate() error {
	return nil // Query results don't need validation
}

// GetManagedFields implements modules.ConfigState interface
func (r *ADQueryResult) GetManagedFields() []string {
	return []string{} // Query results are read-only
}

// ADConnectionStatus represents the status of the AD connection
type ADConnectionStatus struct {
	Connected        bool          `json:"connected"`
	DomainController string        `json:"domain_controller"` // Which DC we're connected to
	Domain           string        `json:"domain"`
	AuthMethod       string        `json:"auth_method"`
	ConnectedSince   time.Time     `json:"connected_since"`
	LastHealthCheck  time.Time     `json:"last_health_check"`
	HealthStatus     string        `json:"health_status"` // "healthy", "degraded", "unhealthy"
	ResponseTime     time.Duration `json:"response_time"` // Latest response time
	ErrorCount       int64         `json:"error_count"`   // Recent error count
	RequestCount     int64         `json:"request_count"` // Total request count
}

// AsMap implements modules.ConfigState interface
func (s *ADConnectionStatus) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"connected":         s.Connected,
		"domain_controller": s.DomainController,
		"domain":            s.Domain,
		"auth_method":       s.AuthMethod,
		"connected_since":   s.ConnectedSince,
		"last_health_check": s.LastHealthCheck,
		"health_status":     s.HealthStatus,
		"response_time":     s.ResponseTime,
		"error_count":       s.ErrorCount,
		"request_count":     s.RequestCount,
	}
}

// ToYAML implements modules.ConfigState interface
func (s *ADConnectionStatus) ToYAML() ([]byte, error) {
	return yaml.Marshal(s)
}

// FromYAML implements modules.ConfigState interface
func (s *ADConnectionStatus) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, s)
}

// Validate implements modules.ConfigState interface
func (s *ADConnectionStatus) Validate() error {
	return nil // Status objects don't need validation
}

// GetManagedFields implements modules.ConfigState interface
func (s *ADConnectionStatus) GetManagedFields() []string {
	return []string{} // Status is read-only
}

// ADOperationLog represents a log entry for AD operations
type ADOperationLog struct {
	Timestamp    time.Time     `json:"timestamp"`
	Operation    string        `json:"operation"` // "get_user", "list_groups", etc.
	ObjectID     string        `json:"object_id"` // Target object ID
	Success      bool          `json:"success"`
	ResponseTime time.Duration `json:"response_time"`
	Error        string        `json:"error,omitempty"`
	UserContext  string        `json:"user_context"` // Who initiated the operation
}
