package network_activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ActiveDirectoryProvider implements the DirectoryProvider interface for Active Directory
// by communicating with AD stewards via gRPC
type ActiveDirectoryProvider struct {
	logger logging.Logger

	// Configuration
	config    interfaces.ProviderConfig
	connected bool
	connMux   sync.RWMutex

	// Steward communication
	stewardClient StewardClient // Interface for gRPC communication

	// Statistics
	stats struct {
		sync.RWMutex
		requestCount int64
		errorCount   int64
		lastRequest  time.Time
		connectedAt  time.Time
		totalLatency time.Duration
	}
}

// StewardClient defines the interface for communicating with AD stewards
// This would be implemented by the actual gRPC client
type StewardClient interface {
	// Module operations via steward gRPC API
	GetModuleState(ctx context.Context, stewardID, moduleType, resourceID string) (map[string]interface{}, error)
	SetModuleConfig(ctx context.Context, stewardID, moduleType, resourceID string, config map[string]interface{}) error

	// Steward discovery and health
	GetConnectedStewards(ctx context.Context) ([]StewardInfo, error)
	GetStewardHealth(ctx context.Context, stewardID string) (*StewardHealth, error)
}

// StewardInfo represents information about a connected steward
type StewardInfo struct {
	ID        string            `json:"id"`
	Hostname  string            `json:"hostname"`
	Platform  string            `json:"platform"`
	Version   string            `json:"version"`
	Modules   []string          `json:"modules"`
	Tags      map[string]string `json:"tags"`
	LastSeen  time.Time         `json:"last_seen"`
	IsHealthy bool              `json:"is_healthy"`
}

// StewardHealth represents the health status of a steward
type StewardHealth struct {
	Status      string            `json:"status"`
	LastCheck   time.Time         `json:"last_check"`
	Modules     map[string]string `json:"modules"` // module -> status
	Uptime      time.Duration     `json:"uptime"`
	CPUUsage    float64           `json:"cpu_usage"`
	MemoryUsage float64           `json:"memory_usage"`
}

// NewActiveDirectoryProvider creates a new Active Directory provider
func NewActiveDirectoryProvider(stewardClient StewardClient, logger logging.Logger) *ActiveDirectoryProvider {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}

	return &ActiveDirectoryProvider{
		logger:        logger,
		stewardClient: stewardClient,
	}
}

// GetProviderInfo returns information about this provider
func (p *ActiveDirectoryProvider) GetProviderInfo() interfaces.ProviderInfo {
	return interfaces.ProviderInfo{
		Name:        "network_activedirectory",
		DisplayName: "Network Active Directory",
		Version:     "1.0.0",
		Description: "Network-based Microsoft Active Directory provider with LDAP support for remote AD management (future Outpost component)",
		SupportedTypes: []interfaces.DirectoryObjectType{
			interfaces.DirectoryObjectTypeUser,
			interfaces.DirectoryObjectTypeGroup,
			interfaces.DirectoryObjectTypeOU,
		},
		Capabilities: interfaces.ProviderCapabilities{
			SupportsUserManagement:     true,
			SupportsGroupManagement:    true,
			SupportsOUManagement:       true,
			SupportsBulkOperations:     true,
			SupportsAdvancedSearch:     true,
			SupportsCrossDirectorySync: true,
			SupportsRealTimeSync:       false, // Not yet implemented
			SupportedAuthMethods: []interfaces.AuthMethod{
				interfaces.AuthMethodKerberos,
				interfaces.AuthMethodLDAP,
			},
			MaxSearchResults:     10000,
			SupportedSearchTypes: []string{"user", "group", "organizational_unit", "computer"},
			RateLimitInfo: &interfaces.RateLimitInfo{
				RequestsPerSecond: 100,
				RequestsPerMinute: 5000,
				RequestsPerHour:   50000,
				BurstSize:         50,
				BackoffStrategy:   "exponential",
			},
		},
		Configuration: interfaces.ConfigurationSchema{
			Required: []interfaces.ConfigField{
				{Name: "server_address", Type: "string", Description: "Domain controller address or domain name", Required: true},
				{Name: "auth_method", Type: "string", Description: "Authentication method", Required: true, ValidValues: []string{"kerberos", "ldap"}},
			},
			Optional: []interfaces.ConfigField{
				{Name: "port", Type: "int", Description: "LDAP port", DefaultValue: 389},
				{Name: "use_tls", Type: "bool", Description: "Use LDAPS", DefaultValue: false},
				{Name: "username", Type: "string", Description: "Service account username"},
				{Name: "password", Type: "string", Description: "Service account password"},
				{Name: "search_base", Type: "string", Description: "Base DN for searches"},
				{Name: "page_size", Type: "int", Description: "LDAP page size", DefaultValue: 100},
			},
		},
		Documentation: "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/",
	}
}

// Connect establishes connection to Active Directory via steward
func (p *ActiveDirectoryProvider) Connect(ctx context.Context, config interfaces.ProviderConfig) error {
	p.connMux.Lock()
	defer p.connMux.Unlock()

	p.logger.Info("Connecting to Active Directory",
		"domain", config.ServerAddress,
		"auth_method", config.AuthMethod)

	// Find steward that can handle AD operations
	stewardID, err := p.findADSteward(ctx, config.ServerAddress)
	if err != nil {
		return fmt.Errorf("failed to find AD steward: %w", err)
	}

	p.logger.Debug("Found AD steward", "steward_id", stewardID)

	// Configure the AD module on the steward
	moduleConfig := map[string]interface{}{
		"domain":         config.ServerAddress,
		"auth_method":    string(config.AuthMethod),
		"operation_type": "read", // Start with read-only
		"object_types":   []string{"user", "group", "organizational_unit"},
		"use_tls":        config.UseTLS,
		"username":       config.Username,
		"password":       config.Password,
	}

	if config.Port > 0 {
		moduleConfig["port"] = config.Port
	}
	if config.PageSize > 0 {
		moduleConfig["page_size"] = config.PageSize
	}
	if config.MaxConnections > 0 {
		moduleConfig["max_connections"] = config.MaxConnections
	}
	if config.ConnectionTimeout > 0 {
		moduleConfig["request_timeout"] = config.ConnectionTimeout
	}

	// Set module configuration on steward
	err = p.stewardClient.SetModuleConfig(ctx, stewardID, "activedirectory", "connection", moduleConfig)
	if err != nil {
		return fmt.Errorf("failed to configure AD module on steward: %w", err)
	}

	// Test the connection by getting status
	statusResult, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", "status")
	if err != nil {
		return fmt.Errorf("failed to verify AD connection: %w", err)
	}

	// Parse status result
	if status, ok := statusResult["connected"]; !ok || !status.(bool) {
		return fmt.Errorf("AD connection failed on steward")
	}

	p.config = config
	p.connected = true

	p.stats.Lock()
	p.stats.connectedAt = time.Now()
	p.stats.Unlock()

	p.logger.Info("Successfully connected to Active Directory",
		"steward_id", stewardID,
		"domain", config.ServerAddress)

	return nil
}

// Disconnect closes the connection to Active Directory
func (p *ActiveDirectoryProvider) Disconnect(ctx context.Context) error {
	p.connMux.Lock()
	defer p.connMux.Unlock()

	if !p.connected {
		return nil
	}

	p.connected = false
	p.logger.Info("Disconnected from Active Directory")

	return nil
}

// IsConnected returns whether the provider is connected
func (p *ActiveDirectoryProvider) IsConnected(ctx context.Context) bool {
	p.connMux.RLock()
	defer p.connMux.RUnlock()
	return p.connected
}

// HealthCheck performs a health check of the AD connection
func (p *ActiveDirectoryProvider) HealthCheck(ctx context.Context) (*interfaces.HealthStatus, error) {
	p.connMux.RLock()
	connected := p.connected
	config := p.config
	p.connMux.RUnlock()

	status := &interfaces.HealthStatus{
		IsHealthy: false,
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}

	if !connected {
		status.Errors = []string{"not connected to Active Directory"}
		return status, nil
	}

	// Find AD steward
	stewardID, err := p.findADSteward(ctx, config.ServerAddress)
	if err != nil {
		status.Errors = []string{fmt.Sprintf("AD steward not available: %v", err)}
		return status, nil
	}

	start := time.Now()

	// Check steward health
	stewardHealth, err := p.stewardClient.GetStewardHealth(ctx, stewardID)
	if err != nil {
		status.Errors = []string{fmt.Sprintf("failed to check steward health: %v", err)}
		return status, nil
	}

	// Check AD module health on steward
	statusResult, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", "status")
	if err != nil {
		status.Errors = []string{fmt.Sprintf("failed to check AD module status: %v", err)}
		return status, nil
	}

	status.ResponseTime = time.Since(start)

	// Parse AD module status
	if healthStr, ok := statusResult["health_status"]; ok {
		if healthStr == "healthy" {
			status.IsHealthy = true
		} else {
			status.Errors = []string{fmt.Sprintf("AD module health: %s", healthStr)}
		}
	}

	// Add steward and module details
	status.Details["steward_id"] = stewardID
	status.Details["steward_status"] = stewardHealth.Status
	status.Details["ad_module_status"] = statusResult["health_status"]
	status.Details["domain_controller"] = statusResult["domain_controller"]
	status.Details["request_count"] = statusResult["request_count"]
	status.Details["error_count"] = statusResult["error_count"]

	return status, nil
}

// findADSteward finds a steward that can handle AD operations for the given domain
func (p *ActiveDirectoryProvider) findADSteward(ctx context.Context, domain string) (string, error) {
	stewards, err := p.stewardClient.GetConnectedStewards(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get connected stewards: %w", err)
	}

	// Look for stewards with activedirectory module that can handle this domain
	for _, steward := range stewards {
		// Check if steward has activedirectory module
		hasADModule := false
		for _, module := range steward.Modules {
			if module == "activedirectory" {
				hasADModule = true
				break
			}
		}

		if !hasADModule {
			continue
		}

		// Check if steward is healthy
		if !steward.IsHealthy {
			continue
		}

		// Check if steward can handle this domain (via tags or hostname)
		if p.stewardCanHandleDomain(steward, domain) {
			return steward.ID, nil
		}
	}

	return "", fmt.Errorf("no suitable AD steward found for domain %s", domain)
}

// stewardCanHandleDomain determines if a steward can handle the specified domain
func (p *ActiveDirectoryProvider) stewardCanHandleDomain(steward StewardInfo, domain string) bool {
	// Check steward tags for domain assignment
	if stewardDomain, exists := steward.Tags["ad_domain"]; exists {
		return strings.EqualFold(stewardDomain, domain)
	}

	// Check if steward hostname suggests it's in the target domain
	if strings.Contains(steward.Hostname, ".") {
		stewardDomain := strings.SplitN(steward.Hostname, ".", 2)[1]
		if strings.EqualFold(stewardDomain, domain) {
			return true
		}
	}

	// Default: assume steward can handle any domain if no specific assignment
	return true
}

// executeADQuery executes a query on the AD steward and returns the result
func (p *ActiveDirectoryProvider) executeADQuery(ctx context.Context, resourceID string) (map[string]interface{}, error) {
	p.connMux.RLock()
	connected := p.connected
	config := p.config
	p.connMux.RUnlock()

	if !connected {
		return nil, fmt.Errorf("not connected to Active Directory")
	}

	// Find AD steward
	stewardID, err := p.findADSteward(ctx, config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("no AD steward available: %w", err)
	}

	// Update stats
	p.stats.Lock()
	p.stats.requestCount++
	p.stats.lastRequest = time.Now()
	p.stats.Unlock()

	start := time.Now()

	// Execute query via steward
	result, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)

	// Update latency stats
	latency := time.Since(start)
	p.stats.Lock()
	p.stats.totalLatency += latency
	if err != nil {
		p.stats.errorCount++
	}
	p.stats.Unlock()

	if err != nil {
		return nil, fmt.Errorf("AD query failed: %w", err)
	}

	p.logger.Debug("AD query completed",
		"resource_id", resourceID,
		"steward_id", stewardID,
		"latency", latency)

	return result, nil
}

// updateStats updates provider statistics
func (p *ActiveDirectoryProvider) updateStats(success bool, latency time.Duration) {
	p.stats.Lock()
	defer p.stats.Unlock()

	p.stats.requestCount++
	p.stats.lastRequest = time.Now()
	p.stats.totalLatency += latency

	if !success {
		p.stats.errorCount++
	}
}

// convertToDirectoryUser converts various object types to DirectoryUser interface
func (p *ActiveDirectoryProvider) convertToDirectoryUser(obj interface{}) (*interfaces.DirectoryUser, error) {
	// Convert interface{} to map
	objMap, ok := obj.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid object format - expected map")
	}

	// Extract common fields
	user := &interfaces.DirectoryUser{
		ProviderAttributes: make(map[string]interface{}),
	}

	// Extract fields with type assertion
	if id, ok := objMap["id"].(string); ok {
		user.ID = id
	}
	if upn, ok := objMap["user_principal_name"].(string); ok {
		user.UserPrincipalName = upn
	}
	if sam, ok := objMap["sam_account_name"].(string); ok {
		user.SAMAccountName = sam
	}
	if display, ok := objMap["display_name"].(string); ok {
		user.DisplayName = display
	}
	if email, ok := objMap["email_address"].(string); ok {
		user.EmailAddress = email
	}
	if enabled, ok := objMap["account_enabled"].(bool); ok {
		user.AccountEnabled = enabled
	}
	if dn, ok := objMap["distinguished_name"].(string); ok {
		user.DistinguishedName = dn
	}
	if source, ok := objMap["source"].(string); ok {
		user.Source = source
	}

	// Copy all other attributes to ProviderAttributes
	for key, value := range objMap {
		processed := map[string]bool{
			"id": true, "user_principal_name": true, "sam_account_name": true,
			"display_name": true, "email_address": true, "account_enabled": true,
			"distinguished_name": true, "source": true,
		}

		if !processed[key] {
			user.ProviderAttributes[key] = value
		}
	}

	return user, nil
}

// parseADQueryResult parses the result from AD module into DirectoryProvider types
func (p *ActiveDirectoryProvider) parseADQueryResult(result map[string]interface{}) (*ADModuleQueryResult, error) {
	// Convert map back to structured result
	resultData, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query result: %w", err)
	}

	var queryResult ADModuleQueryResult
	if err := json.Unmarshal(resultData, &queryResult); err != nil {
		return nil, fmt.Errorf("failed to unmarshal query result: %w", err)
	}

	return &queryResult, nil
}

// ADModuleQueryResult represents the result structure from the AD module
type ADModuleQueryResult struct {
	QueryType    string        `json:"query_type"`
	ObjectID     string        `json:"object_id"`
	Success      bool          `json:"success"`
	ExecutedAt   time.Time     `json:"executed_at"`
	ResponseTime time.Duration `json:"response_time"`
	TotalCount   int           `json:"total_count"`
	HasMore      bool          `json:"has_more"`
	NextToken    string        `json:"next_token,omitempty"`
	Error        string        `json:"error,omitempty"`
	ErrorCode    string        `json:"error_code,omitempty"`

	// Results (these come from the module's ADQueryResult)
	User   *interfaces.DirectoryUser       `json:"user,omitempty"`
	Group  *interfaces.DirectoryGroup      `json:"group,omitempty"`
	OU     *interfaces.OrganizationalUnit  `json:"ou,omitempty"`
	Users  []interfaces.DirectoryUser      `json:"users,omitempty"`
	Groups []interfaces.DirectoryGroup     `json:"groups,omitempty"`
	OUs    []interfaces.OrganizationalUnit `json:"ous,omitempty"`
}

// init registers this provider with the global factory
func init() {
	interfaces.RegisterDirectoryProviderConstructor("network_activedirectory", func() interfaces.DirectoryProvider {
		// In a real implementation, this would get the steward client from a registry
		// For now, return a provider that will need to be configured with a client
		return &ActiveDirectoryProvider{
			logger: logging.NewNoopLogger(),
		}
	})
}
