// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/security"
)

// ADModuleConfig represents the configuration for the system-context AD module
type ADModuleConfig struct {
	OperationType       string        `json:"operation_type" yaml:"operation_type"`
	ObjectTypes         []string      `json:"object_types" yaml:"object_types"`
	SearchBase          string        `json:"search_base,omitempty" yaml:"search_base,omitempty"`
	PageSize            int           `json:"page_size" yaml:"page_size"`
	RequestTimeout      time.Duration `json:"request_timeout" yaml:"request_timeout"`
	EnableDNACollection bool          `json:"enable_dna_collection" yaml:"enable_dna_collection"`
}

// Validate validates the AD module configuration
func (c *ADModuleConfig) Validate() error {
	if c.OperationType == "" {
		return fmt.Errorf("operation_type is required")
	}
	if len(c.ObjectTypes) == 0 {
		return fmt.Errorf("at least one object_type is required")
	}
	if c.PageSize < 0 {
		return fmt.Errorf("page_size must be non-negative")
	}
	if c.RequestTimeout < 0 {
		return fmt.Errorf("request_timeout must be non-negative")
	}
	return nil
}

// AsMap implements the ConfigState interface
func (c *ADModuleConfig) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"operation_type":        c.OperationType,
		"object_types":          c.ObjectTypes,
		"search_base":           c.SearchBase,
		"page_size":             c.PageSize,
		"request_timeout":       c.RequestTimeout,
		"enable_dna_collection": c.EnableDNACollection,
	}
}

// GetManagedFields returns the fields that this module can modify
func (c *ADModuleConfig) GetManagedFields() []string {
	return []string{"operation_type", "object_types", "search_base", "page_size", "request_timeout", "enable_dna_collection"}
}

// ToYAML serializes the configuration to YAML
func (c *ADModuleConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *ADModuleConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// ADSystemStatus represents the current status of the system-context AD module
type ADSystemStatus struct {
	SystemContext      bool      `json:"system_context"`
	Hostname           string    `json:"hostname"`
	Domain             string    `json:"domain"`
	DomainController   string    `json:"domain_controller"`
	ForestRoot         string    `json:"forest_root"`
	HealthStatus       string    `json:"health_status"`
	Error              string    `json:"error,omitempty"`
	RequestCount       int64     `json:"request_count"`
	ErrorCount         int64     `json:"error_count"`
	LastHealthCheck    time.Time `json:"last_health_check"`
	DNACollectionCount int64     `json:"dna_collection_count"`
	LastDNACollection  time.Time `json:"last_dna_collection"`
}

// AsMap implements the ConfigState interface
func (s *ADSystemStatus) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"system_context":       s.SystemContext,
		"hostname":             s.Hostname,
		"domain":               s.Domain,
		"domain_controller":    s.DomainController,
		"forest_root":          s.ForestRoot,
		"health_status":        s.HealthStatus,
		"error":                s.Error,
		"request_count":        s.RequestCount,
		"error_count":          s.ErrorCount,
		"last_health_check":    s.LastHealthCheck,
		"dna_collection_count": s.DNACollectionCount,
		"last_dna_collection":  s.LastDNACollection,
	}
}

// GetManagedFields returns the fields that this status object tracks
func (s *ADSystemStatus) GetManagedFields() []string {
	return []string{"system_context", "hostname", "domain", "domain_controller", "forest_root", "health_status", "request_count", "error_count"}
}

// ToYAML serializes the status to YAML
func (s *ADSystemStatus) ToYAML() ([]byte, error) {
	return yaml.Marshal(s)
}

// FromYAML deserializes YAML data into the status
func (s *ADSystemStatus) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, s)
}

// Validate validates the status object
func (s *ADSystemStatus) Validate() error {
	return nil // Status objects don't need validation
}

// ADQueryResult represents the result of an AD query operation
type ADQueryResult struct {
	QueryType    string                          `json:"query_type"`
	ObjectID     string                          `json:"object_id,omitempty"`
	ExecutedAt   time.Time                       `json:"executed_at"`
	ResponseTime time.Duration                   `json:"response_time"`
	Success      bool                            `json:"success"`
	Error        string                          `json:"error,omitempty"`
	TotalCount   int                             `json:"total_count,omitempty"`
	User         *interfaces.DirectoryUser       `json:"user,omitempty"`
	Users        []interfaces.DirectoryUser      `json:"users,omitempty"`
	Group        *interfaces.DirectoryGroup      `json:"group,omitempty"`
	Groups       []interfaces.DirectoryGroup     `json:"groups,omitempty"`
	OU           *interfaces.OrganizationalUnit  `json:"ou,omitempty"`
	OUs          []interfaces.OrganizationalUnit `json:"ous,omitempty"`
}

// AsMap implements the ConfigState interface
func (r *ADQueryResult) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"query_type":    r.QueryType,
		"object_id":     r.ObjectID,
		"executed_at":   r.ExecutedAt,
		"response_time": r.ResponseTime,
		"success":       r.Success,
		"error":         r.Error,
		"total_count":   r.TotalCount,
	}

	if r.User != nil {
		result["user"] = r.User
	}
	if len(r.Users) > 0 {
		result["users"] = r.Users
	}
	if r.Group != nil {
		result["group"] = r.Group
	}
	if len(r.Groups) > 0 {
		result["groups"] = r.Groups
	}
	if r.OU != nil {
		result["ou"] = r.OU
	}
	if len(r.OUs) > 0 {
		result["ous"] = r.OUs
	}

	return result
}

// GetManagedFields returns the fields that this result object tracks
func (r *ADQueryResult) GetManagedFields() []string {
	return []string{"query_type", "object_id", "executed_at", "response_time", "success", "error", "total_count", "user", "users", "group", "groups", "ou", "ous"}
}

// ToYAML serializes the query result to YAML
func (r *ADQueryResult) ToYAML() ([]byte, error) {
	return yaml.Marshal(r)
}

// FromYAML deserializes YAML data into the query result
func (r *ADQueryResult) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, r)
}

// Validate validates the query result
func (r *ADQueryResult) Validate() error {
	return nil // Query results don't need validation
}

// ADDirectoryDNA represents comprehensive AD directory DNA collection
type ADDirectoryDNA struct {
	CollectionTime time.Time              `json:"collection_time"`
	Success        bool                   `json:"success"`
	Error          string                 `json:"error,omitempty"`
	Source         string                 `json:"source"`
	DNA            map[string]interface{} `json:"dna"`
}

// AsMap implements the ConfigState interface
func (d *ADDirectoryDNA) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"collection_time": d.CollectionTime,
		"success":         d.Success,
		"error":           d.Error,
		"source":          d.Source,
		"dna":             d.DNA,
	}
}

// GetManagedFields returns the fields that this DNA object tracks
func (d *ADDirectoryDNA) GetManagedFields() []string {
	return []string{"collection_time", "success", "error", "source", "dna"}
}

// ToYAML serializes the DNA result to YAML
func (d *ADDirectoryDNA) ToYAML() ([]byte, error) {
	return yaml.Marshal(d)
}

// FromYAML deserializes YAML data into the DNA result
func (d *ADDirectoryDNA) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, d)
}

// Validate validates the DNA result
func (d *ADDirectoryDNA) Validate() error {
	return nil // DNA results don't need validation
}

// DomainInfo represents basic domain information
type DomainInfo struct {
	Domain           string `json:"domain"`
	DomainController string `json:"domain_controller"`
	ForestRoot       string `json:"forest_root"`
	NetBIOSName      string `json:"netbios_name"`
}

// objectIDPattern accepts SAM account names, UPNs, and GUIDs; rejects raw DNs and shell metacharacters.
var objectIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._@\-]+$`)

// validateObjectID rejects any objectID containing characters outside the strict allowlist before
// interpolation into PowerShell scripts, preventing command injection.
func validateObjectID(objectID string) error {
	matched, err := security.MatchStringWithTimeout(objectIDPattern, objectID)
	if err != nil {
		return fmt.Errorf("invalid objectID %q: validation error: %w", objectID, err)
	}
	if !matched {
		return fmt.Errorf("invalid objectID %q: must match [a-zA-Z0-9._@-]+ (SAM account names, UPNs, and GUIDs only)", objectID)
	}
	return nil
}

// activeDirectoryModule implements the Module interface for local Active Directory management
// using Windows system context and native AD APIs
type activeDirectoryModule struct {
	logger logging.Logger

	// Configuration management
	config    *ADModuleConfig
	configMux sync.RWMutex

	// Statistics tracking
	stats struct {
		sync.RWMutex
		requestCount       int64
		errorCount         int64
		lastRequest        time.Time
		dnaCollectionCount int64
		lastDNACollection  time.Time
	}
}

// New creates a new instance of the system-context Active Directory module
func New(logger logging.Logger) modules.Module {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}

	return &activeDirectoryModule{
		logger: logger,
	}
}

// Get retrieves the current state of Active Directory objects using system context
func (m *activeDirectoryModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	m.logger.Debug("Getting local AD object", "resource_id", resourceID)

	// Parse resourceID to determine operation type
	parts := strings.Split(resourceID, ":")
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid resource ID format: %s", resourceID)
	}

	operation := parts[0]

	switch operation {
	case "status":
		return m.getSystemStatus(ctx)
	case "query":
		if len(parts) < 3 {
			return nil, fmt.Errorf("query requires format 'query:type:id', got: %s", resourceID)
		}
		objectType := parts[1]
		objectID := parts[2]
		return m.queryADObjectSystem(ctx, objectType, objectID)
	case "list":
		if len(parts) < 2 {
			return nil, fmt.Errorf("list requires format 'list:type', got: %s", resourceID)
		}
		objectType := parts[1]
		return m.listADObjectsSystem(ctx, objectType)
	case "dna_collection":
		return m.collectDirectoryDNA(ctx)
	default:
		return nil, fmt.Errorf("unsupported operation: %s", operation)
	}
}

// Set configures the system-context Active Directory module
func (m *activeDirectoryModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	m.logger.Debug("Setting local AD module configuration", "resource_id", resourceID)

	// Convert ConfigState to ADModuleConfig
	configMap := config.AsMap()
	adConfig := &ADModuleConfig{}

	// Extract configuration fields (minimal for system context)
	if opType, ok := configMap["operation_type"].(string); ok {
		adConfig.OperationType = opType
	}
	if objTypes, ok := configMap["object_types"].([]string); ok {
		adConfig.ObjectTypes = objTypes
	}
	if searchBase, ok := configMap["search_base"].(string); ok {
		adConfig.SearchBase = searchBase
	}
	if pageSize, ok := configMap["page_size"].(int); ok {
		adConfig.PageSize = pageSize
	}
	if timeout, ok := configMap["request_timeout"].(time.Duration); ok {
		adConfig.RequestTimeout = timeout
	}
	if enableDNA, ok := configMap["enable_dna_collection"].(bool); ok {
		adConfig.EnableDNACollection = enableDNA
	}

	// Set defaults
	if adConfig.PageSize == 0 {
		adConfig.PageSize = 100
	}
	if adConfig.RequestTimeout == 0 {
		adConfig.RequestTimeout = 30 * time.Second
	}
	if adConfig.OperationType == "" {
		adConfig.OperationType = "read"
	}

	// Validate configuration
	if err := adConfig.Validate(); err != nil {
		return fmt.Errorf("invalid AD configuration: %w", err)
	}

	// Store configuration
	m.configMux.Lock()
	m.config = adConfig
	m.configMux.Unlock()

	// Verify system context AD access
	if err := m.verifySystemAccess(ctx); err != nil {
		return fmt.Errorf("failed to verify system AD access: %w", err)
	}

	m.logger.Info("Local AD module configured successfully using system context",
		"operation_type", adConfig.OperationType,
		"dna_collection", adConfig.EnableDNACollection)

	return nil
}

// Test validates the current configuration matches the desired state
func (m *activeDirectoryModule) Test(ctx context.Context, resourceID string, config modules.ConfigState) (bool, error) {
	// For system context AD, test validates system access and configuration
	m.configMux.RLock()
	currentConfig := m.config
	m.configMux.RUnlock()

	if currentConfig == nil {
		return false, fmt.Errorf("module not configured")
	}

	// Test system AD access
	if err := m.verifySystemAccess(ctx); err != nil {
		return false, fmt.Errorf("system AD access test failed: %w", err)
	}

	// Test basic AD query capability
	_, err := m.queryADObjectSystem(ctx, "user", "Administrator")
	if err != nil {
		m.logger.Warn("AD query test failed", "error", err)
		return false, nil
	}

	return true, nil
}

// getSystemStatus returns the current system context AD status
func (m *activeDirectoryModule) getSystemStatus(ctx context.Context) (modules.ConfigState, error) {
	status := &ADSystemStatus{
		SystemContext: true,
		Hostname:      m.getHostname(),
	}

	// Get domain information using system context
	domainInfo, err := m.getDomainInfo(ctx)
	if err != nil {
		status.HealthStatus = "unhealthy"
		status.Error = err.Error()
	} else {
		status.Domain = domainInfo.Domain
		status.DomainController = domainInfo.DomainController
		status.ForestRoot = domainInfo.ForestRoot
		status.HealthStatus = "healthy"
	}

	m.stats.RLock()
	status.RequestCount = m.stats.requestCount
	status.ErrorCount = m.stats.errorCount
	status.LastHealthCheck = time.Now()
	status.DNACollectionCount = m.stats.dnaCollectionCount
	status.LastDNACollection = m.stats.lastDNACollection
	m.stats.RUnlock()

	return status, nil
}

// queryADObjectSystem queries AD objects using Windows system context
func (m *activeDirectoryModule) queryADObjectSystem(ctx context.Context, objectType, objectID string) (modules.ConfigState, error) {
	if err := validateObjectID(objectID); err != nil {
		return nil, err
	}

	m.updateStats(true)
	startTime := time.Now()

	result := &ADQueryResult{
		QueryType:  objectType,
		ObjectID:   objectID,
		ExecutedAt: startTime,
	}

	// Use PowerShell with system context to query AD
	var psScript string
	switch objectType {
	case "user":
		psScript = fmt.Sprintf(`
			try {
				Import-Module ActiveDirectory -ErrorAction Stop
				$user = Get-ADUser -Identity '%s' -Properties * -ErrorAction Stop
				$result = @{
					success = $true
					user = @{
						id = $user.DistinguishedName
						sam_account_name = $user.SamAccountName
						user_principal_name = $user.UserPrincipalName
						display_name = $user.DisplayName
						email_address = $user.EmailAddress
						account_enabled = $user.Enabled
						distinguished_name = $user.DistinguishedName
						source = "activedirectory_system"
						object_guid = $user.ObjectGUID.ToString()
						when_created = $user.WhenCreated.ToString("yyyy-MM-ddTHH:mm:ssZ")
						when_changed = $user.WhenChanged.ToString("yyyy-MM-ddTHH:mm:ssZ")
						member_of = $user.MemberOf
					}
				}
				ConvertTo-Json $result -Depth 10
			} catch {
				$error = @{
					success = $false
					error = $_.Exception.Message
				}
				ConvertTo-Json $error
			}
		`, objectID)

	case "group":
		psScript = fmt.Sprintf(`
			try {
				Import-Module ActiveDirectory -ErrorAction Stop
				$group = Get-ADGroup -Identity '%s' -Properties * -ErrorAction Stop
				$result = @{
					success = $true
					group = @{
						id = $group.DistinguishedName
						sam_account_name = $group.SamAccountName
						display_name = $group.Name
						description = $group.Description
						distinguished_name = $group.DistinguishedName
						source = "activedirectory_system"
						object_guid = $group.ObjectGUID.ToString()
						group_scope = $group.GroupScope
						group_category = $group.GroupCategory
						members = $group.Members
					}
				}
				ConvertTo-Json $result -Depth 10
			} catch {
				$error = @{
					success = $false
					error = $_.Exception.Message
				}
				ConvertTo-Json $error
			}
		`, objectID)

	case "organizational_unit", "ou":
		psScript = fmt.Sprintf(`
			try {
				Import-Module ActiveDirectory -ErrorAction Stop
				$ou = Get-ADOrganizationalUnit -Identity '%s' -Properties * -ErrorAction Stop
				$result = @{
					success = $true
					ou = @{
						id = $ou.DistinguishedName
						name = $ou.Name
						display_name = $ou.DisplayName
						description = $ou.Description
						distinguished_name = $ou.DistinguishedName
						source = "activedirectory_system"
						object_guid = $ou.ObjectGUID.ToString()
						managed_by = $ou.ManagedBy
					}
				}
				ConvertTo-Json $result -Depth 10
			} catch {
				$error = @{
					success = $false
					error = $_.Exception.Message
				}
				ConvertTo-Json $error
			}
		`, objectID)

	case "computer":
		psScript = fmt.Sprintf(`
			try {
				Import-Module ActiveDirectory -ErrorAction Stop
				$computer = Get-ADComputer -Identity '%s' -Properties * -ErrorAction Stop
				$result = @{
					success = $true
					user = @{
						id = $computer.DistinguishedName
						sam_account_name = $computer.SamAccountName
						display_name = $computer.Name
						distinguished_name = $computer.DistinguishedName
						source = "activedirectory_system"
						object_guid = $computer.ObjectGUID.ToString()
						object_type = "computer"
						operating_system = $computer.OperatingSystem
						operating_system_version = $computer.OperatingSystemVersion
						last_logon_date = if($computer.LastLogonDate) { $computer.LastLogonDate.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
						dns_host_name = $computer.DNSHostName
						service_principal_names = $computer.ServicePrincipalNames
					}
				}
				ConvertTo-Json $result -Depth 10
			} catch {
				$error = @{
					success = $false
					error = $_.Exception.Message
				}
				ConvertTo-Json $error
			}
		`, objectID)

	default:
		result.Success = false
		result.Error = fmt.Sprintf("unsupported object type: %s", objectType)
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}

	// Execute PowerShell script with system context
	output, err := m.executePowerShellWithSystemContext(ctx, psScript)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("PowerShell execution failed: %v", err)
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}

	// Parse JSON response
	var psResult map[string]interface{}
	if err := json.Unmarshal([]byte(output), &psResult); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("failed to parse PowerShell output: %v", err)
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}

	// Check if PowerShell operation succeeded
	if success, ok := psResult["success"].(bool); !ok || !success {
		result.Success = false
		if errorMsg, ok := psResult["error"].(string); ok {
			result.Error = errorMsg
		} else {
			result.Error = "unknown PowerShell error"
		}
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}

	// Convert PowerShell result to CFGMS directory objects
	result.Success = true
	result.ResponseTime = time.Since(startTime)

	switch objectType {
	case "user", "computer":
		if userObj, ok := psResult["user"].(map[string]interface{}); ok {
			user := m.convertPSObjectToDirectoryUser(userObj)
			result.User = user
		}
	case "group":
		if groupObj, ok := psResult["group"].(map[string]interface{}); ok {
			group := m.convertPSObjectToDirectoryGroup(groupObj)
			result.Group = group
		}
	case "organizational_unit", "ou":
		if ouObj, ok := psResult["ou"].(map[string]interface{}); ok {
			ou := m.convertPSObjectToOrganizationalUnit(ouObj)
			result.OU = ou
		}
	}

	m.logger.Debug("Local AD query completed successfully",
		"object_type", objectType,
		"object_id", objectID,
		"response_time", result.ResponseTime)

	return result, nil
}

// listADObjectsSystem lists AD objects using Windows system context
func (m *activeDirectoryModule) listADObjectsSystem(ctx context.Context, objectType string) (modules.ConfigState, error) {
	m.updateStats(true)
	startTime := time.Now()

	result := &ADQueryResult{
		QueryType:  "list_" + objectType,
		ExecutedAt: startTime,
	}

	m.configMux.RLock()
	config := m.config
	m.configMux.RUnlock()

	pageSize := 100
	if config != nil && config.PageSize > 0 {
		pageSize = config.PageSize
	}

	// Build PowerShell script for listing objects
	var psScript string
	switch objectType {
	case "user":
		psScript = fmt.Sprintf(`
			try {
				Import-Module ActiveDirectory -ErrorAction Stop
				$users = Get-ADUser -Filter * -Properties SamAccountName,UserPrincipalName,DisplayName,EmailAddress,Enabled,DistinguishedName,ObjectGUID -ResultSetSize %d
				$result = @{
					success = $true
					total_count = $users.Count
					users = @()
				}
				foreach ($user in $users) {
					$result.users += @{
						id = $user.DistinguishedName
						sam_account_name = $user.SamAccountName
						user_principal_name = $user.UserPrincipalName
						display_name = $user.DisplayName
						email_address = $user.EmailAddress
						account_enabled = $user.Enabled
						distinguished_name = $user.DistinguishedName
						source = "activedirectory_system"
						object_guid = $user.ObjectGUID.ToString()
					}
				}
				ConvertTo-Json $result -Depth 10
			} catch {
				$error = @{
					success = $false
					error = $_.Exception.Message
				}
				ConvertTo-Json $error
			}
		`, pageSize)

	case "group":
		psScript = fmt.Sprintf(`
			try {
				Import-Module ActiveDirectory -ErrorAction Stop
				$groups = Get-ADGroup -Filter * -Properties SamAccountName,Name,Description,DistinguishedName,ObjectGUID,GroupScope,GroupCategory -ResultSetSize %d
				$result = @{
					success = $true
					total_count = $groups.Count
					groups = @()
				}
				foreach ($group in $groups) {
					$result.groups += @{
						id = $group.DistinguishedName
						sam_account_name = $group.SamAccountName
						display_name = $group.Name
						description = $group.Description
						distinguished_name = $group.DistinguishedName
						source = "activedirectory_system"
						object_guid = $group.ObjectGUID.ToString()
						group_scope = $group.GroupScope
						group_category = $group.GroupCategory
					}
				}
				ConvertTo-Json $result -Depth 10
			} catch {
				$error = @{
					success = $false
					error = $_.Exception.Message
				}
				ConvertTo-Json $error
			}
		`, pageSize)

	case "computer":
		psScript = fmt.Sprintf(`
			try {
				Import-Module ActiveDirectory -ErrorAction Stop
				$computers = Get-ADComputer -Filter * -Properties SamAccountName,Name,DistinguishedName,ObjectGUID,OperatingSystem,DNSHostName -ResultSetSize %d
				$result = @{
					success = $true
					total_count = $computers.Count
					users = @()  # Computers represented as users for interface compatibility
				}
				foreach ($computer in $computers) {
					$result.users += @{
						id = $computer.DistinguishedName
						sam_account_name = $computer.SamAccountName
						display_name = $computer.Name
						distinguished_name = $computer.DistinguishedName
						source = "activedirectory_system"
						object_guid = $computer.ObjectGUID.ToString()
						object_type = "computer"
						operating_system = $computer.OperatingSystem
						dns_host_name = $computer.DNSHostName
					}
				}
				ConvertTo-Json $result -Depth 10
			} catch {
				$error = @{
					success = $false
					error = $_.Exception.Message
				}
				ConvertTo-Json $error
			}
		`, pageSize)

	case "organizational_unit", "ou":
		psScript = fmt.Sprintf(`
			try {
				Import-Module ActiveDirectory -ErrorAction Stop
				$ous = Get-ADOrganizationalUnit -Filter * -Properties Name,DisplayName,Description,DistinguishedName,ObjectGUID,ManagedBy -ResultSetSize %d
				$result = @{
					success = $true
					total_count = $ous.Count
					ous = @()
				}
				foreach ($ou in $ous) {
					$result.ous += @{
						id = $ou.DistinguishedName
						name = $ou.Name
						display_name = $ou.DisplayName
						description = $ou.Description
						distinguished_name = $ou.DistinguishedName
						source = "activedirectory_system"
						object_guid = $ou.ObjectGUID.ToString()
						managed_by = $ou.ManagedBy
					}
				}
				ConvertTo-Json $result -Depth 10
			} catch {
				$error = @{
					success = $false
					error = $_.Exception.Message
				}
				ConvertTo-Json $error
			}
		`, pageSize)

	default:
		result.Success = false
		result.Error = fmt.Sprintf("unsupported object type: %s", objectType)
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}

	// Execute PowerShell script
	output, err := m.executePowerShellWithSystemContext(ctx, psScript)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("PowerShell execution failed: %v", err)
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}

	// Parse JSON response
	var psResult map[string]interface{}
	if err := json.Unmarshal([]byte(output), &psResult); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("failed to parse PowerShell output: %v", err)
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}

	// Check if operation succeeded
	if success, ok := psResult["success"].(bool); !ok || !success {
		result.Success = false
		if errorMsg, ok := psResult["error"].(string); ok {
			result.Error = errorMsg
		}
		result.ResponseTime = time.Since(startTime)
		m.updateStats(false)
		return result, nil
	}

	// Extract results
	result.Success = true
	result.ResponseTime = time.Since(startTime)

	if totalCount, ok := psResult["total_count"].(float64); ok {
		result.TotalCount = int(totalCount)
	}

	// Convert PowerShell objects to CFGMS directory objects
	switch objectType {
	case "user", "computer":
		if users, ok := psResult["users"].([]interface{}); ok {
			result.Users = make([]interfaces.DirectoryUser, len(users))
			for i, userInterface := range users {
				if userObj, ok := userInterface.(map[string]interface{}); ok {
					user := m.convertPSObjectToDirectoryUser(userObj)
					result.Users[i] = *user
				}
			}
		}
	case "group":
		if groups, ok := psResult["groups"].([]interface{}); ok {
			result.Groups = make([]interfaces.DirectoryGroup, len(groups))
			for i, groupInterface := range groups {
				if groupObj, ok := groupInterface.(map[string]interface{}); ok {
					group := m.convertPSObjectToDirectoryGroup(groupObj)
					result.Groups[i] = *group
				}
			}
		}
	case "organizational_unit", "ou":
		if ous, ok := psResult["ous"].([]interface{}); ok {
			result.OUs = make([]interfaces.OrganizationalUnit, len(ous))
			for i, ouInterface := range ous {
				if ouObj, ok := ouInterface.(map[string]interface{}); ok {
					ou := m.convertPSObjectToOrganizationalUnit(ouObj)
					result.OUs[i] = *ou
				}
			}
		}
	}

	m.logger.Debug("Local AD list completed successfully",
		"object_type", objectType,
		"count", result.TotalCount,
		"response_time", result.ResponseTime)

	return result, nil
}

// collectDirectoryDNA collects comprehensive AD DNA data using system context
func (m *activeDirectoryModule) collectDirectoryDNA(ctx context.Context) (modules.ConfigState, error) {
	m.stats.Lock()
	m.stats.dnaCollectionCount++
	m.stats.lastDNACollection = time.Now()
	m.stats.Unlock()

	startTime := time.Now()

	// PowerShell script to collect comprehensive AD DNA
	psScript := `
		try {
			Import-Module ActiveDirectory -ErrorAction Stop
			
			# Get domain information
			$domain = Get-ADDomain
			$forest = Get-ADForest
			$domainControllers = Get-ADDomainController -Filter *
			
			# Get user statistics
			$totalUsers = (Get-ADUser -Filter *).Count
			$enabledUsers = (Get-ADUser -Filter {Enabled -eq $true}).Count
			$disabledUsers = $totalUsers - $enabledUsers
			
			# Get group statistics
			$totalGroups = (Get-ADGroup -Filter *).Count
			$securityGroups = (Get-ADGroup -Filter {GroupCategory -eq "Security"}).Count
			$distributionGroups = $totalGroups - $securityGroups
			
			# Get computer statistics
			$totalComputers = (Get-ADComputer -Filter *).Count
			$enabledComputers = (Get-ADComputer -Filter {Enabled -eq $true}).Count
			
			# Get organizational units
			$totalOUs = (Get-ADOrganizationalUnit -Filter *).Count
			
			# Get Group Policy Objects
			$gpos = Get-GPO -All
			$totalGPOs = $gpos.Count
			
			# Build DNA result
			$dna = @{
				success = $true
				collection_time = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
				domain_info = @{
					domain_name = $domain.DNSRoot
					netbios_name = $domain.NetBIOSName
					domain_mode = $domain.DomainMode
					forest_name = $forest.Name
					forest_mode = $forest.ForestMode
					schema_master = $forest.SchemaMaster
					domain_naming_master = $forest.DomainNamingMaster
					pdc_emulator = $domain.PDCEmulator
					rid_master = $domain.RIDMaster
					infrastructure_master = $domain.InfrastructureMaster
				}
				domain_controllers = @()
				statistics = @{
					total_users = $totalUsers
					enabled_users = $enabledUsers
					disabled_users = $disabledUsers
					total_groups = $totalGroups
					security_groups = $securityGroups
					distribution_groups = $distributionGroups
					total_computers = $totalComputers
					enabled_computers = $enabledComputers
					total_ous = $totalOUs
					total_gpos = $totalGPOs
				}
				gpos = @()
			}
			
			# Add domain controller information
			foreach ($dc in $domainControllers) {
				$dna.domain_controllers += @{
					name = $dc.Name
					hostname = $dc.HostName
					ipv4_address = $dc.IPv4Address
					site = $dc.Site
					operating_system = $dc.OperatingSystem
					is_global_catalog = $dc.IsGlobalCatalog
					is_read_only = $dc.IsReadOnly
				}
			}
			
			# Add GPO information
			foreach ($gpo in $gpos) {
				$dna.gpos += @{
					display_name = $gpo.DisplayName
					id = $gpo.Id.ToString()
					creation_time = $gpo.CreationTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
					modification_time = $gpo.ModificationTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
					user_version = $gpo.UserVersion
					computer_version = $gpo.ComputerVersion
				}
			}
			
			ConvertTo-Json $dna -Depth 10
		} catch {
			$error = @{
				success = $false
				error = $_.Exception.Message
			}
			ConvertTo-Json $error
		}
	`

	// Execute DNA collection script
	output, err := m.executePowerShellWithSystemContext(ctx, psScript)
	if err != nil {
		return nil, fmt.Errorf("DNA collection failed: %w", err)
	}

	// Parse DNA result
	var dnaResult map[string]interface{}
	if err := json.Unmarshal([]byte(output), &dnaResult); err != nil {
		return nil, fmt.Errorf("failed to parse DNA collection output: %w", err)
	}

	if success, ok := dnaResult["success"].(bool); !ok || !success {
		errorMsg := "unknown DNA collection error"
		if err, ok := dnaResult["error"].(string); ok {
			errorMsg = err
		}
		return nil, fmt.Errorf("DNA collection failed: %s", errorMsg)
	}

	// Create DNA result structure
	dna := &ADDirectoryDNA{
		CollectionTime: time.Now(),
		Success:        true,
		Source:         "activedirectory_system",
		DNA:            dnaResult,
	}

	m.logger.Info("AD DNA collection completed successfully",
		"collection_time", time.Since(startTime),
		"total_users", m.extractStatInt(dnaResult, "statistics", "total_users"),
		"total_groups", m.extractStatInt(dnaResult, "statistics", "total_groups"),
		"total_computers", m.extractStatInt(dnaResult, "statistics", "total_computers"))

	return dna, nil
}

// verifySystemAccess verifies that the module can access AD using system context
func (m *activeDirectoryModule) verifySystemAccess(ctx context.Context) error {
	// Simple test to verify AD module availability and system context
	psScript := `
		try {
			Import-Module ActiveDirectory -ErrorAction Stop
			$domain = Get-ADDomain -ErrorAction Stop
			$result = @{
				success = $true
				domain = $domain.DNSRoot
				access_level = "system_context"
			}
			ConvertTo-Json $result
		} catch {
			$error = @{
				success = $false
				error = $_.Exception.Message
			}
			ConvertTo-Json $error
		}
	`

	output, err := m.executePowerShellWithSystemContext(ctx, psScript)
	if err != nil {
		return fmt.Errorf("system context verification failed: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return fmt.Errorf("failed to parse verification result: %w", err)
	}

	if success, ok := result["success"].(bool); !ok || !success {
		errorMsg := "unknown verification error"
		if err, ok := result["error"].(string); ok {
			errorMsg = err
		}
		return fmt.Errorf("system AD access verification failed: %s", errorMsg)
	}

	m.logger.Debug("System AD access verified successfully",
		"domain", result["domain"],
		"access_level", result["access_level"])

	return nil
}

// executePowerShellWithSystemContext executes PowerShell with system context
func (m *activeDirectoryModule) executePowerShellWithSystemContext(ctx context.Context, script string) (string, error) {
	// Create PowerShell command that runs with current system context
	// The steward should already be running as SYSTEM, so this inherits those permissions
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)

	// Execute command
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("PowerShell script failed: %s", string(exitErr.Stderr))
		}
		return "", fmt.Errorf("failed to execute PowerShell: %w", err)
	}

	return string(output), nil
}

// getDomainInfo gets basic domain information using system context
func (m *activeDirectoryModule) getDomainInfo(ctx context.Context) (*DomainInfo, error) {
	psScript := `
		try {
			Import-Module ActiveDirectory -ErrorAction Stop
			$domain = Get-ADDomain
			$forest = Get-ADForest
			$dc = Get-ADDomainController -Discover
			$result = @{
				success = $true
				domain = $domain.DNSRoot
				domain_controller = $dc.HostName[0]
				forest_root = $forest.Name
				netbios_name = $domain.NetBIOSName
			}
			ConvertTo-Json $result
		} catch {
			$error = @{
				success = $false
				error = $_.Exception.Message
			}
			ConvertTo-Json $error
		}
	`

	output, err := m.executePowerShellWithSystemContext(ctx, psScript)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain info: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, fmt.Errorf("failed to parse domain info: %w", err)
	}

	if success, ok := result["success"].(bool); !ok || !success {
		errorMsg := "unknown error"
		if err, ok := result["error"].(string); ok {
			errorMsg = err
		}
		return nil, fmt.Errorf("domain info query failed: %s", errorMsg)
	}

	domainInfo := &DomainInfo{}
	if domain, ok := result["domain"].(string); ok {
		domainInfo.Domain = domain
	}
	if dc, ok := result["domain_controller"].(string); ok {
		domainInfo.DomainController = dc
	}
	if forest, ok := result["forest_root"].(string); ok {
		domainInfo.ForestRoot = forest
	}
	if netbios, ok := result["netbios_name"].(string); ok {
		domainInfo.NetBIOSName = netbios
	}

	return domainInfo, nil
}

// getHostname returns the current hostname
func (m *activeDirectoryModule) getHostname() string {
	cmd := exec.Command("hostname")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// Helper methods for updating statistics
func (m *activeDirectoryModule) updateStats(isRequest bool) {
	m.stats.Lock()
	defer m.stats.Unlock()

	if isRequest {
		m.stats.requestCount++
		m.stats.lastRequest = time.Now()
	} else {
		m.stats.errorCount++
	}
}

// extractStatInt safely extracts integer statistics from nested maps
func (m *activeDirectoryModule) extractStatInt(data map[string]interface{}, keys ...string) int {
	current := data
	for i, key := range keys {
		if i == len(keys)-1 {
			if val, ok := current[key].(float64); ok {
				return int(val)
			}
			return 0
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return 0
		}
	}
	return 0
}

// GetCapabilities returns the capabilities of this system-context module
func (m *activeDirectoryModule) GetCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"supports_read":      true,
		"supports_write":     true,
		"supports_monitor":   false, // Not yet implemented
		"supports_bulk":      true,
		"object_types":       []string{"user", "group", "organizational_unit", "computer", "gpo", "group_policy", "domain_trust", "trust"},
		"auth_methods":       []string{"system_context"},
		"platforms":          []string{"windows"},
		"requires_domain":    false, // Auto-discovers local domain
		"supports_discovery": true,
		"system_context":     true,
		"credential_free":    true,
		"advanced_features":  []string{"system_context_access", "dna_collection", "computer_objects", "group_policies", "domain_info"},
	}
}

// convertPSObjectToDirectoryUser converts PowerShell AD user object to CFGMS DirectoryUser
func (m *activeDirectoryModule) convertPSObjectToDirectoryUser(psObj map[string]interface{}) *interfaces.DirectoryUser {
	user := &interfaces.DirectoryUser{
		Source: "activedirectory_system",
	}

	if id, ok := psObj["id"].(string); ok {
		user.ID = id
	}
	if sam, ok := psObj["sam_account_name"].(string); ok {
		user.SAMAccountName = sam
	}
	if upn, ok := psObj["user_principal_name"].(string); ok {
		user.UserPrincipalName = upn
	}
	if displayName, ok := psObj["display_name"].(string); ok {
		user.DisplayName = displayName
	}
	if email, ok := psObj["email_address"].(string); ok {
		user.EmailAddress = email
	}
	if enabled, ok := psObj["account_enabled"].(bool); ok {
		user.AccountEnabled = enabled
	}
	if dn, ok := psObj["distinguished_name"].(string); ok {
		user.DistinguishedName = dn
	}
	if created, ok := psObj["when_created"].(string); ok {
		if parsedTime, err := time.Parse("2006-01-02T15:04:05Z", created); err == nil {
			user.Created = &parsedTime
		}
	}
	if changed, ok := psObj["when_changed"].(string); ok {
		if parsedTime, err := time.Parse("2006-01-02T15:04:05Z", changed); err == nil {
			user.Modified = &parsedTime
		}
	}
	if memberOf, ok := psObj["member_of"].([]interface{}); ok {
		user.Groups = make([]string, len(memberOf))
		for i, group := range memberOf {
			if groupStr, ok := group.(string); ok {
				user.Groups[i] = groupStr
			}
		}
	}
	if lastLogon, ok := psObj["last_logon_date"].(string); ok && lastLogon != "" {
		if parsedTime, err := time.Parse("2006-01-02T15:04:05Z", lastLogon); err == nil {
			user.LastLogon = &parsedTime
		}
	}

	// Store AD-specific attributes in ProviderAttributes
	if user.ProviderAttributes == nil {
		user.ProviderAttributes = make(map[string]interface{})
	}

	if guid, ok := psObj["object_guid"].(string); ok {
		user.ProviderAttributes["object_guid"] = guid
	}
	if objectType, ok := psObj["object_type"].(string); ok {
		user.ProviderAttributes["object_type"] = objectType
	} else {
		user.ProviderAttributes["object_type"] = "user"
	}
	if os, ok := psObj["operating_system"].(string); ok {
		user.ProviderAttributes["operating_system"] = os
	}
	if osVersion, ok := psObj["operating_system_version"].(string); ok {
		user.ProviderAttributes["operating_system_version"] = osVersion
	}
	if dnsHost, ok := psObj["dns_host_name"].(string); ok {
		user.ProviderAttributes["dns_host_name"] = dnsHost
	}
	if spns, ok := psObj["service_principal_names"].([]interface{}); ok {
		user.ProviderAttributes["service_principal_names"] = spns
	}

	return user
}

// convertPSObjectToDirectoryGroup converts PowerShell AD group object to CFGMS DirectoryGroup
func (m *activeDirectoryModule) convertPSObjectToDirectoryGroup(psObj map[string]interface{}) *interfaces.DirectoryGroup {
	group := &interfaces.DirectoryGroup{
		Source: "activedirectory_system",
	}

	if id, ok := psObj["id"].(string); ok {
		group.ID = id
	}
	if displayName, ok := psObj["display_name"].(string); ok {
		group.DisplayName = displayName
		group.Name = displayName // Use display name as name
	}
	if description, ok := psObj["description"].(string); ok {
		group.Description = description
	}
	if dn, ok := psObj["distinguished_name"].(string); ok {
		group.DistinguishedName = dn
	}
	if members, ok := psObj["members"].([]interface{}); ok {
		group.Members = make([]string, len(members))
		for i, member := range members {
			if memberStr, ok := member.(string); ok {
				group.Members[i] = memberStr
			}
		}
	}

	// Store AD-specific attributes in ProviderAttributes
	if group.ProviderAttributes == nil {
		group.ProviderAttributes = make(map[string]interface{})
	}

	if sam, ok := psObj["sam_account_name"].(string); ok {
		group.ProviderAttributes["sam_account_name"] = sam
	}
	if guid, ok := psObj["object_guid"].(string); ok {
		group.ProviderAttributes["object_guid"] = guid
	}
	if scope, ok := psObj["group_scope"].(string); ok {
		group.ProviderAttributes["group_scope"] = scope
		// Map to normalized GroupScope
		switch strings.ToLower(scope) {
		case "domainlocal":
			group.GroupScope = interfaces.GroupScopeDomainLocal
		case "global":
			group.GroupScope = interfaces.GroupScopeGlobal
		case "universal":
			group.GroupScope = interfaces.GroupScopeUniversal
		}
	}
	if category, ok := psObj["group_category"].(string); ok {
		group.ProviderAttributes["group_category"] = category
		// Map to normalized GroupType
		switch strings.ToLower(category) {
		case "security":
			group.GroupType = interfaces.GroupTypeSecurity
		case "distribution":
			group.GroupType = interfaces.GroupTypeDistribution
		}
	}

	return group
}

// convertPSObjectToOrganizationalUnit converts PowerShell AD OU object to CFGMS OrganizationalUnit
func (m *activeDirectoryModule) convertPSObjectToOrganizationalUnit(psObj map[string]interface{}) *interfaces.OrganizationalUnit {
	ou := &interfaces.OrganizationalUnit{
		Source: "activedirectory_system",
	}

	if id, ok := psObj["id"].(string); ok {
		ou.ID = id
	}
	if name, ok := psObj["name"].(string); ok {
		ou.Name = name
	}
	if displayName, ok := psObj["display_name"].(string); ok {
		ou.DisplayName = displayName
	}
	if description, ok := psObj["description"].(string); ok {
		ou.Description = description
	}
	if dn, ok := psObj["distinguished_name"].(string); ok {
		ou.DistinguishedName = dn
	}

	// Store AD-specific attributes in ProviderAttributes
	if ou.ProviderAttributes == nil {
		ou.ProviderAttributes = make(map[string]interface{})
	}

	if guid, ok := psObj["object_guid"].(string); ok {
		ou.ProviderAttributes["object_guid"] = guid
	}
	if managedBy, ok := psObj["managed_by"].(string); ok {
		ou.ProviderAttributes["managed_by"] = managedBy
	}

	return ou
}
