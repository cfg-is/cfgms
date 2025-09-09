// Package testing provides comprehensive test scenarios for M365 delegated permissions
package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
)

// ScenarioRunner executes realistic M365 operations to test delegated permissions
type ScenarioRunner struct {
	provider    *auth.OAuth2Provider
	httpClient  *http.Client
	tenantID    string
	userContext *auth.UserContext
	token       *auth.AccessToken
}

// NewScenarioRunner creates a new scenario runner
func NewScenarioRunner(provider *auth.OAuth2Provider, tenantID string, userContext *auth.UserContext, token *auth.AccessToken) *ScenarioRunner {
	return &ScenarioRunner{
		provider:    provider,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		tenantID:    tenantID,
		userContext: userContext,
		token:       token,
	}
}

// ScenarioResult represents the result of running a test scenario
type ScenarioResult struct {
	ScenarioName    string                 `json:"scenario_name"`
	Success         bool                   `json:"success"`
	Error           string                 `json:"error,omitempty"`
	Operations      []OperationResult      `json:"operations"`
	Metadata        map[string]interface{} `json:"metadata"`
	ExecutionTime   time.Duration          `json:"execution_time"`
	UserContext     *auth.UserContext      `json:"user_context"`
}

// OperationResult represents the result of a single Graph API operation
type OperationResult struct {
	Name         string                 `json:"name"`
	Method       string                 `json:"method"`
	URL          string                 `json:"url"`
	StatusCode   int                    `json:"status_code"`
	Success      bool                   `json:"success"`
	Error        string                 `json:"error,omitempty"`
	ResponseData map[string]interface{} `json:"response_data,omitempty"`
	Duration     time.Duration          `json:"duration"`
}

// RunAllScenarios runs all available test scenarios
func (sr *ScenarioRunner) RunAllScenarios(ctx context.Context) ([]*ScenarioResult, error) {
	fmt.Printf("🧪 Running M365 Integration Test Scenarios\n")
	fmt.Printf("==========================================\n")

	scenarios := []*ScenarioResult{
		sr.RunUserManagementScenario(ctx),
		sr.RunDirectoryReadScenario(ctx),
		sr.RunGroupManagementScenario(ctx),
		sr.RunConditionalAccessScenario(ctx),
		sr.RunIntuneScenario(ctx),
		sr.RunAuditLogScenario(ctx),
	}

	// Summary
	successful := 0
	for _, result := range scenarios {
		if result.Success {
			successful++
		}
	}

	fmt.Printf("\n📊 Test Summary:\n")
	fmt.Printf("   Total scenarios: %d\n", len(scenarios))
	fmt.Printf("   Successful: %d\n", successful)
	fmt.Printf("   Failed: %d\n", len(scenarios)-successful)

	return scenarios, nil
}

// RunUserManagementScenario tests user management operations
func (sr *ScenarioRunner) RunUserManagementScenario(ctx context.Context) *ScenarioResult {
	start := time.Now()
	result := &ScenarioResult{
		ScenarioName: "User Management",
		UserContext:  sr.userContext,
		Operations:   make([]OperationResult, 0),
		Metadata:     make(map[string]interface{}),
	}

	fmt.Printf("🔍 Running User Management Scenario...\n")

	// Test 1: Read current user profile
	op1 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/me", nil)
	op1.Name = "Get Current User Profile"
	result.Operations = append(result.Operations, op1)

	if op1.Success {
		fmt.Printf("  ✅ Successfully read user profile\n")
		if displayName, ok := op1.ResponseData["displayName"].(string); ok {
			result.Metadata["current_user_name"] = displayName
		}
	} else {
		fmt.Printf("  ❌ Failed to read user profile: %s\n", op1.Error)
	}

	// Test 2: List users (requires elevated permissions)
	op2 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/users?$top=5&$select=id,displayName,userPrincipalName", nil)
	op2.Name = "List Users"
	result.Operations = append(result.Operations, op2)

	if op2.Success {
		fmt.Printf("  ✅ Successfully listed users\n")
		if value, ok := op2.ResponseData["value"].([]interface{}); ok {
			result.Metadata["user_count"] = len(value)
		}
	} else {
		fmt.Printf("  ❌ Failed to list users: %s\n", op2.Error)
	}

	// Test 3: Get user's manager (if exists)
	op3 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/me/manager", nil)
	op3.Name = "Get User Manager"
	result.Operations = append(result.Operations, op3)

	if op3.Success {
		fmt.Printf("  ✅ Successfully retrieved manager information\n")
		if displayName, ok := op3.ResponseData["displayName"].(string); ok {
			result.Metadata["manager_name"] = displayName
		}
	} else {
		fmt.Printf("  ❌ Failed to get manager (may not exist): %s\n", op3.Error)
		// Manager not existing is not a failure for this test
		op3.Success = true
		op3.Error = "No manager assigned (expected)"
	}

	// Determine overall success
	result.Success = true
	for _, op := range result.Operations {
		if !op.Success {
			result.Success = false
			result.Error = fmt.Sprintf("Operation '%s' failed: %s", op.Name, op.Error)
			break
		}
	}

	result.ExecutionTime = time.Since(start)
	
	if result.Success {
		fmt.Printf("  ✅ User Management scenario completed successfully\n\n")
	} else {
		fmt.Printf("  ❌ User Management scenario failed: %s\n\n", result.Error)
	}

	return result
}

// RunDirectoryReadScenario tests directory reading operations
func (sr *ScenarioRunner) RunDirectoryReadScenario(ctx context.Context) *ScenarioResult {
	start := time.Now()
	result := &ScenarioResult{
		ScenarioName: "Directory Read",
		UserContext:  sr.userContext,
		Operations:   make([]OperationResult, 0),
		Metadata:     make(map[string]interface{}),
	}

	fmt.Printf("🔍 Running Directory Read Scenario...\n")

	// Test 1: Get organization info
	op1 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/organization", nil)
	op1.Name = "Get Organization Info"
	result.Operations = append(result.Operations, op1)

	if op1.Success {
		fmt.Printf("  ✅ Successfully read organization info\n")
		if value, ok := op1.ResponseData["value"].([]interface{}); ok && len(value) > 0 {
			if org, ok := value[0].(map[string]interface{}); ok {
				if displayName, ok := org["displayName"].(string); ok {
					result.Metadata["org_name"] = displayName
				}
				if tenantType, ok := org["tenantType"].(string); ok {
					result.Metadata["tenant_type"] = tenantType
				}
			}
		}
	} else {
		fmt.Printf("  ❌ Failed to read organization info: %s\n", op1.Error)
	}

	// Test 2: List directory roles
	op2 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/directoryRoles?$top=10", nil)
	op2.Name = "List Directory Roles"
	result.Operations = append(result.Operations, op2)

	if op2.Success {
		fmt.Printf("  ✅ Successfully listed directory roles\n")
		if value, ok := op2.ResponseData["value"].([]interface{}); ok {
			result.Metadata["directory_roles_count"] = len(value)
		}
	} else {
		fmt.Printf("  ❌ Failed to list directory roles: %s\n", op2.Error)
	}

	// Test 3: Get subscribed SKUs (licenses)
	op3 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/subscribedSkus", nil)
	op3.Name = "Get Subscribed SKUs"
	result.Operations = append(result.Operations, op3)

	if op3.Success {
		fmt.Printf("  ✅ Successfully retrieved subscribed SKUs\n")
		if value, ok := op3.ResponseData["value"].([]interface{}); ok {
			result.Metadata["license_skus_count"] = len(value)
		}
	} else {
		fmt.Printf("  ❌ Failed to get subscribed SKUs: %s\n", op3.Error)
	}

	// Determine overall success
	result.Success = true
	for _, op := range result.Operations {
		if !op.Success {
			result.Success = false
			result.Error = fmt.Sprintf("Operation '%s' failed: %s", op.Name, op.Error)
			break
		}
	}

	result.ExecutionTime = time.Since(start)
	
	if result.Success {
		fmt.Printf("  ✅ Directory Read scenario completed successfully\n\n")
	} else {
		fmt.Printf("  ❌ Directory Read scenario failed: %s\n\n", result.Error)
	}

	return result
}

// RunGroupManagementScenario tests group management operations
func (sr *ScenarioRunner) RunGroupManagementScenario(ctx context.Context) *ScenarioResult {
	start := time.Now()
	result := &ScenarioResult{
		ScenarioName: "Group Management",
		UserContext:  sr.userContext,
		Operations:   make([]OperationResult, 0),
		Metadata:     make(map[string]interface{}),
	}

	fmt.Printf("🔍 Running Group Management Scenario...\n")

	// Test 1: List groups
	op1 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/groups?$top=10&$select=id,displayName,groupTypes,mailEnabled,securityEnabled", nil)
	op1.Name = "List Groups"
	result.Operations = append(result.Operations, op1)

	if op1.Success {
		fmt.Printf("  ✅ Successfully listed groups\n")
		if value, ok := op1.ResponseData["value"].([]interface{}); ok {
			result.Metadata["groups_count"] = len(value)
			
			// Count different group types
			securityGroups := 0
			mailGroups := 0
			for _, group := range value {
				if g, ok := group.(map[string]interface{}); ok {
					if securityEnabled, ok := g["securityEnabled"].(bool); ok && securityEnabled {
						securityGroups++
					}
					if mailEnabled, ok := g["mailEnabled"].(bool); ok && mailEnabled {
						mailGroups++
					}
				}
			}
			result.Metadata["security_groups_count"] = securityGroups
			result.Metadata["mail_groups_count"] = mailGroups
		}
	} else {
		fmt.Printf("  ❌ Failed to list groups: %s\n", op1.Error)
	}

	// Test 2: Get current user's group memberships
	op2 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/me/memberOf?$top=10&$select=id,displayName", nil)
	op2.Name = "Get User Group Memberships"
	result.Operations = append(result.Operations, op2)

	if op2.Success {
		fmt.Printf("  ✅ Successfully retrieved user group memberships\n")
		if value, ok := op2.ResponseData["value"].([]interface{}); ok {
			result.Metadata["user_group_memberships"] = len(value)
		}
	} else {
		fmt.Printf("  ❌ Failed to get user group memberships: %s\n", op2.Error)
	}

	// Determine overall success
	result.Success = true
	for _, op := range result.Operations {
		if !op.Success {
			result.Success = false
			result.Error = fmt.Sprintf("Operation '%s' failed: %s", op.Name, op.Error)
			break
		}
	}

	result.ExecutionTime = time.Since(start)
	
	if result.Success {
		fmt.Printf("  ✅ Group Management scenario completed successfully\n\n")
	} else {
		fmt.Printf("  ❌ Group Management scenario failed: %s\n\n", result.Error)
	}

	return result
}

// RunConditionalAccessScenario tests Conditional Access operations
func (sr *ScenarioRunner) RunConditionalAccessScenario(ctx context.Context) *ScenarioResult {
	start := time.Now()
	result := &ScenarioResult{
		ScenarioName: "Conditional Access",
		UserContext:  sr.userContext,
		Operations:   make([]OperationResult, 0),
		Metadata:     make(map[string]interface{}),
	}

	fmt.Printf("🔍 Running Conditional Access Scenario...\n")

	// Test 1: List Conditional Access policies
	op1 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=10", nil)
	op1.Name = "List Conditional Access Policies"
	result.Operations = append(result.Operations, op1)

	if op1.Success {
		fmt.Printf("  ✅ Successfully listed Conditional Access policies\n")
		if value, ok := op1.ResponseData["value"].([]interface{}); ok {
			result.Metadata["ca_policies_count"] = len(value)
			
			// Count enabled vs disabled policies
			enabledPolicies := 0
			for _, policy := range value {
				if p, ok := policy.(map[string]interface{}); ok {
					if state, ok := p["state"].(string); ok && state == "enabled" {
						enabledPolicies++
					}
				}
			}
			result.Metadata["ca_enabled_policies"] = enabledPolicies
		}
	} else {
		fmt.Printf("  ❌ Failed to list Conditional Access policies: %s\n", op1.Error)
		// This is expected if user doesn't have CA admin permissions
		if strings.Contains(op1.Error, "Forbidden") || strings.Contains(op1.Error, "403") {
			fmt.Printf("    (This is expected if user doesn't have Conditional Access admin permissions)\n")
			op1.Success = true
			op1.Error = "Insufficient permissions (expected for non-CA admins)"
		}
	}

	// Test 2: Get named locations (if accessible)
	op2 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations?$top=5", nil)
	op2.Name = "List Named Locations"
	result.Operations = append(result.Operations, op2)

	if op2.Success {
		fmt.Printf("  ✅ Successfully listed named locations\n")
		if value, ok := op2.ResponseData["value"].([]interface{}); ok {
			result.Metadata["named_locations_count"] = len(value)
		}
	} else {
		fmt.Printf("  ❌ Failed to list named locations: %s\n", op2.Error)
		// This is expected if user doesn't have CA admin permissions
		if strings.Contains(op2.Error, "Forbidden") || strings.Contains(op2.Error, "403") {
			fmt.Printf("    (This is expected if user doesn't have Conditional Access admin permissions)\n")
			op2.Success = true
			op2.Error = "Insufficient permissions (expected for non-CA admins)"
		}
	}

	// Determine overall success
	result.Success = true
	for _, op := range result.Operations {
		if !op.Success {
			result.Success = false
			result.Error = fmt.Sprintf("Operation '%s' failed: %s", op.Name, op.Error)
			break
		}
	}

	result.ExecutionTime = time.Since(start)
	
	if result.Success {
		fmt.Printf("  ✅ Conditional Access scenario completed successfully\n\n")
	} else {
		fmt.Printf("  ❌ Conditional Access scenario failed: %s\n\n", result.Error)
	}

	return result
}

// RunIntuneScenario tests Intune device management operations
func (sr *ScenarioRunner) RunIntuneScenario(ctx context.Context) *ScenarioResult {
	start := time.Now()
	result := &ScenarioResult{
		ScenarioName: "Intune Device Management",
		UserContext:  sr.userContext,
		Operations:   make([]OperationResult, 0),
		Metadata:     make(map[string]interface{}),
	}

	fmt.Printf("🔍 Running Intune Device Management Scenario...\n")

	// Test 1: List device configurations
	op1 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$top=10", nil)
	op1.Name = "List Device Configurations"
	result.Operations = append(result.Operations, op1)

	if op1.Success {
		fmt.Printf("  ✅ Successfully listed device configurations\n")
		if value, ok := op1.ResponseData["value"].([]interface{}); ok {
			result.Metadata["device_configs_count"] = len(value)
		}
	} else {
		fmt.Printf("  ❌ Failed to list device configurations: %s\n", op1.Error)
		// This is expected if user doesn't have Intune admin permissions
		if strings.Contains(op1.Error, "Forbidden") || strings.Contains(op1.Error, "403") {
			fmt.Printf("    (This is expected if user doesn't have Intune admin permissions)\n")
			op1.Success = true
			op1.Error = "Insufficient permissions (expected for non-Intune admins)"
		}
	}

	// Test 2: List managed devices
	op2 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=10&$select=id,deviceName,operatingSystem,complianceState", nil)
	op2.Name = "List Managed Devices"
	result.Operations = append(result.Operations, op2)

	if op2.Success {
		fmt.Printf("  ✅ Successfully listed managed devices\n")
		if value, ok := op2.ResponseData["value"].([]interface{}); ok {
			result.Metadata["managed_devices_count"] = len(value)
		}
	} else {
		fmt.Printf("  ❌ Failed to list managed devices: %s\n", op2.Error)
		// This is expected if user doesn't have Intune admin permissions
		if strings.Contains(op2.Error, "Forbidden") || strings.Contains(op2.Error, "403") {
			fmt.Printf("    (This is expected if user doesn't have Intune admin permissions)\n")
			op2.Success = true
			op2.Error = "Insufficient permissions (expected for non-Intune admins)"
		}
	}

	// Determine overall success
	result.Success = true
	for _, op := range result.Operations {
		if !op.Success {
			result.Success = false
			result.Error = fmt.Sprintf("Operation '%s' failed: %s", op.Name, op.Error)
			break
		}
	}

	result.ExecutionTime = time.Since(start)
	
	if result.Success {
		fmt.Printf("  ✅ Intune Device Management scenario completed successfully\n\n")
	} else {
		fmt.Printf("  ❌ Intune Device Management scenario failed: %s\n\n", result.Error)
	}

	return result
}

// RunAuditLogScenario tests audit log access
func (sr *ScenarioRunner) RunAuditLogScenario(ctx context.Context) *ScenarioResult {
	start := time.Now()
	result := &ScenarioResult{
		ScenarioName: "Audit Logs",
		UserContext:  sr.userContext,
		Operations:   make([]OperationResult, 0),
		Metadata:     make(map[string]interface{}),
	}

	fmt.Printf("🔍 Running Audit Logs Scenario...\n")

	// Test 1: Get sign-in logs (limited to recent entries)
	op1 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=5&$select=createdDateTime,userDisplayName,appDisplayName,status", nil)
	op1.Name = "Get Sign-in Logs"
	result.Operations = append(result.Operations, op1)

	if op1.Success {
		fmt.Printf("  ✅ Successfully retrieved sign-in logs\n")
		if value, ok := op1.ResponseData["value"].([]interface{}); ok {
			result.Metadata["signin_logs_count"] = len(value)
		}
	} else {
		fmt.Printf("  ❌ Failed to get sign-in logs: %s\n", op1.Error)
		// This is expected if user doesn't have audit log reader permissions
		if strings.Contains(op1.Error, "Forbidden") || strings.Contains(op1.Error, "403") {
			fmt.Printf("    (This is expected if user doesn't have audit log reader permissions)\n")
			op1.Success = true
			op1.Error = "Insufficient permissions (expected for non-security admins)"
		}
	}

	// Test 2: Get directory audit logs
	op2 := sr.makeGraphRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=5&$select=activityDateTime,activityDisplayName,initiatedBy,targetResources", nil)
	op2.Name = "Get Directory Audit Logs"
	result.Operations = append(result.Operations, op2)

	if op2.Success {
		fmt.Printf("  ✅ Successfully retrieved directory audit logs\n")
		if value, ok := op2.ResponseData["value"].([]interface{}); ok {
			result.Metadata["directory_audit_logs_count"] = len(value)
		}
	} else {
		fmt.Printf("  ❌ Failed to get directory audit logs: %s\n", op2.Error)
		// This is expected if user doesn't have audit log reader permissions
		if strings.Contains(op2.Error, "Forbidden") || strings.Contains(op2.Error, "403") {
			fmt.Printf("    (This is expected if user doesn't have audit log reader permissions)\n")
			op2.Success = true
			op2.Error = "Insufficient permissions (expected for non-security admins)"
		}
	}

	// Determine overall success
	result.Success = true
	for _, op := range result.Operations {
		if !op.Success {
			result.Success = false
			result.Error = fmt.Sprintf("Operation '%s' failed: %s", op.Name, op.Error)
			break
		}
	}

	result.ExecutionTime = time.Since(start)
	
	if result.Success {
		fmt.Printf("  ✅ Audit Logs scenario completed successfully\n\n")
	} else {
		fmt.Printf("  ❌ Audit Logs scenario failed: %s\n\n", result.Error)
	}

	return result
}

// makeGraphRequest makes a Microsoft Graph API request
func (sr *ScenarioRunner) makeGraphRequest(ctx context.Context, method, url string, body interface{}) OperationResult {
	start := time.Now()
	
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return OperationResult{
			Method:    method,
			URL:       url,
			Success:   false,
			Error:     fmt.Sprintf("Failed to create request: %v", err),
			Duration:  time.Since(start),
		}
	}

	// Set headers
	req.Header.Set("Authorization", sr.token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := sr.httpClient.Do(req)
	if err != nil {
		return OperationResult{
			Method:    method,
			URL:       url,
			Success:   false,
			Error:     fmt.Sprintf("Request failed: %v", err),
			Duration:  time.Since(start),
		}
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
			_ = err
		}
	}()

	// Parse response
	var responseData map[string]interface{}
	if resp.Header.Get("Content-Type") != "" && 
	   strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		decoder := json.NewDecoder(resp.Body)
		if err := decoder.Decode(&responseData); err != nil {
			return OperationResult{
				Method:     method,
				URL:        url,
				StatusCode: resp.StatusCode,
				Success:    false,
				Error:      fmt.Sprintf("Failed to parse JSON response: %v", err),
				Duration:   time.Since(start),
			}
		}
	}

	// Check for success
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	var errorMessage string
	if !success {
		if responseData != nil {
			if errorObj, ok := responseData["error"].(map[string]interface{}); ok {
				if code, ok := errorObj["code"].(string); ok {
					if message, ok := errorObj["message"].(string); ok {
						errorMessage = fmt.Sprintf("%s: %s", code, message)
					} else {
						errorMessage = code
					}
				}
			}
		}
		if errorMessage == "" {
			errorMessage = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
	}

	return OperationResult{
		Method:       method,
		URL:          url,
		StatusCode:   resp.StatusCode,
		Success:      success,
		Error:        errorMessage,
		ResponseData: responseData,
		Duration:     time.Since(start),
	}
}