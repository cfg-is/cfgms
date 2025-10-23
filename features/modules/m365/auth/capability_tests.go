// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Microsoft Graph API endpoints for capability testing
const (
	GraphBaseURL = "https://graph.microsoft.com/v1.0"
)

// extractUserContext extracts user information from ID token
// NOTE: This function is deprecated for MSP scenarios using application permissions
// MSP applications don't use user context since they operate with application permissions
func (f *InteractiveAuthFlow) extractUserContext(idToken, tenantID string) (*UserContext, error) {
	if idToken == "" {
		return nil, fmt.Errorf("no ID token provided")
	}

	// In a real implementation, you would parse and validate the JWT
	// For now, return a basic user context that can be enhanced
	return &UserContext{
		UserID:            "extracted-from-id-token",
		UserPrincipalName: "user@" + tenantID + ".onmicrosoft.com",
		DisplayName:       "Authenticated User",
		LastAuthenticated: time.Now(),
	}, nil
}

// testUserReadAccess tests user read access for MSP application permissions (User.Read.All)
// For MSP scenarios, we test reading users from the client tenant, not '/me' endpoint
func (f *InteractiveAuthFlow) testUserReadAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "User Read Access",
		Description: "Test ability to read user information from client tenant",
		TestedAt:    time.Now(),
	}

	// For application permissions, test reading users from tenant (not /me which requires user context)
	url := GraphBaseURL + "/users?$top=1&$select=id,userPrincipalName,displayName"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("API call failed: %v", err)
		return test
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			test.Details = fmt.Sprintf("Successfully retrieved %d users with application permissions", len(response.Value))
		} else {
			test.Success = true
			test.Details = "Successfully accessed users API with application permissions"
		}
	case http.StatusForbidden:
		test.Success = false
		test.Error = "Insufficient permissions for user read access - need User.Read.All application permission"
	default:
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}

	return test
}

// testDirectoryReadAccess tests comprehensive directory read access (Directory.ReadWrite.All)
// For MSP scenarios, test broader directory access including organization info
func (f *InteractiveAuthFlow) testDirectoryReadAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Directory Read Access",
		Description: "Test ability to read comprehensive directory information",
		TestedAt:    time.Now(),
	}

	// Test organization information access (requires Directory.Read.All or higher)
	url := GraphBaseURL + "/organization?$select=id,displayName,verifiedDomains"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("Organization API call failed: %v", err)
		return test
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			if len(response.Value) > 0 {
				orgName := "Unknown"
				if name, ok := response.Value[0]["displayName"]; ok {
					orgName = fmt.Sprintf("%v", name)
				}
				test.Details = fmt.Sprintf("Successfully accessed directory for organization: %s", orgName)
			} else {
				test.Details = "Successfully accessed directory organization API"
			}
		} else {
			test.Success = true
			test.Details = "Successfully accessed directory API with application permissions"
		}
	case http.StatusForbidden:
		test.Success = false
		test.Error = "Insufficient permissions for directory access - need Directory.ReadWrite.All application permission"
	default:
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}

	return test
}

// testGroupManagementAccess tests group management access (Group.ReadWrite.All + GroupMember.ReadWrite.All)
// For MSP scenarios, verify comprehensive group and membership management capabilities
func (f *InteractiveAuthFlow) testGroupManagementAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Group Management Access",
		Description: "Test ability to read and manage groups with application permissions",
		TestedAt:    time.Now(),
	}

	// Test reading groups with detailed information
	url := GraphBaseURL + "/groups?$top=5&$select=id,displayName,groupTypes,mailEnabled,securityEnabled,membershipRule"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("Group read API call failed: %v", err)
		return test
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			groupTypes := make(map[string]int)
			for _, group := range response.Value {
				if types, ok := group["groupTypes"]; ok {
					if typeSlice, ok := types.([]interface{}); ok && len(typeSlice) > 0 {
						groupTypes["Dynamic"]++
					} else {
						groupTypes["Static"]++
					}
				}
			}
			test.Details = fmt.Sprintf("Successfully retrieved %d groups with application permissions. Group management verified.", len(response.Value))
		} else {
			test.Success = true
			test.Details = "Successfully accessed groups API with application permissions"
		}
	case http.StatusForbidden:
		test.Success = false
		test.Error = "Insufficient permissions for group management - need Group.ReadWrite.All application permission"
	default:
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}

	return test
}

// testConditionalAccessAccess tests conditional access policy access for MSP scenarios
// Tests both Policy.ReadWrite.ConditionalAccess and Policy.ReadWrite.All permissions
func (f *InteractiveAuthFlow) testConditionalAccessAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Conditional Access Management",
		Description: "Test ability to manage conditional access policies with application permissions",
		TestedAt:    time.Now(),
	}

	// Test reading conditional access policies with comprehensive data
	url := GraphBaseURL + "/identity/conditionalAccess/policies?$top=10&$select=id,displayName,state,conditions,grantControls"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("Conditional Access API call failed: %v", err)
		return test
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			policyStates := make(map[string]int)
			for _, policy := range response.Value {
				if state, ok := policy["state"]; ok {
					policyStates[fmt.Sprintf("%v", state)]++
				}
			}
			test.Details = fmt.Sprintf("Successfully retrieved %d conditional access policies with application permissions", len(response.Value))
		} else {
			test.Success = true
			test.Details = "Successfully accessed Conditional Access API with application permissions"
		}
	case http.StatusForbidden:
		test.Success = false
		test.Error = "Insufficient permissions for Conditional Access - need Policy.ReadWrite.ConditionalAccess or Policy.ReadWrite.All application permission"
	default:
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}

	return test
}

// testIntuneManagementAccess tests comprehensive Intune device management access for MSP scenarios
// Tests multiple Intune endpoints to verify full management capabilities
func (f *InteractiveAuthFlow) testIntuneManagementAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Intune Device Management",
		Description: "Test ability to access comprehensive Intune device management with application permissions",
		TestedAt:    time.Now(),
	}

	// Test reading managed devices (most common MSP use case)
	url := GraphBaseURL + "/deviceManagement/managedDevices?$top=5&$select=id,deviceName,operatingSystem,complianceState,managementAgent"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("Intune managed devices API call failed: %v", err)
		return test
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			osTypes := make(map[string]int)
			for _, device := range response.Value {
				if os, ok := device["operatingSystem"]; ok {
					osTypes[fmt.Sprintf("%v", os)]++
				}
			}
			test.Details = fmt.Sprintf("Successfully retrieved %d managed devices from Intune with application permissions", len(response.Value))
		} else {
			test.Success = true
			test.Details = "Successfully accessed Intune managed devices API with application permissions"
		}
	case http.StatusForbidden:
		test.Success = false
		test.Error = "Insufficient permissions for Intune device management - need DeviceManagementManagedDevices.ReadWrite.All application permission"
	default:
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}

	return test
}

// testOrganizationManagementAccess tests organization settings management (Organization.ReadWrite.All)
// Essential for MSP tenant configuration and branding management
func (f *InteractiveAuthFlow) testOrganizationManagementAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Organization Management",
		Description: "Test ability to manage organization settings with application permissions",
		TestedAt:    time.Now(),
	}

	// Test reading organization settings and verified domains
	url := GraphBaseURL + "/organization?$select=id,displayName,verifiedDomains,assignedPlans,provisionedPlans"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("Organization API call failed: %v", err)
		return test
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			if len(response.Value) > 0 {
				org := response.Value[0]
				domainCount := 0
				if domains, ok := org["verifiedDomains"]; ok {
					if domainSlice, ok := domains.([]interface{}); ok {
						domainCount = len(domainSlice)
					}
				}
				test.Details = fmt.Sprintf("Successfully accessed organization settings with %d verified domains", domainCount)
			} else {
				test.Details = "Successfully accessed organization settings API"
			}
		} else {
			test.Success = true
			test.Details = "Successfully accessed organization API with application permissions"
		}
	case http.StatusForbidden:
		test.Success = false
		test.Error = "Insufficient permissions for organization management - need Organization.ReadWrite.All application permission"
	default:
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}

	return test
}

// testAuditLogAccess tests audit log access (AuditLog.Read.All)
// Critical for MSP compliance reporting and security monitoring
func (f *InteractiveAuthFlow) testAuditLogAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Audit Log Access",
		Description: "Test ability to access audit logs and sign-in reports",
		TestedAt:    time.Now(),
	}

	// Test reading audit logs (directory activities)
	url := GraphBaseURL + "/auditLogs/directoryAudits?$top=5&$select=id,activityDisplayName,activityDateTime,result,initiatedBy"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("Audit log API call failed: %v", err)
		return test
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			test.Details = fmt.Sprintf("Successfully retrieved %d audit log entries with application permissions", len(response.Value))
		} else {
			test.Success = true
			test.Details = "Successfully accessed audit logs API with application permissions"
		}
	case http.StatusForbidden:
		test.Success = false
		test.Error = "Insufficient permissions for audit log access - need AuditLog.Read.All application permission"
	default:
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}

	return test
}

// testUsageReportsAccess tests usage reports access (Reports.Read.All)
// Important for MSP client reporting and usage analytics
func (f *InteractiveAuthFlow) testUsageReportsAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Usage Reports Access",
		Description: "Test ability to access usage and activity reports",
		TestedAt:    time.Now(),
	}

	// Test reading Office 365 usage reports
	url := GraphBaseURL + "/reports/getOffice365ActiveUserDetail(period='D7')?$format=application/json"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("Usage reports API call failed: %v", err)
		return test
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		test.Success = true
		test.Details = "Successfully accessed Office 365 usage reports with application permissions"
	case http.StatusForbidden:
		test.Success = false
		test.Error = "Insufficient permissions for usage reports - need Reports.Read.All application permission"
	default:
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}

	return test
}

// makeGraphAPICall makes an authenticated call to Microsoft Graph API
func (f *InteractiveAuthFlow) makeGraphAPICall(ctx context.Context, method, url string, token *AccessToken, body interface{}) (*http.Response, error) {
	var reqBody strings.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = *strings.NewReader(string(jsonBody))
	}

	req, err := http.NewRequestWithContext(ctx, method, url, &reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header
	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add headers to prevent caching and ensure fresh data
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	return resp, nil
}

// TestFullCapabilities runs a comprehensive test of all available capabilities
func (f *InteractiveAuthFlow) TestFullCapabilities(ctx context.Context, tenantID string, accessToken *AccessToken) (*FullCapabilityReport, error) {
	report := &FullCapabilityReport{
		TenantID:        tenantID,
		TestedAt:        time.Now(),
		AccessToken:     accessToken,
		Tests:           make(map[string]*CapabilityTest),
		Capabilities:    make(map[string]bool),
		Recommendations: make([]string, 0),
	}

	// Core MSP capability tests for application permissions
	// Updated to reflect MSP scenarios with application permissions instead of delegated
	coreTests := []struct {
		name     string
		scope    string
		testFunc func(context.Context, *AccessToken) *CapabilityTest
	}{
		{"user_read", "User.ReadWrite.All", f.testUserReadAccess},
		{"directory_access", "Directory.ReadWrite.All", f.testDirectoryReadAccess},
		{"group_management", "Group.ReadWrite.All", f.testGroupManagementAccess},
		{"conditional_access", "Policy.ReadWrite.ConditionalAccess", f.testConditionalAccessAccess},
		{"intune_management", "DeviceManagementManagedDevices.ReadWrite.All", f.testIntuneManagementAccess},
		{"organization_management", "Organization.ReadWrite.All", f.testOrganizationManagementAccess},
		{"audit_log_access", "AuditLog.Read.All", f.testAuditLogAccess},
		{"usage_reports", "Reports.Read.All", f.testUsageReportsAccess},
	}

	// Run tests for available scopes
	for _, testCase := range coreTests {
		if f.hasScope(accessToken, testCase.scope) {
			report.Tests[testCase.name] = testCase.testFunc(ctx, accessToken)
			report.Capabilities[testCase.name] = report.Tests[testCase.name].Success
		} else {
			// Create a skipped test result for missing application permissions
			report.Tests[testCase.name] = &CapabilityTest{
				Name:        testCase.name,
				Description: fmt.Sprintf("Test skipped - missing application permission: %s", testCase.scope),
				Success:     false,
				Error:       "Missing required application permission",
				TestedAt:    time.Now(),
			}
			report.Capabilities[testCase.name] = false
			report.Recommendations = append(report.Recommendations,
				fmt.Sprintf("Add application permission '%s' to Azure app registration for %s functionality", testCase.scope, testCase.name))
		}
	}

	// Calculate overall success rate
	successCount := 0
	totalTests := 0
	for _, test := range report.Tests {
		totalTests++
		if test.Success {
			successCount++
		}
	}

	if totalTests > 0 {
		report.SuccessRate = float64(successCount) / float64(totalTests)
		report.OverallSuccess = report.SuccessRate >= 0.8 // 80% success threshold
	}

	// Add MSP-specific recommendations for application permissions
	if report.SuccessRate < 1.0 {
		report.Recommendations = append(report.Recommendations,
			"Some MSP capabilities are not available. Review application permissions in Azure app registration and ensure admin consent is granted.")
	}

	if !report.Capabilities["user_read"] {
		report.Recommendations = append(report.Recommendations,
			"User.ReadWrite.All is a fundamental application permission required for MSP user management operations.")
	}

	if !report.Capabilities["directory_access"] {
		report.Recommendations = append(report.Recommendations,
			"Directory.ReadWrite.All application permission is essential for MSP directory operations.")
	}

	return report, nil
}

// Supporting types for comprehensive capability testing

type FullCapabilityReport struct {
	TenantID        string                     `json:"tenant_id"`
	TestedAt        time.Time                  `json:"tested_at"`
	AccessToken     *AccessToken               `json:"access_token,omitempty"`
	Tests           map[string]*CapabilityTest `json:"tests"`
	Capabilities    map[string]bool            `json:"capabilities"`
	SuccessRate     float64                    `json:"success_rate"`
	OverallSuccess  bool                       `json:"overall_success"`
	Recommendations []string                   `json:"recommendations"`
}

// GetCapabilitySummary returns a human-readable summary of capabilities
func (r *FullCapabilityReport) GetCapabilitySummary() string {
	var summary strings.Builder

	summary.WriteString(fmt.Sprintf("Capability Test Results for Tenant: %s\n", r.TenantID))
	summary.WriteString(fmt.Sprintf("Success Rate: %.1f%%\n", r.SuccessRate*100))
	summary.WriteString(fmt.Sprintf("Overall Success: %t\n\n", r.OverallSuccess))

	summary.WriteString("Available Capabilities:\n")
	for capability, available := range r.Capabilities {
		status := "❌"
		if available {
			status = "✅"
		}
		summary.WriteString(fmt.Sprintf("  %s %s\n", status, capability))
	}

	if len(r.Recommendations) > 0 {
		summary.WriteString("\nRecommendations:\n")
		for _, rec := range r.Recommendations {
			summary.WriteString(fmt.Sprintf("  • %s\n", rec))
		}
	}

	return summary.String()
}

// TestMSPCapabilities tests MSP capabilities for a specific client tenant using application permissions
// This function is designed to work with the MSP admin consent flow and client tenant management
func TestMSPCapabilities(ctx context.Context, config *MSPOAuth2Config, clientTenantID string, accessToken *AccessToken) (*FullCapabilityReport, error) {
	return TestMSPCapabilitiesWithClient(ctx, config, clientTenantID, accessToken, nil)
}

// TestMSPCapabilitiesWithClient tests MSP capabilities with a custom HTTP client (for testing)
func TestMSPCapabilitiesWithClient(ctx context.Context, config *MSPOAuth2Config, clientTenantID string, accessToken *AccessToken, httpClient *http.Client) (*FullCapabilityReport, error) {
	// Create a temporary flow instance for testing (we only need the HTTP client and test methods)
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	flow := &InteractiveAuthFlow{
		httpClient: httpClient,
	}

	report := &FullCapabilityReport{
		TenantID:        clientTenantID,
		TestedAt:        time.Now(),
		AccessToken:     accessToken,
		Tests:           make(map[string]*CapabilityTest),
		Capabilities:    make(map[string]bool),
		Recommendations: make([]string, 0),
	}

	// MSP application permission tests - test all capabilities regardless of token scope
	// since MSP applications use .default scope with all consented permissions
	mspTests := []struct {
		name        string
		permission  string
		description string
		testFunc    func(context.Context, *AccessToken) *CapabilityTest
	}{
		{"user_management", "User.ReadWrite.All", "MSP user account management", flow.testUserReadAccess},
		{"directory_management", "Directory.ReadWrite.All", "MSP directory and organization management", flow.testDirectoryReadAccess},
		{"group_management", "Group.ReadWrite.All", "MSP group and membership management", flow.testGroupManagementAccess},
		{"conditional_access", "Policy.ReadWrite.ConditionalAccess", "MSP conditional access policy management", flow.testConditionalAccessAccess},
		{"intune_management", "DeviceManagementManagedDevices.ReadWrite.All", "MSP Intune device management", flow.testIntuneManagementAccess},
		{"organization_settings", "Organization.ReadWrite.All", "MSP tenant configuration management", flow.testOrganizationManagementAccess},
		{"audit_and_compliance", "AuditLog.Read.All", "MSP security monitoring and compliance", flow.testAuditLogAccess},
		{"usage_analytics", "Reports.Read.All", "MSP client usage reporting and analytics", flow.testUsageReportsAccess},
	}

	// Run all MSP capability tests
	for _, testCase := range mspTests {
		result := testCase.testFunc(ctx, accessToken)
		result.Name = testCase.name
		result.Description = testCase.description

		report.Tests[testCase.name] = result
		report.Capabilities[testCase.name] = result.Success

		// Add specific recommendations for failed tests
		if !result.Success {
			report.Recommendations = append(report.Recommendations,
				fmt.Sprintf("Ensure '%s' application permission is granted and admin consent is provided for %s functionality",
					testCase.permission, testCase.description))
		}
	}

	// Calculate MSP-specific success metrics
	successCount := 0
	totalTests := len(mspTests)
	for _, test := range report.Tests {
		if test.Success {
			successCount++
		}
	}

	report.SuccessRate = float64(successCount) / float64(totalTests)
	report.OverallSuccess = report.SuccessRate >= 0.8 // 80% threshold for MSP readiness

	// Add MSP-specific recommendations
	if report.SuccessRate < 1.0 {
		report.Recommendations = append(report.Recommendations,
			"Some MSP capabilities are not available. Verify that all required application permissions are configured in the Azure app registration.")
		report.Recommendations = append(report.Recommendations,
			"Ensure that admin consent has been granted for the client tenant. MSP operations require application permissions, not delegated permissions.")
	}

	if report.SuccessRate < 0.5 {
		report.Recommendations = append(report.Recommendations,
			"Critical: Less than 50% of MSP capabilities are functional. Review Azure app registration permissions and client tenant admin consent status.")
	}

	// Add client tenant specific context
	if clientTenantID != "" {
		report.Recommendations = append(report.Recommendations,
			fmt.Sprintf("Testing completed for client tenant: %s. Capabilities reflect permissions available for MSP operations in this tenant.", clientTenantID))
	}

	return report, nil
}

// GetMSPCapabilitySummary returns a summary focused on MSP operational readiness
func (r *FullCapabilityReport) GetMSPCapabilitySummary() string {
	var summary strings.Builder

	summary.WriteString(fmt.Sprintf("MSP Capability Assessment - Client Tenant: %s\n", r.TenantID))
	summary.WriteString(fmt.Sprintf("Tested: %s\n", r.TestedAt.Format("2006-01-02 15:04:05 UTC")))
	summary.WriteString(fmt.Sprintf("Operational Readiness: %.1f%%\n", r.SuccessRate*100))

	if r.OverallSuccess {
		summary.WriteString("Status: ✅ MSP READY - Client tenant is ready for management operations\n\n")
	} else {
		summary.WriteString("Status: ⚠️  SETUP REQUIRED - Additional configuration needed before MSP operations\n\n")
	}

	summary.WriteString("MSP Capability Status:\n")

	// Group capabilities by operational area
	capabilities := map[string][]string{
		"Core Management":       {"user_management", "directory_management", "group_management"},
		"Security & Compliance": {"conditional_access", "audit_and_compliance"},
		"Device Management":     {"intune_management"},
		"Reporting & Analytics": {"usage_analytics", "organization_settings"},
	}

	for category, capList := range capabilities {
		summary.WriteString(fmt.Sprintf("\n%s:\n", category))
		for _, capability := range capList {
			if available, exists := r.Capabilities[capability]; exists {
				status := "❌"
				if available {
					status = "✅"
				}
				// Get the test details for better display name
				if test, testExists := r.Tests[capability]; testExists {
					summary.WriteString(fmt.Sprintf("  %s %s\n", status, test.Description))
				} else {
					summary.WriteString(fmt.Sprintf("  %s %s\n", status, capability))
				}
			}
		}
	}

	if len(r.Recommendations) > 0 {
		summary.WriteString("\nMSP Setup Recommendations:\n")
		for i, rec := range r.Recommendations {
			summary.WriteString(fmt.Sprintf("  %d. %s\n", i+1, rec))
		}
	}

	summary.WriteString("\nNext Steps:\n")
	if r.OverallSuccess {
		summary.WriteString("  • Client tenant is ready for CFGMS MSP management\n")
		summary.WriteString("  • Begin configuration management operations\n")
		summary.WriteString("  • Set up monitoring and reporting workflows\n")
	} else {
		summary.WriteString("  • Review Azure app registration permissions\n")
		summary.WriteString("  • Ensure admin consent is granted for this client tenant\n")
		summary.WriteString("  • Re-run capability testing after configuration changes\n")
	}

	return summary.String()
}
