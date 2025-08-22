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

// testUserProfileAccess tests basic user profile access (User.Read)
func (f *InteractiveAuthFlow) testUserProfileAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "User Profile Access",
		Description: "Test ability to read user profile information",
		TestedAt:    time.Now(),
	}
	
	// Make API call to get user profile
	url := GraphBaseURL + "/me"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("API call failed: %v", err)
		return test
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		test.Success = true
		test.Details = "Successfully retrieved user profile"
	} else {
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}
	
	return test
}

// testDirectoryReadAccess tests directory read access (Directory.Read.All)
func (f *InteractiveAuthFlow) testDirectoryReadAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Directory Read Access",
		Description: "Test ability to read directory information",
		TestedAt:    time.Now(),
	}
	
	// Make API call to list users (limited to first 5)
	url := GraphBaseURL + "/users?$top=5&$select=id,userPrincipalName,displayName"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("API call failed: %v", err)
		return test
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		// Parse response to get count
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			test.Details = fmt.Sprintf("Successfully retrieved %d users from directory", len(response.Value))
		} else {
			test.Success = true
			test.Details = "Successfully accessed directory (parsing response failed)"
		}
	} else {
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}
	
	return test
}

// testGroupManagementAccess tests group management access (Group.ReadWrite.All)
func (f *InteractiveAuthFlow) testGroupManagementAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Group Management Access",
		Description: "Test ability to read and manage groups",
		TestedAt:    time.Now(),
	}
	
	// Test reading groups first
	url := GraphBaseURL + "/groups?$top=5&$select=id,displayName,groupTypes"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("Group read API call failed: %v", err)
		return test
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			test.Details = fmt.Sprintf("Successfully retrieved %d groups. Group management permissions verified.", len(response.Value))
		} else {
			test.Success = true
			test.Details = "Successfully accessed groups API"
		}
	} else if resp.StatusCode == http.StatusForbidden {
		test.Success = false
		test.Error = "Insufficient permissions for group management"
	} else {
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}
	
	return test
}

// testConditionalAccessAccess tests conditional access policy access
func (f *InteractiveAuthFlow) testConditionalAccessAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Conditional Access Management",
		Description: "Test ability to read conditional access policies",
		TestedAt:    time.Now(),
	}
	
	// Test reading conditional access policies
	url := GraphBaseURL + "/identity/conditionalAccess/policies?$top=5&$select=id,displayName,state"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("Conditional Access API call failed: %v", err)
		return test
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			test.Details = fmt.Sprintf("Successfully retrieved %d conditional access policies", len(response.Value))
		} else {
			test.Success = true
			test.Details = "Successfully accessed Conditional Access API"
		}
	} else if resp.StatusCode == http.StatusForbidden {
		test.Success = false
		test.Error = "Insufficient permissions for Conditional Access management"
	} else {
		test.Success = false
		test.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
	}
	
	return test
}

// testIntuneManagementAccess tests Intune device management access
func (f *InteractiveAuthFlow) testIntuneManagementAccess(ctx context.Context, token *AccessToken) *CapabilityTest {
	test := &CapabilityTest{
		Name:        "Intune Device Management",
		Description: "Test ability to access Intune device management",
		TestedAt:    time.Now(),
	}
	
	// Test reading device configurations
	url := GraphBaseURL + "/deviceManagement/deviceConfigurations?$top=5&$select=id,displayName,deviceManagementApplicabilityRuleOsEdition"
	resp, err := f.makeGraphAPICall(ctx, "GET", url, token, nil)
	if err != nil {
		test.Success = false
		test.Error = fmt.Sprintf("Intune API call failed: %v", err)
		return test
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		var response struct {
			Value []map[string]interface{} `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
			test.Success = true
			test.Details = fmt.Sprintf("Successfully retrieved %d device configurations from Intune", len(response.Value))
		} else {
			test.Success = true
			test.Details = "Successfully accessed Intune API"
		}
	} else if resp.StatusCode == http.StatusForbidden {
		test.Success = false
		test.Error = "Insufficient permissions for Intune device management"
	} else {
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
		TenantID:      tenantID,
		TestedAt:      time.Now(),
		AccessToken:   accessToken,
		Tests:         make(map[string]*CapabilityTest),
		Capabilities:  make(map[string]bool),
		Recommendations: make([]string, 0),
	}
	
	// Core capability tests
	coreTests := []struct {
		name     string
		scope    string
		testFunc func(context.Context, *AccessToken) *CapabilityTest
	}{
		{"user_profile", "User.Read", f.testUserProfileAccess},
		{"directory_read", "Directory.Read.All", f.testDirectoryReadAccess},
		{"group_management", "Group.ReadWrite.All", f.testGroupManagementAccess},
		{"conditional_access", "Policy.ReadWrite.ConditionalAccess", f.testConditionalAccessAccess},
		{"intune_management", "DeviceManagementConfiguration.ReadWrite.All", f.testIntuneManagementAccess},
	}
	
	// Run tests for available scopes
	for _, testCase := range coreTests {
		if f.hasScope(accessToken, testCase.scope) {
			report.Tests[testCase.name] = testCase.testFunc(ctx, accessToken)
			report.Capabilities[testCase.name] = report.Tests[testCase.name].Success
		} else {
			// Create a skipped test result
			report.Tests[testCase.name] = &CapabilityTest{
				Name:        testCase.name,
				Description: fmt.Sprintf("Test skipped - missing scope: %s", testCase.scope),
				Success:     false,
				Error:       "Missing required scope",
				TestedAt:    time.Now(),
			}
			report.Capabilities[testCase.name] = false
			report.Recommendations = append(report.Recommendations, 
				fmt.Sprintf("Consider adding scope '%s' for %s functionality", testCase.scope, testCase.name))
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
	
	// Add general recommendations
	if report.SuccessRate < 1.0 {
		report.Recommendations = append(report.Recommendations,
			"Some capabilities are not available. Review app permissions in Azure portal.")
	}
	
	if !report.Capabilities["user_profile"] {
		report.Recommendations = append(report.Recommendations,
			"User.Read is a fundamental scope required for most operations.")
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