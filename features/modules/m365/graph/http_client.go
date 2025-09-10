package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
)

// HTTPClient implements the Client interface using HTTP requests to Microsoft Graph API
type HTTPClient struct {
	// HTTP client for making requests
	httpClient *http.Client

	// Base URL for Microsoft Graph API
	baseURL string

	// Rate limiter for API requests
	rateLimiter RateLimiter

	// Retry configuration
	retryConfig *RetryConfig
}

// NewHTTPClient creates a new HTTP-based Graph API client
func NewHTTPClient(options ...ClientOption) *HTTPClient {
	client := &HTTPClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:     "https://graph.microsoft.com/v1.0",
		retryConfig: DefaultRetryConfig(),
	}

	// Apply options
	for _, option := range options {
		option(client)
	}

	return client
}

// ClientOption defines a functional option for configuring the Graph client
type ClientOption func(*HTTPClient)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *HTTPClient) {
		c.httpClient = httpClient
	}
}

// WithBaseURL sets a custom base URL (useful for testing)
func WithBaseURL(baseURL string) ClientOption {
	return func(c *HTTPClient) {
		c.baseURL = strings.TrimSuffix(baseURL, "/")
	}
}

// WithRateLimiter sets a rate limiter for API requests
func WithRateLimiter(rateLimiter RateLimiter) ClientOption {
	return func(c *HTTPClient) {
		c.rateLimiter = rateLimiter
	}
}

// WithRetryConfig sets retry configuration
func WithRetryConfig(retryConfig *RetryConfig) ClientOption {
	return func(c *HTTPClient) {
		c.retryConfig = retryConfig
	}
}

// GetUser retrieves a user by user principal name
func (c *HTTPClient) GetUser(ctx context.Context, token *auth.AccessToken, userPrincipalName string) (*User, error) {
	// URL encode the UPN to handle special characters
	encodedUPN := url.QueryEscape(userPrincipalName)
	endpoint := fmt.Sprintf("/users/%s", encodedUPN)

	var user User
	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &user); err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// ListUsers retrieves users with optional OData filter
func (c *HTTPClient) ListUsers(ctx context.Context, token *auth.AccessToken, filter string) ([]User, error) {
	endpoint := "/users"
	if filter != "" {
		endpoint = fmt.Sprintf("/users?$filter=%s", url.QueryEscape(filter))
	}

	var response struct {
		Value []User `json:"value"`
	}

	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &response); err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	return response.Value, nil
}

// CreateUser creates a new user
func (c *HTTPClient) CreateUser(ctx context.Context, token *auth.AccessToken, request *CreateUserRequest) (*User, error) {
	endpoint := "/users"

	var user User
	if err := c.makeRequest(ctx, token, "POST", endpoint, request, &user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &user, nil
}

// UpdateUser updates an existing user
func (c *HTTPClient) UpdateUser(ctx context.Context, token *auth.AccessToken, userID string, request *UpdateUserRequest) error {
	endpoint := fmt.Sprintf("/users/%s", userID)

	if err := c.makeRequest(ctx, token, "PATCH", endpoint, request, nil); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// DeleteUser deletes a user
func (c *HTTPClient) DeleteUser(ctx context.Context, token *auth.AccessToken, userID string) error {
	endpoint := fmt.Sprintf("/users/%s", userID)

	if err := c.makeRequest(ctx, token, "DELETE", endpoint, nil, nil); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// GetUserLicenses retrieves license assignments for a user
func (c *HTTPClient) GetUserLicenses(ctx context.Context, token *auth.AccessToken, userID string) ([]LicenseAssignment, error) {
	endpoint := fmt.Sprintf("/users/%s/licenseDetails", userID)

	var response struct {
		Value []struct {
			SkuID        string `json:"skuId"`
			ServicePlans []struct {
				ServicePlanId      string `json:"servicePlanId"`
				ProvisioningStatus string `json:"provisioningStatus"`
			} `json:"servicePlans"`
		} `json:"value"`
	}

	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &response); err != nil {
		return nil, fmt.Errorf("failed to get user licenses: %w", err)
	}

	var licenses []LicenseAssignment
	for _, license := range response.Value {
		assignment := LicenseAssignment{
			SkuID: license.SkuID,
		}

		// Collect disabled service plans
		for _, plan := range license.ServicePlans {
			if plan.ProvisioningStatus == "Disabled" {
				assignment.DisabledPlans = append(assignment.DisabledPlans, plan.ServicePlanId)
			}
		}

		licenses = append(licenses, assignment)
	}

	return licenses, nil
}

// AssignLicense assigns a license to a user
func (c *HTTPClient) AssignLicense(ctx context.Context, token *auth.AccessToken, userID, skuID string, disabledPlans []string) error {
	endpoint := fmt.Sprintf("/users/%s/assignLicense", userID)

	request := struct {
		AddLicenses []struct {
			SkuID         string   `json:"skuId"`
			DisabledPlans []string `json:"disabledPlans"`
		} `json:"addLicenses"`
		RemoveLicenses []string `json:"removeLicenses"`
	}{
		AddLicenses: []struct {
			SkuID         string   `json:"skuId"`
			DisabledPlans []string `json:"disabledPlans"`
		}{
			{
				SkuID:         skuID,
				DisabledPlans: disabledPlans,
			},
		},
		RemoveLicenses: []string{},
	}

	if err := c.makeRequest(ctx, token, "POST", endpoint, request, nil); err != nil {
		return fmt.Errorf("failed to assign license: %w", err)
	}

	return nil
}

// RemoveLicense removes a license from a user
func (c *HTTPClient) RemoveLicense(ctx context.Context, token *auth.AccessToken, userID, skuID string) error {
	endpoint := fmt.Sprintf("/users/%s/assignLicense", userID)

	request := struct {
		AddLicenses    []interface{} `json:"addLicenses"`
		RemoveLicenses []string      `json:"removeLicenses"`
	}{
		AddLicenses:    []interface{}{},
		RemoveLicenses: []string{skuID},
	}

	if err := c.makeRequest(ctx, token, "POST", endpoint, request, nil); err != nil {
		return fmt.Errorf("failed to remove license: %w", err)
	}

	return nil
}

// GetUserGroups retrieves group memberships for a user
func (c *HTTPClient) GetUserGroups(ctx context.Context, token *auth.AccessToken, userID string) ([]string, error) {
	endpoint := fmt.Sprintf("/users/%s/memberOf", userID)

	var response struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			ODataType   string `json:"@odata.type"`
		} `json:"value"`
	}

	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &response); err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}

	var groups []string
	for _, group := range response.Value {
		// Only include security groups and mail-enabled security groups
		if group.ODataType == "#microsoft.graph.group" {
			groups = append(groups, group.DisplayName)
		}
	}

	return groups, nil
}

// AddUserToGroup adds a user to a group
func (c *HTTPClient) AddUserToGroup(ctx context.Context, token *auth.AccessToken, userID, groupName string) error {
	// First, find the group by name
	groupID, err := c.findGroupByName(ctx, token, groupName)
	if err != nil {
		return fmt.Errorf("failed to find group: %w", err)
	}

	endpoint := fmt.Sprintf("/groups/%s/members/$ref", groupID)

	request := struct {
		ODataID string `json:"@odata.id"`
	}{
		ODataID: fmt.Sprintf("%s/users/%s", c.baseURL, userID),
	}

	if err := c.makeRequest(ctx, token, "POST", endpoint, request, nil); err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}

	return nil
}

// RemoveUserFromGroup removes a user from a group
func (c *HTTPClient) RemoveUserFromGroup(ctx context.Context, token *auth.AccessToken, userID, groupName string) error {
	// First, find the group by name
	groupID, err := c.findGroupByName(ctx, token, groupName)
	if err != nil {
		return fmt.Errorf("failed to find group: %w", err)
	}

	endpoint := fmt.Sprintf("/groups/%s/members/%s/$ref", groupID, userID)

	if err := c.makeRequest(ctx, token, "DELETE", endpoint, nil, nil); err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}

	return nil
}

// GetConditionalAccessPolicy retrieves a Conditional Access policy
func (c *HTTPClient) GetConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, policyID string) (*ConditionalAccessPolicy, error) {
	endpoint := fmt.Sprintf("/identity/conditionalAccess/policies/%s", policyID)

	var policy ConditionalAccessPolicy
	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &policy); err != nil {
		return nil, fmt.Errorf("failed to get Conditional Access policy: %w", err)
	}

	return &policy, nil
}

// CreateConditionalAccessPolicy creates a new Conditional Access policy
func (c *HTTPClient) CreateConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, request *CreateConditionalAccessPolicyRequest) (*ConditionalAccessPolicy, error) {
	endpoint := "/identity/conditionalAccess/policies"

	var policy ConditionalAccessPolicy
	if err := c.makeRequest(ctx, token, "POST", endpoint, request, &policy); err != nil {
		return nil, fmt.Errorf("failed to create Conditional Access policy: %w", err)
	}

	return &policy, nil
}

// UpdateConditionalAccessPolicy updates an existing Conditional Access policy
func (c *HTTPClient) UpdateConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, policyID string, request *UpdateConditionalAccessPolicyRequest) error {
	endpoint := fmt.Sprintf("/identity/conditionalAccess/policies/%s", policyID)

	if err := c.makeRequest(ctx, token, "PATCH", endpoint, request, nil); err != nil {
		return fmt.Errorf("failed to update Conditional Access policy: %w", err)
	}

	return nil
}

// DeleteConditionalAccessPolicy deletes a Conditional Access policy
func (c *HTTPClient) DeleteConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, policyID string) error {
	endpoint := fmt.Sprintf("/identity/conditionalAccess/policies/%s", policyID)

	if err := c.makeRequest(ctx, token, "DELETE", endpoint, nil, nil); err != nil {
		return fmt.Errorf("failed to delete Conditional Access policy: %w", err)
	}

	return nil
}

// GetDeviceConfiguration retrieves an Intune device configuration
func (c *HTTPClient) GetDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string) (*DeviceConfiguration, error) {
	endpoint := fmt.Sprintf("/deviceManagement/deviceConfigurations/%s", configurationID)

	var config DeviceConfiguration
	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &config); err != nil {
		return nil, fmt.Errorf("failed to get device configuration: %w", err)
	}

	return &config, nil
}

// CreateDeviceConfiguration creates a new Intune device configuration
func (c *HTTPClient) CreateDeviceConfiguration(ctx context.Context, token *auth.AccessToken, request *CreateDeviceConfigurationRequest) (*DeviceConfiguration, error) {
	endpoint := "/deviceManagement/deviceConfigurations"

	var config DeviceConfiguration
	if err := c.makeRequest(ctx, token, "POST", endpoint, request, &config); err != nil {
		return nil, fmt.Errorf("failed to create device configuration: %w", err)
	}

	return &config, nil
}

// UpdateDeviceConfiguration updates an existing Intune device configuration
func (c *HTTPClient) UpdateDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string, request *UpdateDeviceConfigurationRequest) error {
	endpoint := fmt.Sprintf("/deviceManagement/deviceConfigurations/%s", configurationID)

	if err := c.makeRequest(ctx, token, "PATCH", endpoint, request, nil); err != nil {
		return fmt.Errorf("failed to update device configuration: %w", err)
	}

	return nil
}

// DeleteDeviceConfiguration deletes an Intune device configuration
func (c *HTTPClient) DeleteDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string) error {
	endpoint := fmt.Sprintf("/deviceManagement/deviceConfigurations/%s", configurationID)

	if err := c.makeRequest(ctx, token, "DELETE", endpoint, nil, nil); err != nil {
		return fmt.Errorf("failed to delete device configuration: %w", err)
	}

	return nil
}

// findGroupByName finds a group ID by its display name
func (c *HTTPClient) findGroupByName(ctx context.Context, token *auth.AccessToken, groupName string) (string, error) {
	// Use $filter to search for the group by display name
	endpoint := fmt.Sprintf("/groups?$filter=displayName eq '%s'", url.QueryEscape(groupName))

	var response struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}

	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &response); err != nil {
		return "", fmt.Errorf("failed to search for group: %w", err)
	}

	if len(response.Value) == 0 {
		return "", fmt.Errorf("group '%s' not found", groupName)
	}

	if len(response.Value) > 1 {
		return "", fmt.Errorf("multiple groups found with name '%s'", groupName)
	}

	return response.Value[0].ID, nil
}

// makeRequest makes an HTTP request to the Microsoft Graph API with retry logic
func (c *HTTPClient) makeRequest(ctx context.Context, token *auth.AccessToken, method, endpoint string, requestBody interface{}, responseBody interface{}) error {
	// Apply rate limiting if configured
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter error: %w", err)
		}
	}

	// Retry loop
	var lastErr error
	for attempt := 0; attempt <= c.retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			// Calculate delay for retry
			delay := c.calculateRetryDelay(attempt)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				// Continue with retry
			}
		}

		// Make the actual request
		err := c.doRequest(ctx, token, method, endpoint, requestBody, responseBody)
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Check if this error is retryable
		if !c.isRetryableError(err) {
			break // Don't retry non-retryable errors
		}

		// Check if we've reached max retries
		if attempt >= c.retryConfig.MaxRetries {
			break
		}
	}

	return lastErr
}

// doRequest performs the actual HTTP request
func (c *HTTPClient) doRequest(ctx context.Context, token *auth.AccessToken, method, endpoint string, requestBody interface{}, responseBody interface{}) error {
	// Build full URL
	url := c.baseURL + endpoint

	// Prepare request body
	var bodyReader io.Reader
	if requestBody != nil {
		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CFGMS-SaaS-Steward/1.0")

	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Make the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore error for cleanup operation
		}
	}()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		return c.parseErrorResponse(resp.StatusCode, respBody)
	}

	// Parse response body if expected
	if responseBody != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, responseBody); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// parseErrorResponse parses an error response from Microsoft Graph API
func (c *HTTPClient) parseErrorResponse(statusCode int, body []byte) error {
	var errorResponse struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details []struct {
				Code    string `json:"code"`
				Message string `json:"message"`
				Target  string `json:"target"`
			} `json:"details"`
			InnerError map[string]interface{} `json:"innerError"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &errorResponse); err != nil {
		// If we can't parse the error response, return a generic error
		return &GraphError{
			Code:       "UNKNOWN_ERROR",
			Message:    fmt.Sprintf("HTTP %d: %s", statusCode, string(body)),
			StatusCode: statusCode,
		}
	}

	graphError := &GraphError{
		Code:       errorResponse.Error.Code,
		Message:    errorResponse.Error.Message,
		InnerError: errorResponse.Error.InnerError,
		StatusCode: statusCode,
	}

	// Convert details
	for _, detail := range errorResponse.Error.Details {
		graphError.Details = append(graphError.Details, GraphErrorDetail{
			Code:    detail.Code,
			Message: detail.Message,
			Target:  detail.Target,
		})
	}

	return graphError
}

// isRetryableError determines if an error should trigger a retry
func (c *HTTPClient) isRetryableError(err error) bool {
	if graphErr, ok := err.(*GraphError); ok {
		// Retry on throttling errors
		if IsThrottledError(graphErr) {
			return true
		}

		// Retry on 5xx server errors
		if graphErr.StatusCode >= 500 && graphErr.StatusCode < 600 {
			return true
		}

		// Retry on specific transient errors
		retryableCodes := []string{
			"ServiceUnavailable",
			"Timeout",
			"InternalServerError",
		}

		for _, code := range retryableCodes {
			if graphErr.Code == code {
				return true
			}
		}
	}

	return false
}

// calculateRetryDelay calculates the delay before a retry attempt
func (c *HTTPClient) calculateRetryDelay(attempt int) time.Duration {
	// Exponential backoff with jitter
	delay := time.Duration(float64(c.retryConfig.InitialDelay) *
		(c.retryConfig.BackoffMultiplier * float64(attempt)))

	// Cap at max delay
	if delay > c.retryConfig.MaxDelay {
		delay = c.retryConfig.MaxDelay
	}

	// Add jitter (±25%)
	jitter := time.Duration(float64(delay) * 0.25)
	randomFactor := float64(time.Now().UnixNano()%1000) / 1000.0
	delay = delay + time.Duration(float64(jitter)*(2*randomFactor-1))

	return delay
}

// GetApplication retrieves an application by ID
func (c *HTTPClient) GetApplication(ctx context.Context, token *auth.AccessToken, applicationID string) (*Application, error) {
	endpoint := fmt.Sprintf("/applications/%s", applicationID)
	var application Application
	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &application); err != nil {
		return nil, fmt.Errorf("failed to get application: %w", err)
	}
	return &application, nil
}

// CreateApplication creates a new application
func (c *HTTPClient) CreateApplication(ctx context.Context, token *auth.AccessToken, request *CreateApplicationRequest) (*Application, error) {
	endpoint := "/applications"
	var application Application
	if err := c.makeRequest(ctx, token, "POST", endpoint, request, &application); err != nil {
		return nil, fmt.Errorf("failed to create application: %w", err)
	}
	return &application, nil
}

// UpdateApplication updates an existing application
func (c *HTTPClient) UpdateApplication(ctx context.Context, token *auth.AccessToken, applicationID string, request *UpdateApplicationRequest) error {
	endpoint := fmt.Sprintf("/applications/%s", applicationID)
	if err := c.makeRequest(ctx, token, "PATCH", endpoint, request, nil); err != nil {
		return fmt.Errorf("failed to update application: %w", err)
	}
	return nil
}

// DeleteApplication deletes an application
func (c *HTTPClient) DeleteApplication(ctx context.Context, token *auth.AccessToken, applicationID string) error {
	endpoint := fmt.Sprintf("/applications/%s", applicationID)
	if err := c.makeRequest(ctx, token, "DELETE", endpoint, nil, nil); err != nil {
		return fmt.Errorf("failed to delete application: %w", err)
	}
	return nil
}

// ListApplications retrieves applications with optional OData filter
func (c *HTTPClient) ListApplications(ctx context.Context, token *auth.AccessToken, filter string) ([]Application, error) {
	endpoint := "/applications"
	if filter != "" {
		endpoint = fmt.Sprintf("/applications?$filter=%s", url.QueryEscape(filter))
	}

	var response struct {
		Value []Application `json:"value"`
	}

	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &response); err != nil {
		return nil, fmt.Errorf("failed to list applications: %w", err)
	}

	return response.Value, nil
}

// GetAdministrativeUnit retrieves an administrative unit by ID
func (c *HTTPClient) GetAdministrativeUnit(ctx context.Context, token *auth.AccessToken, unitID string) (*AdministrativeUnit, error) {
	endpoint := fmt.Sprintf("/administrativeUnits/%s", unitID)
	var unit AdministrativeUnit
	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &unit); err != nil {
		return nil, fmt.Errorf("failed to get administrative unit: %w", err)
	}
	return &unit, nil
}

// ListAdministrativeUnits retrieves administrative units with optional OData filter
func (c *HTTPClient) ListAdministrativeUnits(ctx context.Context, token *auth.AccessToken, filter string) ([]AdministrativeUnit, error) {
	endpoint := "/administrativeUnits"
	if filter != "" {
		endpoint = fmt.Sprintf("/administrativeUnits?$filter=%s", url.QueryEscape(filter))
	}

	var response struct {
		Value []AdministrativeUnit `json:"value"`
	}

	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &response); err != nil {
		return nil, fmt.Errorf("failed to list administrative units: %w", err)
	}

	return response.Value, nil
}

// CreateAdministrativeUnit creates a new administrative unit
func (c *HTTPClient) CreateAdministrativeUnit(ctx context.Context, token *auth.AccessToken, request *CreateAdministrativeUnitRequest) (*AdministrativeUnit, error) {
	endpoint := "/administrativeUnits"
	var unit AdministrativeUnit
	if err := c.makeRequest(ctx, token, "POST", endpoint, request, &unit); err != nil {
		return nil, fmt.Errorf("failed to create administrative unit: %w", err)
	}
	return &unit, nil
}

// UpdateAdministrativeUnit updates an existing administrative unit
func (c *HTTPClient) UpdateAdministrativeUnit(ctx context.Context, token *auth.AccessToken, unitID string, request *UpdateAdministrativeUnitRequest) error {
	endpoint := fmt.Sprintf("/administrativeUnits/%s", unitID)
	if err := c.makeRequest(ctx, token, "PATCH", endpoint, request, nil); err != nil {
		return fmt.Errorf("failed to update administrative unit: %w", err)
	}
	return nil
}

// DeleteAdministrativeUnit deletes an administrative unit
func (c *HTTPClient) DeleteAdministrativeUnit(ctx context.Context, token *auth.AccessToken, unitID string) error {
	endpoint := fmt.Sprintf("/administrativeUnits/%s", unitID)
	if err := c.makeRequest(ctx, token, "DELETE", endpoint, nil, nil); err != nil {
		return fmt.Errorf("failed to delete administrative unit: %w", err)
	}
	return nil
}

// GetGroup retrieves a group by ID
func (c *HTTPClient) GetGroup(ctx context.Context, token *auth.AccessToken, groupID string) (*Group, error) {
	endpoint := fmt.Sprintf("/groups/%s", groupID)
	var group Group
	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &group); err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	return &group, nil
}

// ListGroups retrieves groups with optional OData filter
func (c *HTTPClient) ListGroups(ctx context.Context, token *auth.AccessToken, filter string) ([]Group, error) {
	endpoint := "/groups"
	if filter != "" {
		endpoint = fmt.Sprintf("/groups?$filter=%s", url.QueryEscape(filter))
	}

	var response struct {
		Value []Group `json:"value"`
	}

	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &response); err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	return response.Value, nil
}

// CreateGroup creates a new group
func (c *HTTPClient) CreateGroup(ctx context.Context, token *auth.AccessToken, request *CreateGroupRequest) (*Group, error) {
	endpoint := "/groups"
	var group Group
	if err := c.makeRequest(ctx, token, "POST", endpoint, request, &group); err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}
	return &group, nil
}

// UpdateGroup updates an existing group
func (c *HTTPClient) UpdateGroup(ctx context.Context, token *auth.AccessToken, groupID string, request *UpdateGroupRequest) error {
	endpoint := fmt.Sprintf("/groups/%s", groupID)
	if err := c.makeRequest(ctx, token, "PATCH", endpoint, request, nil); err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}
	return nil
}

// DeleteGroup deletes a group
func (c *HTTPClient) DeleteGroup(ctx context.Context, token *auth.AccessToken, groupID string) error {
	endpoint := fmt.Sprintf("/groups/%s", groupID)
	if err := c.makeRequest(ctx, token, "DELETE", endpoint, nil, nil); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	return nil
}
