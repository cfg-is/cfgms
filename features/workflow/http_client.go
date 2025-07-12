// Package workflow provides HTTP client capabilities for workflow engine API operations.
//
// This module implements HTTP client functionality with authentication, rate limiting,
// retry logic, and comprehensive error handling for API-based workflow steps.
//
// Key features:
//   - Multiple authentication methods (Bearer, API Key, Basic, OAuth2, Custom)
//   - Automatic retry with exponential backoff
//   - Rate limiting with burst support
//   - Timeout and cancellation support
//   - Response validation and error handling
//
// Basic usage:
//
//	client := NewHTTPClient(HTTPClientConfig{
//		Timeout: 30 * time.Second,
//		RetryConfig: &RetryConfig{
//			MaxAttempts: 3,
//			InitialDelay: time.Second,
//		},
//	})
//
//	response, err := client.ExecuteRequest(ctx, &HTTPConfig{
//		URL:    "https://api.example.com/users",
//		Method: "GET",
//		Auth: &AuthConfig{
//			Type: AuthTypeBearer,
//			BearerToken: "token",
//		},
//	})
package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// HTTPClient provides HTTP request capabilities for workflow engine
type HTTPClient struct {
	client      *http.Client
	rateLimiter *rate.Limiter
	config      HTTPClientConfig
}

// HTTPClientConfig defines configuration for the HTTP client
type HTTPClientConfig struct {
	// Timeout for HTTP requests (default: 30 seconds)
	Timeout time.Duration

	// DefaultRetryConfig for requests without specific retry configuration
	DefaultRetryConfig *RetryConfig

	// DefaultRateLimitConfig for requests without specific rate limiting
	DefaultRateLimitConfig *RateLimitConfig

	// UserAgent for HTTP requests
	UserAgent string

	// MaxIdleConns for HTTP transport
	MaxIdleConns int

	// MaxIdleConnsPerHost for HTTP transport
	MaxIdleConnsPerHost int
}

// HTTPResponse represents the response from an HTTP request
type HTTPResponse struct {
	// StatusCode is the HTTP status code
	StatusCode int

	// Headers contains response headers
	Headers map[string][]string

	// Body contains the response body
	Body []byte

	// Duration is how long the request took
	Duration time.Duration
}

// NewHTTPClient creates a new HTTP client with the specified configuration
func NewHTTPClient(config HTTPClientConfig) *HTTPClient {
	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "CFGMS-Workflow-Engine/1.0"
	}
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = 100
	}
	if config.MaxIdleConnsPerHost == 0 {
		config.MaxIdleConnsPerHost = 10
	}

	// Create HTTP client with custom transport
	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
	}

	httpClient := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	// Create rate limiter if configured
	var rateLimiter *rate.Limiter
	if config.DefaultRateLimitConfig != nil {
		rateLimiter = rate.NewLimiter(
			rate.Limit(config.DefaultRateLimitConfig.RequestsPerSecond),
			config.DefaultRateLimitConfig.BurstSize,
		)
	}

	return &HTTPClient{
		client:      httpClient,
		rateLimiter: rateLimiter,
		config:      config,
	}
}

// ExecuteRequest executes an HTTP request with the specified configuration
func (c *HTTPClient) ExecuteRequest(ctx context.Context, httpConfig *HTTPConfig) (*HTTPResponse, error) {
	startTime := time.Now()

	// Validate configuration
	if err := c.validateHTTPConfig(httpConfig); err != nil {
		return nil, fmt.Errorf("invalid HTTP configuration: %w", err)
	}

	// Apply rate limiting
	if err := c.applyRateLimit(ctx, httpConfig); err != nil {
		return nil, fmt.Errorf("rate limit error: %w", err)
	}

	// Determine retry configuration
	retryConfig := httpConfig.Retry
	if retryConfig == nil {
		retryConfig = c.config.DefaultRetryConfig
	}

	// Execute request with retry logic
	var lastErr error
	maxAttempts := 1
	if retryConfig != nil {
		maxAttempts = retryConfig.MaxAttempts
		if maxAttempts < 1 {
			maxAttempts = 1
		}
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Execute single request
		response, err := c.executeSingleRequest(ctx, httpConfig)
		if err == nil {
			response.Duration = time.Since(startTime)
			return response, nil
		}

		lastErr = err

		// Check if we should retry
		if attempt < maxAttempts && c.shouldRetry(err, response, retryConfig) {
			delay := c.calculateRetryDelay(attempt, retryConfig)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				// Continue to next attempt
			}
		}
	}

	return nil, fmt.Errorf("HTTP request failed after %d attempts: %w", maxAttempts, lastErr)
}

// executeSingleRequest executes a single HTTP request without retry logic
func (c *HTTPClient) executeSingleRequest(ctx context.Context, httpConfig *HTTPConfig) (*HTTPResponse, error) {
	// Create request
	req, err := c.createHTTPRequest(ctx, httpConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply authentication
	if err := c.applyAuthentication(req, httpConfig.Auth); err != nil {
		return nil, fmt.Errorf("failed to apply authentication: %w", err)
	}

	// Execute request
	startTime := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	response := &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Duration:   time.Since(startTime),
	}

	// Validate response status
	if err := c.validateResponseStatus(response, httpConfig); err != nil {
		return response, err
	}

	return response, nil
}

// createHTTPRequest creates an HTTP request from the configuration
func (c *HTTPClient) createHTTPRequest(ctx context.Context, httpConfig *HTTPConfig) (*http.Request, error) {
	// Prepare request body
	var bodyReader io.Reader
	if httpConfig.Body != nil {
		bodyBytes, err := c.prepareRequestBody(httpConfig.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, httpConfig.Method, httpConfig.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", c.config.UserAgent)
	for key, value := range httpConfig.Headers {
		req.Header.Set(key, value)
	}

	// Set content type for body requests
	if httpConfig.Body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

// prepareRequestBody converts the body interface to bytes
func (c *HTTPClient) prepareRequestBody(body interface{}) ([]byte, error) {
	switch v := body.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	case nil:
		return nil, nil
	default:
		// Marshal as JSON
		return json.Marshal(v)
	}
}

// applyAuthentication applies authentication to the HTTP request
func (c *HTTPClient) applyAuthentication(req *http.Request, auth *AuthConfig) error {
	if auth == nil {
		return nil
	}

	switch auth.Type {
	case AuthTypeBearer:
		if auth.BearerToken == "" {
			return fmt.Errorf("bearer token is required for bearer authentication")
		}
		req.Header.Set("Authorization", "Bearer "+auth.BearerToken)

	case AuthTypeAPIKey:
		if auth.APIKey == "" {
			return fmt.Errorf("API key is required for API key authentication")
		}
		header := auth.APIKeyHeader
		if header == "" {
			header = "X-API-Key"
		}
		req.Header.Set(header, auth.APIKey)

	case AuthTypeBasic:
		if auth.Username == "" || auth.Password == "" {
			return fmt.Errorf("username and password are required for basic authentication")
		}
		req.SetBasicAuth(auth.Username, auth.Password)

	case AuthTypeOAuth2:
		// OAuth2 requires token acquisition - this would need to be implemented
		// based on the specific OAuth2 flow and token storage
		return fmt.Errorf("OAuth2 authentication not yet implemented")

	case AuthTypeCustom:
		for key, value := range auth.CustomHeaders {
			req.Header.Set(key, value)
		}

	case AuthTypeNone:
		// No authentication required

	default:
		return fmt.Errorf("unsupported authentication type: %s", auth.Type)
	}

	return nil
}

// applyRateLimit applies rate limiting if configured
func (c *HTTPClient) applyRateLimit(ctx context.Context, httpConfig *HTTPConfig) error {
	// Use step-specific rate limiter if configured
	var rateLimiter *rate.Limiter
	if httpConfig.RateLimit != nil {
		rateLimiter = rate.NewLimiter(
			rate.Limit(httpConfig.RateLimit.RequestsPerSecond),
			httpConfig.RateLimit.BurstSize,
		)
	} else if c.rateLimiter != nil {
		rateLimiter = c.rateLimiter
	}

	if rateLimiter == nil {
		return nil
	}

	// Wait for rate limit or fail immediately
	if httpConfig.RateLimit != nil && !httpConfig.RateLimit.WaitOnLimit {
		if !rateLimiter.Allow() {
			return fmt.Errorf("rate limit exceeded")
		}
		return nil
	}

	// Wait for rate limit
	return rateLimiter.Wait(ctx)
}

// validateHTTPConfig validates the HTTP configuration
func (c *HTTPClient) validateHTTPConfig(httpConfig *HTTPConfig) error {
	if httpConfig.URL == "" {
		return fmt.Errorf("URL is required")
	}

	if httpConfig.Method == "" {
		return fmt.Errorf("HTTP method is required")
	}

	// Validate method
	method := strings.ToUpper(httpConfig.Method)
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true,
	}
	if !validMethods[method] {
		return fmt.Errorf("invalid HTTP method: %s", httpConfig.Method)
	}

	return nil
}

// validateResponseStatus validates the HTTP response status code
func (c *HTTPClient) validateResponseStatus(response *HTTPResponse, httpConfig *HTTPConfig) error {
	expectedStatus := httpConfig.ExpectedStatus
	if len(expectedStatus) == 0 {
		// Default to 2xx status codes
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return nil
		}
		return fmt.Errorf("unexpected HTTP status: %d", response.StatusCode)
	}

	// Check against expected status codes
	for _, status := range expectedStatus {
		if response.StatusCode == status {
			return nil
		}
	}

	return fmt.Errorf("unexpected HTTP status: %d, expected: %v", response.StatusCode, expectedStatus)
}

// shouldRetry determines if a request should be retried
func (c *HTTPClient) shouldRetry(err error, response *HTTPResponse, retryConfig *RetryConfig) bool {
	if retryConfig == nil {
		return false
	}

	// Always retry on network errors
	if response == nil {
		return true
	}

	// Check retryable status codes
	if len(retryConfig.RetryableStatusCodes) > 0 {
		for _, code := range retryConfig.RetryableStatusCodes {
			if response.StatusCode == code {
				return true
			}
		}
		return false
	}

	// Default retryable status codes (5xx and 429)
	return response.StatusCode >= 500 || response.StatusCode == 429
}

// calculateRetryDelay calculates the delay before the next retry attempt
func (c *HTTPClient) calculateRetryDelay(attempt int, retryConfig *RetryConfig) time.Duration {
	if retryConfig == nil {
		return time.Second
	}

	delay := retryConfig.InitialDelay
	for i := 1; i < attempt; i++ {
		delay = time.Duration(float64(delay) * retryConfig.BackoffMultiplier)
		if retryConfig.MaxDelay > 0 && delay > retryConfig.MaxDelay {
			delay = retryConfig.MaxDelay
			break
		}
	}

	return delay
}