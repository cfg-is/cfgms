// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// APIClient provides HTTP client functionality for communicating with the controller API
type APIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// TokenCreateRequest represents the request body for creating a registration token
type APITokenCreateRequest struct {
	TenantID      string `json:"tenant_id"`
	ControllerURL string `json:"controller_url"`
	Group         string `json:"group,omitempty"`
	ExpiresIn     string `json:"expires_in,omitempty"`
	SingleUse     bool   `json:"single_use,omitempty"`
}

// TokenResponse represents a registration token in API responses
type APITokenResponse struct {
	Token         string  `json:"token"`
	TenantID      string  `json:"tenant_id"`
	ControllerURL string  `json:"controller_url"`
	Group         string  `json:"group,omitempty"`
	CreatedAt     string  `json:"created_at"`
	ExpiresAt     *string `json:"expires_at,omitempty"`
	SingleUse     bool    `json:"single_use"`
	UsedAt        *string `json:"used_at,omitempty"`
	UsedBy        string  `json:"used_by,omitempty"`
	Revoked       bool    `json:"revoked"`
	RevokedAt     *string `json:"revoked_at,omitempty"`
}

// TokenListResponse represents a list of tokens from the API
type APITokenListResponse struct {
	Tokens []APITokenResponse `json:"tokens"`
	Total  int                `json:"total"`
}

// NewAPIClient creates a new API client for communicating with the controller
func NewAPIClient(baseURL, apiKey string) *APIClient {
	return &APIClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					// Allow insecure for development - production should use proper certs
					// #nosec G402 - TLS InsecureSkipVerify is configurable for development
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

// CreateToken creates a new registration token via the controller API
func (c *APIClient) CreateToken(ctx context.Context, req *APITokenCreateRequest) (*APITokenResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/registration/tokens", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	var tokenResp APITokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

// ListTokens lists registration tokens via the controller API
func (c *APIClient) ListTokens(ctx context.Context, tenantID string) (*APITokenListResponse, error) {
	path := "/api/v1/registration/tokens"
	if tenantID != "" {
		path += "?tenant_id=" + tenantID
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var listResp APITokenListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &listResp, nil
}

// GetToken retrieves a specific token via the controller API
func (c *APIClient) GetToken(ctx context.Context, tokenStr string) (*APITokenResponse, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/registration/tokens/"+tokenStr, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var tokenResp APITokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

// DeleteToken deletes a token via the controller API
func (c *APIClient) DeleteToken(ctx context.Context, tokenStr string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/api/v1/registration/tokens/"+tokenStr, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}

	return nil
}

// RevokeToken revokes a token via the controller API
func (c *APIClient) RevokeToken(ctx context.Context, tokenStr string) (*APITokenResponse, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/registration/tokens/"+tokenStr+"/revoke", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var tokenResp APITokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

// doRequest performs an HTTP request with authentication
func (c *APIClient) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	return c.httpClient.Do(req)
}

// parseError extracts error message from HTTP response
func (c *APIClient) parseError(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("API error (status %d)", resp.StatusCode)
	}

	// Try to parse as JSON error
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil {
		if errResp.Error != "" {
			return fmt.Errorf("API error: %s", errResp.Error)
		}
		if errResp.Message != "" {
			return fmt.Errorf("API error: %s", errResp.Message)
		}
	}

	// Return raw body as error message
	return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
}
