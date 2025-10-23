// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package registration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// HTTPClient handles steward registration via REST API
type HTTPClient struct {
	controllerURL string
	httpClient    *http.Client
	logger        logging.Logger
}

// HTTPConfig holds configuration for HTTP registration
type HTTPConfig struct {
	ControllerURL string
	Timeout       time.Duration
	Logger        logging.Logger
}

// NewHTTPClient creates a new HTTP-based registration client
func NewHTTPClient(cfg *HTTPConfig) (*HTTPClient, error) {
	if cfg.ControllerURL == "" {
		return nil, fmt.Errorf("controller URL is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &HTTPClient{
		controllerURL: cfg.ControllerURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: cfg.Logger,
	}, nil
}

// Register registers the steward with the controller using a registration token
func (c *HTTPClient) Register(ctx context.Context, token string) (*RegistrationResponse, error) {
	// Build registration URL
	registrationURL := fmt.Sprintf("%s/api/v1/register", c.controllerURL)

	// Create request body
	reqBody := RegistrationRequest{
		Token: token,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	c.logger.Info("Sending registration request to controller", "url", registrationURL)

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send registration request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.logger.Warn("Failed to close response body", "error", closeErr)
		}
	}()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var regResp RegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	c.logger.Info("Registration successful",
		"steward_id", regResp.StewardID,
		"tenant_id", regResp.TenantID,
		"group", regResp.Group)

	return &regResp, nil
}
