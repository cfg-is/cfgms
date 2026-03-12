// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"time"
)

// executeHTTPStep executes an HTTP-based workflow step
func (e *Engine) executeHTTPStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.HTTP == nil {
		return fmt.Errorf("HTTP configuration is required for HTTP steps")
	}

	// Execute HTTP request
	response, err := e.httpClient.ExecuteRequest(ctx, step.HTTP)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}

	// Store response in variables safely
	e.mutex.Lock()
	execution.SetVariable(step.Name+"_status_code", response.StatusCode)
	execution.SetVariable(step.Name+"_headers", response.Headers)
	execution.SetVariable(step.Name+"_body", string(response.Body))
	execution.SetVariable(step.Name+"_duration", response.Duration.String())
	e.mutex.Unlock()

	e.logger.Info("HTTP step completed",
		"step", step.Name,
		"status_code", response.StatusCode,
		"duration", response.Duration)

	return nil
}

// executeAPIStep executes an API-based workflow step (SaaS integrations)
func (e *Engine) executeAPIStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.API == nil {
		return fmt.Errorf("API configuration is required for API steps")
	}

	// Use provider registry for API operations
	response, err := e.providerRegistry.ExecuteOperation(ctx, step.API)
	if err != nil {
		return fmt.Errorf("API operation failed: %w", err)
	}

	// Store API response in variables safely
	e.mutex.Lock()
	execution.SetVariable(step.Name+"_api_success", response.Success)
	execution.SetVariable(step.Name+"_api_status", response.StatusCode)
	execution.SetVariable(step.Name+"_api_duration", response.Duration)
	execution.SetVariable(step.Name+"_api_response", response.Data)
	execution.SetVariable(step.Name+"_api_metadata", response.Metadata)
	e.mutex.Unlock()

	e.logger.Info("API step completed",
		"step", step.Name,
		"provider", step.API.Provider,
		"service", step.API.Service,
		"operation", step.API.Operation,
		"success", response.Success)

	return nil
}

// executeWebhookStep executes a webhook-based workflow step
func (e *Engine) executeWebhookStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Webhook == nil {
		return fmt.Errorf("webhook configuration is required for webhook steps")
	}

	// Convert webhook config to HTTP config
	httpConfig := &HTTPConfig{
		URL:            step.Webhook.URL,
		Method:         step.Webhook.Method,
		Headers:        step.Webhook.Headers,
		Body:           step.Webhook.Payload,
		Auth:           step.Webhook.Auth,
		Timeout:        step.Webhook.Timeout,
		Retry:          step.Webhook.Retry,
		ExpectedStatus: []int{200, 201, 202, 204}, // Common webhook success codes
	}

	// Set default method if not specified
	if httpConfig.Method == "" {
		httpConfig.Method = "POST"
	}

	// Execute webhook request
	response, err := e.httpClient.ExecuteRequest(ctx, httpConfig)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}

	// Store webhook response in variables safely
	e.mutex.Lock()
	execution.SetVariable(step.Name+"_webhook_status", response.StatusCode)
	execution.SetVariable(step.Name+"_webhook_response", string(response.Body))
	e.mutex.Unlock()

	e.logger.Info("Webhook step completed",
		"step", step.Name,
		"url", step.Webhook.URL,
		"status_code", response.StatusCode)

	return nil
}

// executeDelayStep executes a delay workflow step
func (e *Engine) executeDelayStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Delay == nil {
		return fmt.Errorf("delay configuration is required for delay steps")
	}

	if step.Delay.Duration <= 0 {
		return fmt.Errorf("delay duration must be positive")
	}

	message := step.Delay.Message
	if message == "" {
		message = "Waiting"
	}

	e.logger.Info("Starting delay step",
		"step", step.Name,
		"duration", step.Delay.Duration,
		"message", message)

	// Wait for the specified duration or context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(step.Delay.Duration):
		// Delay completed successfully
	}

	e.logger.Info("Delay step completed",
		"step", step.Name,
		"duration", step.Delay.Duration)

	// Set the output for the step result
	result, exists := execution.GetStepResult(step.Name)
	if exists {
		if result.Output == nil {
			result.Output = make(map[string]interface{})
		}
		result.Output["message"] = message
		execution.SetStepResult(step.Name, result)
	}

	return nil
}
