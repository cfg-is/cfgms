// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// executeHTTPStep executes an HTTP-based workflow step
func (e *Engine) executeHTTPStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.HTTP == nil {
		return fmt.Errorf("HTTP configuration is required for HTTP steps")
	}

	// Render {{ }} template fields against current execution variables.
	vars := execution.GetVariables()
	renderedHTTP, err := renderHTTPConfig(step.HTTP, vars)
	if err != nil {
		return fmt.Errorf("template rendering failed for step %q: %w", step.Name, err)
	}

	// Execute HTTP request
	response, err := e.httpClient.ExecuteRequest(ctx, renderedHTTP)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}

	// Store response in variables safely
	e.mutex.Lock()
	execution.SetVariable(step.Name+"_status_code", response.StatusCode)
	execution.SetVariable(step.Name+"_headers", response.Headers)
	execution.SetVariable(step.Name+"_body", string(response.Body))
	execution.SetVariable(step.Name+"_duration", response.Duration.String())

	// Attempt to decode response body as JSON for addressable downstream access.
	// Non-JSON bodies are silently ignored; raw body is always available via _body.
	if len(response.Body) > 0 {
		var jsonData interface{}
		if jsonErr := json.Unmarshal(response.Body, &jsonData); jsonErr == nil {
			execution.SetVariable(step.Name+"_response_json", jsonData)
		}
	}
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

	// Render {{ }} template fields against current execution variables.
	vars := execution.GetVariables()
	renderedAPI, err := renderAPIConfig(step.API, vars)
	if err != nil {
		return fmt.Errorf("template rendering failed for step %q: %w", step.Name, err)
	}

	// Use provider registry for API operations
	response, err := e.providerRegistry.ExecuteOperation(ctx, renderedAPI)
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
		"provider", renderedAPI.Provider,
		"service", renderedAPI.Service,
		"operation", renderedAPI.Operation,
		"success", response.Success)

	return nil
}

// executeWebhookStep executes a webhook-based workflow step
func (e *Engine) executeWebhookStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Webhook == nil {
		return fmt.Errorf("webhook configuration is required for webhook steps")
	}

	// Render {{ }} template fields against current execution variables.
	vars := execution.GetVariables()
	renderedWebhook, err := renderWebhookConfig(step.Webhook, vars)
	if err != nil {
		return fmt.Errorf("template rendering failed for step %q: %w", step.Name, err)
	}

	// Convert webhook config to HTTP config
	httpConfig := &HTTPConfig{
		URL:            renderedWebhook.URL,
		Method:         renderedWebhook.Method,
		Headers:        renderedWebhook.Headers,
		Body:           renderedWebhook.Payload,
		Auth:           renderedWebhook.Auth,
		Timeout:        renderedWebhook.Timeout,
		Retry:          renderedWebhook.Retry,
		ExpectedStatus: []int{200, 201, 202, 204},
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
		"url", renderedWebhook.URL,
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

	// Wait for the specified duration or context cancellation.
	//
	// Use an explicit timer (stopped on return) rather than time.After: time.After
	// leaks its underlying timer and goroutine until the full duration elapses even
	// when the context is cancelled first. For long delays cancelled early (e.g. a
	// cancelled or abandoned execution) that leak keeps a goroutine parked in this
	// select for the whole duration, which surfaces as "stuck in executeDelayStep"
	// goroutines in dumps. Stopping the timer releases it immediately on cancellation.
	timer := time.NewTimer(step.Delay.Duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		// Delay completed successfully
	}

	e.logger.Info("Delay step completed",
		"step", step.Name,
		"duration", step.Delay.Duration)

	// Set the output for the step result
	delayKey := StepResultKey(step)
	result, exists := execution.GetStepResult(delayKey)
	if exists {
		if result.Output == nil {
			result.Output = make(map[string]interface{})
		}
		result.Output["message"] = message
		execution.SetStepResult(delayKey, result)
	}

	return nil
}
