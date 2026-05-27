// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build experimental

package workflow

import "context"

// experimentalMicrosoftProvider wraps MicrosoftProvider with a simulated ExecuteOperation.
type experimentalMicrosoftProvider struct {
	MicrosoftProvider
}

func (p *experimentalMicrosoftProvider) ExecuteOperation(_ context.Context, config *APIConfig) (*APIResponse, error) {
	return &APIResponse{
		Success:    true,
		Data:       map[string]interface{}{"message": "Microsoft operation simulated"},
		StatusCode: 200,
		Metadata: map[string]interface{}{
			"provider": "microsoft",
			"service":  config.Service,
		},
	}, nil
}

// experimentalGoogleProvider wraps GoogleProvider with a simulated ExecuteOperation.
type experimentalGoogleProvider struct {
	GoogleProvider
}

func (p *experimentalGoogleProvider) ExecuteOperation(_ context.Context, config *APIConfig) (*APIResponse, error) {
	return &APIResponse{
		Success:    true,
		Data:       map[string]interface{}{"message": "Google operation simulated"},
		StatusCode: 200,
		Metadata: map[string]interface{}{
			"provider": "google",
			"service":  config.Service,
		},
	}, nil
}

// experimentalSalesforceProvider wraps SalesforceProvider with a simulated ExecuteOperation.
type experimentalSalesforceProvider struct {
	SalesforceProvider
}

func (p *experimentalSalesforceProvider) ExecuteOperation(_ context.Context, config *APIConfig) (*APIResponse, error) {
	return &APIResponse{
		Success:    true,
		Data:       map[string]interface{}{"message": "Salesforce operation simulated"},
		StatusCode: 200,
		Metadata: map[string]interface{}{
			"provider": "salesforce",
			"service":  config.Service,
		},
	}, nil
}

// experimentalConnectWiseProvider wraps ConnectWiseProvider with a simulated ExecuteOperation.
type experimentalConnectWiseProvider struct {
	ConnectWiseProvider
}

func (p *experimentalConnectWiseProvider) ExecuteOperation(_ context.Context, config *APIConfig) (*APIResponse, error) {
	return &APIResponse{
		Success:    true,
		Data:       map[string]interface{}{"message": "ConnectWise operation simulated"},
		StatusCode: 200,
		Metadata: map[string]interface{}{
			"provider": "connectwise",
			"service":  config.Service,
		},
	}, nil
}

// init overrides the default stub registrations with simulated implementations.
// Runs before any NewProviderRegistry call so registerBuiltinProviders picks up the overrides.
func init() {
	providerOverrides["microsoft"] = &experimentalMicrosoftProvider{}
	providerOverrides["google"] = &experimentalGoogleProvider{}
	providerOverrides["salesforce"] = &experimentalSalesforceProvider{}
	providerOverrides["connectwise"] = &experimentalConnectWiseProvider{}
}
