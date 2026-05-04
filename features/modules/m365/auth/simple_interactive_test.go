// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// TestSimpleInteractiveFlow tests basic interactive flow components
func TestSimpleInteractiveFlow(t *testing.T) {
	credStore := newTestCredentialStore(t)

	config := &OAuth2Config{
		ClientID:             "simple-test-client-id",
		ClientSecret:         "simple-test-client-secret",
		TenantID:             "simple-test-tenant-id",
		RedirectURI:          "http://localhost:8080/auth/callback",
		UseClientCredentials: false,
		SupportDelegatedAuth: true,
		DelegatedScopes: []string{
			"User.Read",
			"Directory.Read.All",
		},
	}

	provider := NewOAuth2Provider(credStore, config, logging.NewNoopLogger())
	flow := NewInteractiveAuthFlow(provider, config)
	ctx := context.Background()

	t.Run("TestAuthURLGeneration", func(t *testing.T) {
		// Test generating auth URL
		flowState, authURL, err := flow.StartAuthFlow(ctx, config.TenantID, config.DelegatedScopes)

		require.NoError(t, err)
		assert.NotNil(t, flowState)
		assert.NotEmpty(t, authURL)

		// Basic validations
		assert.Equal(t, config.TenantID, flowState.TenantID)
		assert.NotEmpty(t, flowState.State)
		assert.NotEmpty(t, flowState.CodeVerifier)
		assert.NotEmpty(t, flowState.CodeChallenge)

		assert.Contains(t, authURL, "login.microsoftonline.com")
		assert.Contains(t, authURL, config.ClientID)
		assert.Contains(t, authURL, config.TenantID)
		assert.Contains(t, authURL, flowState.State)

		t.Logf("Generated auth URL: %s", authURL)
	})

	t.Run("TestPKCEGeneration", func(t *testing.T) {
		// Test PKCE parameter generation
		codeVerifier, err := flow.generateCodeVerifier()
		require.NoError(t, err)
		assert.NotEmpty(t, codeVerifier)
		assert.GreaterOrEqual(t, len(codeVerifier), 32) // Should be at least 32 chars

		codeChallenge := flow.generateCodeChallenge(codeVerifier)
		assert.NotEmpty(t, codeChallenge)
		assert.NotEqual(t, codeVerifier, codeChallenge) // Should be different

		t.Logf("Code verifier: %s", codeVerifier)
		t.Logf("Code challenge: %s", codeChallenge)
	})

	t.Run("TestStateGeneration", func(t *testing.T) {
		// Test state and nonce generation
		state1 := flow.generateState()
		state2 := flow.generateState()
		nonce1 := flow.generateNonce()
		nonce2 := flow.generateNonce()

		assert.NotEmpty(t, state1)
		assert.NotEmpty(t, state2)
		assert.NotEqual(t, state1, state2) // Should be unique

		assert.NotEmpty(t, nonce1)
		assert.NotEmpty(t, nonce2)
		assert.NotEqual(t, nonce1, nonce2) // Should be unique

		t.Logf("State 1: %s, State 2: %s", state1, state2)
		t.Logf("Nonce 1: %s, Nonce 2: %s", nonce1, nonce2)
	})

	t.Run("TestCallbackHandler", func(t *testing.T) {
		// Test callback handler basic functionality
		handler := NewCallbackHandler()
		assert.NotNil(t, handler)

		// Test flow state storage
		testFlowState := &AuthFlowState{
			CodeVerifier:  "test-verifier",
			CodeChallenge: "test-challenge",
			State:         "test-state",
			TenantID:      config.TenantID,
		}

		err := handler.StoreFlowState("test-state", testFlowState)
		require.NoError(t, err)

		// Retrieve flow state
		retrievedState, err := handler.GetFlowState("test-state")
		require.NoError(t, err)
		assert.Equal(t, testFlowState.CodeVerifier, retrievedState.CodeVerifier)
		assert.Equal(t, testFlowState.State, retrievedState.State)
		assert.Equal(t, testFlowState.TenantID, retrievedState.TenantID)

		// Test cleanup
		handler.CleanupFlowState("test-state")
		_, err = handler.GetFlowState("test-state")
		assert.Error(t, err) // Should not be found after cleanup
	})
}

// TestCallbackServer tests the HTTP callback server
func TestCallbackServer(t *testing.T) {
	handler := NewCallbackHandler()
	ctx := context.Background()

	// Start server on random port
	err := handler.StartCallbackServer(ctx, "0")
	require.NoError(t, err)
	defer func() {
		if err := handler.StopCallbackServer(ctx); err != nil {
			t.Logf("Failed to stop callback server: %v", err)
		}
	}()

	t.Run("TestHealthEndpoint", func(t *testing.T) {
		port := handler.serverPort
		assert.NotEmpty(t, port, "server port must be assigned after StartCallbackServer")
		assert.NotEqual(t, "0", port, "server port must be a real port, not the placeholder 0")
	})
}
