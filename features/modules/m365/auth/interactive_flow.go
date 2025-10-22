package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// InteractiveAuthFlow manages the OAuth2 authorization code flow with PKCE
type InteractiveAuthFlow struct {
	provider        *OAuth2Provider
	config          *OAuth2Config
	httpClient      *http.Client
	callbackHandler *CallbackHandler
}

// AuthFlowState represents the state of an ongoing authorization flow
type AuthFlowState struct {
	// PKCE parameters
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
	State         string `json:"state"`
	Nonce         string `json:"nonce"`

	// Flow metadata
	TenantID        string    `json:"tenant_id"`
	UserID          string    `json:"user_id,omitempty"`
	RequestedScopes []string  `json:"requested_scopes"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`

	// Callback information
	RedirectURI  string `json:"redirect_uri"`
	CallbackPath string `json:"callback_path"`
}

// AuthFlowResult contains the result of a completed authorization flow
type AuthFlowResult struct {
	Success       bool         `json:"success"`
	AccessToken   *AccessToken `json:"access_token,omitempty"`
	UserContext   *UserContext `json:"user_context,omitempty"`
	GrantedScopes []string     `json:"granted_scopes,omitempty"`
	Error         string       `json:"error,omitempty"`
	ErrorDetails  string       `json:"error_details,omitempty"`
}

// NewInteractiveAuthFlow creates a new interactive authentication flow manager
func NewInteractiveAuthFlow(provider *OAuth2Provider, config *OAuth2Config) *InteractiveAuthFlow {
	return &InteractiveAuthFlow{
		provider:        provider,
		config:          config,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		callbackHandler: NewCallbackHandler(),
	}
}

// StartAuthFlow initiates the OAuth2 authorization code flow
func (f *InteractiveAuthFlow) StartAuthFlow(ctx context.Context, tenantID string, requestedScopes []string) (*AuthFlowState, string, error) {
	// Generate PKCE parameters
	codeVerifier, err := f.generateCodeVerifier()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	codeChallenge := f.generateCodeChallenge(codeVerifier)
	state := f.generateState()
	nonce := f.generateNonce()

	// Create flow state
	flowState := &AuthFlowState{
		CodeVerifier:    codeVerifier,
		CodeChallenge:   codeChallenge,
		State:           state,
		Nonce:           nonce,
		TenantID:        tenantID,
		RequestedScopes: requestedScopes,
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(10 * time.Minute), // 10 minute expiry
		RedirectURI:     f.config.RedirectURI,
		CallbackPath:    "/auth/callback",
	}

	// Store flow state temporarily
	if err := f.storeFlowState(state, flowState); err != nil {
		return nil, "", fmt.Errorf("failed to store flow state: %w", err)
	}

	// Build authorization URL
	authURL, err := f.buildAuthorizationURL(tenantID, flowState)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build authorization URL: %w", err)
	}

	return flowState, authURL, nil
}

// HandleCallback processes the OAuth2 callback and exchanges code for tokens
func (f *InteractiveAuthFlow) HandleCallback(ctx context.Context, callbackURL string) (*AuthFlowResult, error) {
	// Parse callback URL
	parsedURL, err := url.Parse(callbackURL)
	if err != nil {
		return &AuthFlowResult{
			Success:      false,
			Error:        "INVALID_CALLBACK_URL",
			ErrorDetails: fmt.Sprintf("Failed to parse callback URL: %v", err),
		}, nil
	}

	query := parsedURL.Query()

	// Check for error in callback
	if errorCode := query.Get("error"); errorCode != "" {
		return &AuthFlowResult{
			Success:      false,
			Error:        errorCode,
			ErrorDetails: query.Get("error_description"),
		}, nil
	}

	// Extract authorization code and state
	authCode := query.Get("code")
	state := query.Get("state")

	if authCode == "" || state == "" {
		return &AuthFlowResult{
			Success:      false,
			Error:        "MISSING_PARAMETERS",
			ErrorDetails: "Missing authorization code or state parameter",
		}, nil
	}

	// Retrieve flow state
	flowState, err := f.getFlowState(state)
	if err != nil {
		return &AuthFlowResult{
			Success:      false,
			Error:        "INVALID_STATE",
			ErrorDetails: fmt.Sprintf("Failed to retrieve flow state: %v", err),
		}, nil
	}

	// Validate flow state
	if err := f.validateFlowState(flowState); err != nil {
		return &AuthFlowResult{
			Success:      false,
			Error:        "INVALID_FLOW_STATE",
			ErrorDetails: fmt.Sprintf("Flow state validation failed: %v", err),
		}, nil
	}

	// Exchange authorization code for tokens
	tokenResponse, err := f.exchangeCodeForTokens(ctx, authCode, flowState)
	if err != nil {
		return &AuthFlowResult{
			Success:      false,
			Error:        "TOKEN_EXCHANGE_FAILED",
			ErrorDetails: fmt.Sprintf("Failed to exchange code for tokens: %v", err),
		}, nil
	}

	// Parse and validate tokens
	accessToken, userContext, err := f.processTokenResponse(tokenResponse, flowState)
	if err != nil {
		return &AuthFlowResult{
			Success:      false,
			Error:        "TOKEN_PROCESSING_FAILED",
			ErrorDetails: fmt.Sprintf("Failed to process token response: %v", err),
		}, nil
	}

	// Store tokens securely
	if err := f.storeTokens(flowState.TenantID, accessToken, userContext); err != nil {
		return &AuthFlowResult{
			Success:      false,
			Error:        "TOKEN_STORAGE_FAILED",
			ErrorDetails: fmt.Sprintf("Failed to store tokens: %v", err),
		}, nil
	}

	// Clean up flow state
	f.cleanupFlowState(state)

	return &AuthFlowResult{
		Success:       true,
		AccessToken:   accessToken,
		UserContext:   userContext,
		GrantedScopes: accessToken.GrantedScopes,
	}, nil
}

// TestCapabilities verifies that the obtained tokens have the necessary permissions
func (f *InteractiveAuthFlow) TestCapabilities(ctx context.Context, tenantID string, accessToken *AccessToken) (*CapabilityTestResult, error) {
	testResult := &CapabilityTestResult{
		TenantID: tenantID,
		TestedAt: time.Now(),
		Tests:    make(map[string]*CapabilityTest),
	}

	// Test basic user profile access
	testResult.Tests["user_read"] = f.testUserReadAccess(ctx, accessToken)

	// Test directory read access
	testResult.Tests["directory_read"] = f.testDirectoryReadAccess(ctx, accessToken)

	// Test group management (if scopes available)
	if f.hasScope(accessToken, "Group.ReadWrite.All") {
		testResult.Tests["group_management"] = f.testGroupManagementAccess(ctx, accessToken)
	}

	// Test conditional access (if scopes available)
	if f.hasScope(accessToken, "Policy.ReadWrite.ConditionalAccess") {
		testResult.Tests["conditional_access"] = f.testConditionalAccessAccess(ctx, accessToken)
	}

	// Test Intune management (if scopes available)
	if f.hasScope(accessToken, "DeviceManagementConfiguration.ReadWrite.All") {
		testResult.Tests["intune_management"] = f.testIntuneManagementAccess(ctx, accessToken)
	}

	// Calculate overall success
	testResult.OverallSuccess = f.calculateOverallSuccess(testResult.Tests)

	return testResult, nil
}

// PKCE helper methods

func (f *InteractiveAuthFlow) generateCodeVerifier() (string, error) {
	// Generate 32 random bytes (256 bits)
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	// Base64 URL encode without padding
	codeVerifier := base64.RawURLEncoding.EncodeToString(randomBytes)
	return codeVerifier, nil
}

func (f *InteractiveAuthFlow) generateCodeChallenge(codeVerifier string) string {
	// SHA256 hash the code verifier
	hash := sha256.Sum256([]byte(codeVerifier))

	// Base64 URL encode without padding
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return codeChallenge
}

func (f *InteractiveAuthFlow) generateState() string {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to timestamp-based state if crypto/rand fails
		return fmt.Sprintf("state-%x", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}

func (f *InteractiveAuthFlow) generateNonce() string {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to timestamp-based nonce if crypto/rand fails
		return fmt.Sprintf("nonce-%x", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}

// Authorization URL builder

func (f *InteractiveAuthFlow) buildAuthorizationURL(tenantID string, flowState *AuthFlowState) (string, error) {
	baseURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenantID)

	params := url.Values{
		"client_id":             {f.config.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {f.config.RedirectURI},
		"response_mode":         {"query"},
		"scope":                 {strings.Join(flowState.RequestedScopes, " ")},
		"state":                 {flowState.State},
		"nonce":                 {flowState.Nonce},
		"code_challenge":        {flowState.CodeChallenge},
		"code_challenge_method": {"S256"},
		"prompt":                {"consent"}, // Force consent screen
	}

	authURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())
	return authURL, nil
}

// Token exchange

func (f *InteractiveAuthFlow) exchangeCodeForTokens(ctx context.Context, authCode string, flowState *AuthFlowState) (*TokenResponse, error) {
	tokenURL := f.config.GetTokenURL()

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.config.ClientID},
		"client_secret": {f.config.ClientSecret},
		"code":          {authCode},
		"redirect_uri":  {f.config.RedirectURI},
		"code_verifier": {flowState.CodeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error - could add logger field to InteractiveAuthFlow
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

// Token processing and storage

func (f *InteractiveAuthFlow) processTokenResponse(tokenResponse *TokenResponse, flowState *AuthFlowState) (*AccessToken, *UserContext, error) {
	// Create AccessToken
	accessToken := &AccessToken{
		Token:         tokenResponse.AccessToken,
		TokenType:     tokenResponse.TokenType,
		ExpiresIn:     tokenResponse.ExpiresIn,
		ExpiresAt:     time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
		RefreshToken:  tokenResponse.RefreshToken,
		TenantID:      flowState.TenantID,
		IsDelegated:   true,
		GrantedScopes: strings.Split(tokenResponse.Scope, " "),
	}

	// Extract user information from ID token if available
	userContext, err := f.extractUserContext(tokenResponse.IDToken, flowState.TenantID)
	if err != nil {
		// Non-fatal error - create basic user context
		userContext = &UserContext{
			UserID:            "unknown",
			UserPrincipalName: "unknown",
			DisplayName:       "Unknown User",
			LastAuthenticated: time.Now(),
		}
	}

	accessToken.UserContext = userContext

	return accessToken, userContext, nil
}

func (f *InteractiveAuthFlow) storeTokens(tenantID string, accessToken *AccessToken, userContext *UserContext) error {
	// Store the access token
	if err := f.provider.credentialStore.StoreToken(tenantID, accessToken); err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}

	// Store delegated token for user context
	if userContext.UserID != "" {
		if err := f.provider.credentialStore.StoreDelegatedToken(tenantID, userContext.UserID, accessToken); err != nil {
			return fmt.Errorf("failed to store delegated token: %w", err)
		}

		// Store user context
		if err := f.provider.credentialStore.StoreUserContext(tenantID, userContext.UserID, userContext); err != nil {
			return fmt.Errorf("failed to store user context: %w", err)
		}
	}

	return nil
}

// State management

func (f *InteractiveAuthFlow) storeFlowState(state string, flowState *AuthFlowState) error {
	// In a real implementation, this would use a secure temporary store
	// For now, implement in-memory storage (not production ready)
	return f.callbackHandler.StoreFlowState(state, flowState)
}

func (f *InteractiveAuthFlow) getFlowState(state string) (*AuthFlowState, error) {
	return f.callbackHandler.GetFlowState(state)
}

func (f *InteractiveAuthFlow) validateFlowState(flowState *AuthFlowState) error {
	if time.Now().After(flowState.ExpiresAt) {
		return fmt.Errorf("flow state expired")
	}

	if flowState.CodeVerifier == "" || flowState.TenantID == "" {
		return fmt.Errorf("invalid flow state: missing required fields")
	}

	return nil
}

func (f *InteractiveAuthFlow) cleanupFlowState(state string) {
	f.callbackHandler.CleanupFlowState(state)
}

// Helper methods

func (f *InteractiveAuthFlow) hasScope(token *AccessToken, scope string) bool {
	// For MSP application permissions, check if we have the .default scope
	// which grants all consented application permissions
	for _, grantedScope := range token.GrantedScopes {
		if grantedScope == scope {
			return true
		}
		// For application permissions with .default scope, assume we have all consented permissions
		if grantedScope == "https://graph.microsoft.com/.default" {
			// For MSP scenarios, we assume all capabilities are available if .default scope is present
			// The actual capability testing will validate real API access
			return true
		}
	}
	return false
}

func (f *InteractiveAuthFlow) calculateOverallSuccess(tests map[string]*CapabilityTest) bool {
	for _, test := range tests {
		if !test.Success {
			return false
		}
	}
	return true
}

// Supporting types

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
}

type CapabilityTestResult struct {
	TenantID       string                     `json:"tenant_id"`
	TestedAt       time.Time                  `json:"tested_at"`
	OverallSuccess bool                       `json:"overall_success"`
	Tests          map[string]*CapabilityTest `json:"tests"`
}

type CapabilityTest struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	TestedAt    time.Time `json:"tested_at"`
	Details     string    `json:"details,omitempty"`
}
