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

// InteractiveAuthenticator provides methods for interactive OAuth2 flows
type InteractiveAuthenticator struct {
	provider     *OAuth2Provider
	callbackAddr string
	server       *http.Server
}

// NewInteractiveAuthenticator creates a new interactive authenticator
func NewInteractiveAuthenticator(provider *OAuth2Provider, callbackAddr string) *InteractiveAuthenticator {
	if callbackAddr == "" {
		callbackAddr = ":8080"
	}

	return &InteractiveAuthenticator{
		provider:     provider,
		callbackAddr: callbackAddr,
	}
}

// AuthenticateUser performs interactive user authentication and returns user context with delegated token
func (ia *InteractiveAuthenticator) AuthenticateUser(ctx context.Context, tenantID string) (*UserContext, *AccessToken, error) {
	// Generate PKCE parameters
	codeVerifier, codeChallenge, err := ia.generatePKCE()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate PKCE parameters: %w", err)
	}

	// Generate state parameter
	state, err := ia.generateState()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate state parameter: %w", err)
	}

	// Create authorization URL
	authURL, err := ia.provider.AuthorizeURL(tenantID, state, codeChallenge)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create authorization URL: %w", err)
	}

	// Set up callback handler
	resultChan := make(chan authResult, 1)
	ia.setupCallbackHandler(state, codeVerifier, tenantID, resultChan)

	// Start the callback server
	if err := ia.startCallbackServer(); err != nil {
		return nil, nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	defer ia.stopCallbackServer()

	// Open browser or show URL
	fmt.Printf("\n🔐 Interactive M365 Authentication Required\n")
	fmt.Printf("==================================================\n")
	fmt.Printf("Please open the following URL in your browser:\n\n")
	fmt.Printf("%s\n\n", authURL)
	fmt.Printf("After authorization, you will be redirected to localhost.\n")
	fmt.Printf("Waiting for callback...\n\n")

	// Wait for callback with timeout
	select {
	case result := <-resultChan:
		if result.err != nil {
			return nil, nil, result.err
		}
		
		// Get user info from the token
		userContext, err := ia.getUserInfo(ctx, result.token)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get user info: %w", err)
		}

		fmt.Printf("✅ Authentication successful! Welcome, %s\n", userContext.DisplayName)
		return userContext, result.token, nil

	case <-time.After(5 * time.Minute):
		return nil, nil, fmt.Errorf("authentication timed out after 5 minutes")
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

type authResult struct {
	token *AccessToken
	err   error
}

// setupCallbackHandler sets up the HTTP handler for the OAuth callback
func (ia *InteractiveAuthenticator) setupCallbackHandler(state, codeVerifier, tenantID string, resultChan chan authResult) {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		defer close(resultChan)

		// Check for errors
		if errCode := r.URL.Query().Get("error"); errCode != "" {
			errDesc := r.URL.Query().Get("error_description")
			err := fmt.Errorf("OAuth error: %s - %s", errCode, errDesc)
			resultChan <- authResult{err: err}
			
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Authentication Failed</title></head>
<body>
	<h1>❌ Authentication Failed</h1>
	<p>Error: %s</p>
	<p>Description: %s</p>
	<p>You can close this window.</p>
</body>
</html>`, errCode, errDesc)
			return
		}

		// Verify state parameter
		returnedState := r.URL.Query().Get("state")
		if returnedState != state {
			err := fmt.Errorf("state parameter mismatch")
			resultChan <- authResult{err: err}
			
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Authentication Failed</title></head>
<body>
	<h1>❌ Authentication Failed</h1>
	<p>State parameter mismatch. Possible CSRF attack.</p>
	<p>You can close this window.</p>
</body>
</html>`)
			return
		}

		// Get authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			err := fmt.Errorf("no authorization code received")
			resultChan <- authResult{err: err}
			
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Authentication Failed</title></head>
<body>
	<h1>❌ Authentication Failed</h1>
	<p>No authorization code received.</p>
	<p>You can close this window.</p>
</body>
</html>`)
			return
		}

		// Exchange code for token
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		token, err := ia.provider.ExchangeCodeForToken(ctx, tenantID, code, codeVerifier)
		if err != nil {
			resultChan <- authResult{err: err}
			
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Authentication Failed</title></head>
<body>
	<h1>❌ Authentication Failed</h1>
	<p>Failed to exchange authorization code for token: %s</p>
	<p>You can close this window.</p>
</body>
</html>`, err.Error())
			return
		}

		// Success!
		resultChan <- authResult{token: token}
		
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
	<title>Authentication Successful</title>
	<style>
		body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
		.success { color: green; }
		.container { max-width: 600px; margin: 0 auto; }
	</style>
</head>
<body>
	<div class="container">
		<h1 class="success">✅ Authentication Successful!</h1>
		<p>You have successfully authenticated with Microsoft 365.</p>
		<p>You can now close this window and return to the terminal.</p>
		<hr>
		<p><small>CFGMS M365 Virtual Steward - Delegated Permissions</small></p>
	</div>
</body>
</html>`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
	<title>CFGMS Authentication</title>
	<style>
		body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
		.container { max-width: 600px; margin: 0 auto; }
	</style>
</head>
<body>
	<div class="container">
		<h1>🔐 CFGMS M365 Authentication</h1>
		<p>Waiting for authentication callback...</p>
		<p>If you haven't already, please complete the authentication in your browser.</p>
	</div>
</body>
</html>`)
	})

	ia.server = &http.Server{
		Addr:    ia.callbackAddr,
		Handler: mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// startCallbackServer starts the HTTP server for handling callbacks
func (ia *InteractiveAuthenticator) startCallbackServer() error {
	go func() {
		if err := ia.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Callback server error: %v\n", err)
		}
	}()

	// Give server a moment to start
	time.Sleep(100 * time.Millisecond)
	return nil
}

// stopCallbackServer stops the callback server
func (ia *InteractiveAuthenticator) stopCallbackServer() {
	if ia.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ia.server.Shutdown(ctx)
	}
}

// generatePKCE generates PKCE code verifier and challenge
func (ia *InteractiveAuthenticator) generatePKCE() (codeVerifier, codeChallenge string, err error) {
	// Generate code verifier (43-128 characters)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	codeVerifier = base64.RawURLEncoding.EncodeToString(bytes)

	// Generate code challenge (SHA256 hash of verifier)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return codeVerifier, codeChallenge, nil
}

// generateState generates a random state parameter
func (ia *InteractiveAuthenticator) generateState() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// getUserInfo retrieves user information from Microsoft Graph
func (ia *InteractiveAuthenticator) getUserInfo(ctx context.Context, token *AccessToken) (*UserContext, error) {
	// Create request to get user info
	req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")

	// Make the request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status %d", resp.StatusCode)
	}

	// Parse response
	var userInfo struct {
		ID                string   `json:"id"`
		UserPrincipalName string   `json:"userPrincipalName"`
		DisplayName       string   `json:"displayName"`
		GivenName         string   `json:"givenName"`
		Surname           string   `json:"surname"`
		JobTitle          string   `json:"jobTitle"`
		Mail              string   `json:"mail"`
		BusinessPhones    []string `json:"businessPhones"`
	}

	if err := parseJSONResponse(resp, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	// Get user's directory roles
	roles, err := ia.getUserRoles(ctx, token)
	if err != nil {
		// Log warning but don't fail - roles are nice-to-have
		fmt.Printf("Warning: Could not retrieve user roles: %v\n", err)
		roles = []string{}
	}

	// Create user context
	userContext := &UserContext{
		UserID:            userInfo.ID,
		UserPrincipalName: userInfo.UserPrincipalName,
		DisplayName:       userInfo.DisplayName,
		Roles:             roles,
		LastAuthenticated: time.Now(),
		SessionID:         ia.generateSessionID(),
	}

	return userContext, nil
}

// getUserRoles retrieves the user's directory roles
func (ia *InteractiveAuthenticator) getUserRoles(ctx context.Context, token *AccessToken) ([]string, error) {
	// Create request to get user's directory roles
	req, err := http.NewRequestWithContext(ctx, "GET", 
		"https://graph.microsoft.com/v1.0/me/memberOf?$filter=startswith(odata.type,'microsoft.graph.directoryRole')", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create roles request: %w", err)
	}

	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")

	// Make the request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
			_ = err
		}
	}()

	// If forbidden, user may not have permission to read roles
	if resp.StatusCode == http.StatusForbidden {
		return []string{"Standard User"}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("roles request failed with status %d", resp.StatusCode)
	}

	// Parse response
	var rolesResponse struct {
		Value []struct {
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}

	if err := parseJSONResponse(resp, &rolesResponse); err != nil {
		return nil, fmt.Errorf("failed to parse roles: %w", err)
	}

	// Extract role names
	var roles []string
	for _, role := range rolesResponse.Value {
		roles = append(roles, role.DisplayName)
	}

	// If no roles found, user is a standard user
	if len(roles) == 0 {
		roles = []string{"Standard User"}
	}

	return roles, nil
}

// generateSessionID generates a unique session ID
func (ia *InteractiveAuthenticator) generateSessionID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("session-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("session-%s", base64.RawURLEncoding.EncodeToString(bytes))
}

// TestDelegatedPermissions tests delegated permissions with the provided user context
func (ia *InteractiveAuthenticator) TestDelegatedPermissions(ctx context.Context, userContext *UserContext, token *AccessToken) (*PermissionTestResult, error) {
	result := &PermissionTestResult{
		UserContext:    userContext,
		TestedScopes:   make(map[string]bool),
		FailedScopes:   make([]string, 0),
		TestResults:    make(map[string]string),
		TestTimestamp:  time.Now(),
	}

	// Test common scopes
	scopesToTest := []string{
		"User.Read",
		"User.ReadWrite.All", 
		"Directory.Read.All",
		"Directory.ReadWrite.All",
		"Group.Read.All",
		"Group.ReadWrite.All",
		"Policy.ReadWrite.ConditionalAccess",
		"DeviceManagementConfiguration.ReadWrite.All",
	}

	fmt.Printf("🧪 Testing Delegated Permissions for %s\n", userContext.DisplayName)
	fmt.Printf("================================================\n")

	for _, scope := range scopesToTest {
		fmt.Printf("Testing %s... ", scope)
		
		err := ia.provider.ValidatePermissions(ctx, token, []string{scope})
		if err != nil {
			result.TestedScopes[scope] = false
			result.FailedScopes = append(result.FailedScopes, scope)
			result.TestResults[scope] = fmt.Sprintf("Failed: %s", err.Error())
			fmt.Printf("❌ Failed\n")
		} else {
			result.TestedScopes[scope] = true
			result.TestResults[scope] = "Success"
			fmt.Printf("✅ Success\n")
		}
	}

	fmt.Printf("\n📊 Test Summary:\n")
	fmt.Printf("- Successful scopes: %d\n", len(result.TestedScopes)-len(result.FailedScopes))
	fmt.Printf("- Failed scopes: %d\n", len(result.FailedScopes))
	
	if len(result.FailedScopes) > 0 {
		fmt.Printf("- Failed scopes: %s\n", strings.Join(result.FailedScopes, ", "))
	}

	return result, nil
}

// PermissionTestResult represents the results of permission testing
type PermissionTestResult struct {
	UserContext    *UserContext      `json:"user_context"`
	TestedScopes   map[string]bool   `json:"tested_scopes"`
	FailedScopes   []string          `json:"failed_scopes"`
	TestResults    map[string]string `json:"test_results"`
	TestTimestamp  time.Time         `json:"test_timestamp"`
}

// GetScopeString returns the scopes as a formatted string for authorization URLs
func (c *OAuth2Config) GetDelegatedAuthURL() string {
	if !c.SupportsDelegatedAuth() {
		return ""
	}
	
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {c.ClientID},
		"redirect_uri":  {c.RedirectURI},
		"scope":         {c.GetDelegatedScopeString()},
		"response_mode": {"query"},
	}
	
	return fmt.Sprintf("%s/oauth2/v2.0/authorize?%s", c.GetAuthorityURL(), params.Encode())
}

// parseJSONResponse parses a JSON response into the provided interface
func parseJSONResponse(resp *http.Response, v interface{}) error {
	decoder := json.NewDecoder(resp.Body)
	return decoder.Decode(v)
}