// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package saas auth implements universal authentication abstraction
// for SaaS provider integrations.
//
// This authentication system provides a unified interface for all
// common authentication mechanisms used by SaaS APIs, including:
//   - OAuth2 (authorization code, client credentials, device flow)
//   - API Keys (header, query parameter, custom formats)
//   - Basic Authentication
//   - Bearer Tokens
//   - JWT (signed tokens)
//   - Client Certificates
//   - AWS Signature V4
//   - Custom authentication schemes
//
// The system handles token refresh, credential storage, and automatic
// authentication header generation for HTTP requests.
package saas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/golang-jwt/jwt/v5"
)

// UniversalAuthenticator provides authentication services for all provider types.
// Not safe for concurrent calls to Authenticate/RefreshAuth on the same instance
// (oauth2Client is replaced per-provider; add a mutex if concurrent use is required).
type UniversalAuthenticator struct {
	credStore    auth.CredentialStore
	httpClient   *http.Client
	oauth2Client OAuth2Client
}

// NewUniversalAuthenticator creates a new universal authenticator
func NewUniversalAuthenticator(credStore auth.CredentialStore, httpClient *http.Client) *UniversalAuthenticator {
	return &UniversalAuthenticator{
		credStore:    credStore,
		httpClient:   httpClient,
		oauth2Client: NewOAuth2Client(httpClient, nil),
	}
}

// Authenticate performs authentication using the specified method and configuration
func (ua *UniversalAuthenticator) Authenticate(ctx context.Context, provider string, config AuthConfig) error {
	switch config.Method {
	case AuthMethodOAuth2:
		return ua.authenticateOAuth2(ctx, provider, config.Config)
	case AuthMethodAPIKey:
		return ua.authenticateAPIKey(ctx, provider, config.Config)
	case AuthMethodBasicAuth:
		return ua.authenticateBasicAuth(ctx, provider, config.Config)
	case AuthMethodBearerToken:
		return ua.authenticateBearerToken(ctx, provider, config.Config)
	case AuthMethodJWT:
		return ua.authenticateJWT(ctx, provider, config.Config)
	case AuthMethodClientCert:
		return ua.authenticateClientCert(ctx, provider, config.Config)
	case AuthMethodAWSSignature:
		return ua.authenticateAWSSignature(ctx, provider, config.Config)
	case AuthMethodCustom:
		return ua.authenticateCustom(ctx, provider, config.Config)
	default:
		return fmt.Errorf("unsupported authentication method: %s", config.Method)
	}
}

// IsAuthenticated checks if valid credentials exist for the provider
func (ua *UniversalAuthenticator) IsAuthenticated(ctx context.Context, provider string, method AuthMethod) bool {
	switch method {
	case AuthMethodOAuth2:
		authToken, err := ua.credStore.GetToken(provider)
		if err != nil {
			return false
		}
		tokenSet := accessTokenToTokenSet(authToken)
		return tokenSet != nil && tokenSet.IsValid(5*time.Minute) // 5 min threshold
	case AuthMethodAPIKey, AuthMethodBasicAuth, AuthMethodBearerToken, AuthMethodJWT:
		_, err := ua.credStore.GetToken(provider + ":secret")
		return err == nil
	default:
		return false
	}
}

// RefreshAuth refreshes authentication credentials if needed
func (ua *UniversalAuthenticator) RefreshAuth(ctx context.Context, provider string, method AuthMethod) error {
	switch method {
	case AuthMethodOAuth2:
		return ua.refreshOAuth2Token(ctx, provider)
	default:
		// Most auth methods don't need refresh
		return nil
	}
}

// GetAuthHeaders returns HTTP headers for authenticated requests
func (ua *UniversalAuthenticator) GetAuthHeaders(ctx context.Context, provider string, method AuthMethod) (map[string]string, error) {
	switch method {
	case AuthMethodOAuth2:
		authToken, err := ua.credStore.GetToken(provider)
		if err != nil {
			return nil, fmt.Errorf("failed to get OAuth2 token: %w", err)
		}
		tokenSet := accessTokenToTokenSet(authToken)
		return map[string]string{
			"Authorization": tokenSet.GetAuthorizationHeader(),
		}, nil

	case AuthMethodAPIKey:
		return ua.getAPIKeyHeaders(provider)

	case AuthMethodBasicAuth:
		return ua.getBasicAuthHeaders(provider)

	case AuthMethodBearerToken:
		return ua.getBearerTokenHeaders(provider)

	case AuthMethodJWT:
		return ua.getJWTHeaders(provider)

	default:
		// Design decision: custom auth method headers must be pre-computed by the caller and passed via the custom headers map; this method only covers standard methods.
		return nil, fmt.Errorf("unsupported auth method: %s", method)
	}
}

// OAuth2 Authentication Implementation

func (ua *UniversalAuthenticator) authenticateOAuth2(ctx context.Context, provider string, config map[string]interface{}) error {
	oauth2Config, err := parseOAuth2Config(config)
	if err != nil {
		return fmt.Errorf("invalid OAuth2 config: %w", err)
	}

	// Create a configured client so subsequent RefreshToken calls have access to
	// TokenURL and client credentials without requiring an interface signature change.
	oauth2Client := NewOAuth2Client(ua.httpClient, oauth2Config)
	ua.oauth2Client = oauth2Client

	// Start OAuth2 flow
	flow, err := ua.oauth2Client.StartFlow(ctx, oauth2Config)
	if err != nil {
		return fmt.Errorf("failed to start OAuth2 flow: %w", err)
	}

	// For client credentials flow, complete immediately
	if oauth2Config.GrantType == "client_credentials" {
		tokenSet, err := ua.oauth2Client.ClientCredentialsGrant(ctx, oauth2Config)
		if err != nil {
			return fmt.Errorf("client credentials grant failed: %w", err)
		}

		return ua.credStore.StoreToken(provider, tokenSetToAccessToken(tokenSet, provider))
	}

	// For authorization code flow, return the authorization URL
	return fmt.Errorf("authorization code flow requires user interaction: %s", flow.AuthURL)
}

func (ua *UniversalAuthenticator) refreshOAuth2Token(ctx context.Context, provider string) error {
	authToken, err := ua.credStore.GetToken(provider)
	if err != nil {
		return fmt.Errorf("failed to get token set: %w", err)
	}
	tokenSet := accessTokenToTokenSet(authToken)

	if tokenSet.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	newTokenSet, err := ua.oauth2Client.RefreshToken(ctx, tokenSet.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	return ua.credStore.StoreToken(provider, tokenSetToAccessToken(newTokenSet, provider))
}

// API Key Authentication Implementation

func (ua *UniversalAuthenticator) authenticateAPIKey(ctx context.Context, provider string, config map[string]interface{}) error {
	apiKeyConfig, err := parseAPIKeyConfig(config)
	if err != nil {
		return fmt.Errorf("invalid API key config: %w", err)
	}

	// Store the API key configuration as JSON
	data, err := json.Marshal(struct {
		Key        string `json:"key"`
		Header     string `json:"header"`
		QueryParam string `json:"query_param"`
	}{
		Key:        apiKeyConfig.Key,
		Header:     apiKeyConfig.Header,
		QueryParam: apiKeyConfig.QueryParam,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal API key config: %w", err)
	}
	return ua.credStore.StoreToken(provider+":secret", &auth.AccessToken{Token: string(data), TenantID: provider})
}

func (ua *UniversalAuthenticator) getAPIKeyHeaders(provider string) (map[string]string, error) {
	secretToken, err := ua.credStore.GetToken(provider + ":secret")
	if err != nil {
		return nil, fmt.Errorf("failed to get API key config: %w", err)
	}

	var apiKey struct {
		Key        string `json:"key"`
		Header     string `json:"header"`
		QueryParam string `json:"query_param"`
	}
	if err := json.Unmarshal([]byte(secretToken.Token), &apiKey); err != nil {
		return nil, fmt.Errorf("invalid API key config: %w", err)
	}

	if apiKey.Header != "" {
		return map[string]string{apiKey.Header: apiKey.Key}, nil
	}
	return map[string]string{"X-API-Key": apiKey.Key}, nil
}

// Basic Authentication Implementation

func (ua *UniversalAuthenticator) authenticateBasicAuth(ctx context.Context, provider string, config map[string]interface{}) error {
	basicConfig, err := parseBasicAuthConfig(config)
	if err != nil {
		return fmt.Errorf("invalid basic auth config: %w", err)
	}

	// Store username and password as JSON
	data, err := json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: basicConfig.Username,
		Password: basicConfig.Password,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal basic auth config: %w", err)
	}
	return ua.credStore.StoreToken(provider+":secret", &auth.AccessToken{Token: string(data), TenantID: provider})
}

func (ua *UniversalAuthenticator) getBasicAuthHeaders(provider string) (map[string]string, error) {
	secretToken, err := ua.credStore.GetToken(provider + ":secret")
	if err != nil {
		return nil, fmt.Errorf("failed to get basic auth config: %w", err)
	}

	var basicAuth struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(secretToken.Token), &basicAuth); err != nil {
		return nil, fmt.Errorf("invalid basic auth config: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(basicAuth.Username + ":" + basicAuth.Password))
	return map[string]string{
		"Authorization": "Basic " + encoded,
	}, nil
}

// Bearer Token Authentication Implementation

func (ua *UniversalAuthenticator) authenticateBearerToken(ctx context.Context, provider string, config map[string]interface{}) error {
	bearerConfig, err := parseBearerTokenConfig(config)
	if err != nil {
		return fmt.Errorf("invalid bearer token config: %w", err)
	}

	return ua.credStore.StoreToken(provider+":secret", &auth.AccessToken{Token: bearerConfig.Token, TenantID: provider})
}

func (ua *UniversalAuthenticator) getBearerTokenHeaders(provider string) (map[string]string, error) {
	secretToken, err := ua.credStore.GetToken(provider + ":secret")
	if err != nil {
		return nil, fmt.Errorf("failed to get bearer token: %w", err)
	}

	return map[string]string{
		"Authorization": "Bearer " + secretToken.Token,
	}, nil
}

// JWT Authentication Implementation

func (ua *UniversalAuthenticator) authenticateJWT(ctx context.Context, provider string, config map[string]interface{}) error {
	jwtConfig, err := parseJWTConfig(config)
	if err != nil {
		return fmt.Errorf("invalid JWT config: %w", err)
	}

	// Generate JWT token
	token, err := ua.generateJWT(jwtConfig)
	if err != nil {
		return fmt.Errorf("failed to generate JWT: %w", err)
	}

	return ua.credStore.StoreToken(provider+":secret", &auth.AccessToken{Token: token, TenantID: provider})
}

func (ua *UniversalAuthenticator) getJWTHeaders(provider string) (map[string]string, error) {
	secretToken, err := ua.credStore.GetToken(provider + ":secret")
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT token: %w", err)
	}

	return map[string]string{
		"Authorization": "Bearer " + secretToken.Token,
	}, nil
}

// Client Certificate Authentication Implementation

func (ua *UniversalAuthenticator) authenticateClientCert(ctx context.Context, provider string, config map[string]interface{}) error {
	// Client certificate authentication is handled at the HTTP client level
	// This would configure the HTTP client with the certificate
	return fmt.Errorf("client certificate authentication is not supported by this build")
}

// AWS Signature V4 Authentication Implementation

func (ua *UniversalAuthenticator) authenticateAWSSignature(ctx context.Context, provider string, config map[string]interface{}) error {
	awsConfig, err := parseAWSSignatureConfig(config)
	if err != nil {
		return fmt.Errorf("invalid AWS signature config: %w", err)
	}

	data, err := json.Marshal(awsConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal AWS signature config: %w", err)
	}

	return ua.credStore.StoreToken(provider+":secret", &auth.AccessToken{Token: string(data), TenantID: provider})
}

// VerifyAWSSignedRequest verifies an AWS Signature V4 signed HTTP request against
// credentials previously stored via authenticateAWSSignature. Returns nil when the
// signature is valid, an error wrapping codes.Unauthenticated on signature mismatch,
// or a descriptive error on a malformed Authorization header.
func (ua *UniversalAuthenticator) VerifyAWSSignedRequest(ctx context.Context, provider string, r *http.Request) error {
	secretToken, err := ua.credStore.GetToken(provider + ":secret")
	if err != nil {
		return fmt.Errorf("failed to retrieve AWS credentials for provider %q: %w", provider, err)
	}

	var awsCreds AWSSignatureConfig
	if err := json.Unmarshal([]byte(secretToken.Token), &awsCreds); err != nil {
		return fmt.Errorf("stored AWS credentials for provider %q are malformed: %w", provider, err)
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing Authorization header")
	}

	parsed, err := parseV4AuthorizationHeader(authHeader)
	if err != nil {
		return fmt.Errorf("malformed AWS Signature V4 Authorization header: %w", err)
	}

	if parsed.accessKeyID != awsCreds.AccessKeyID {
		return fmt.Errorf("%w: credential access key does not match stored credentials", errUnauthenticated)
	}

	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return fmt.Errorf("missing X-Amz-Date header")
	}

	// Validate X-Amz-Date is in the required ISO 8601 basic format.
	if _, err := time.Parse("20060102T150405Z", amzDate); err != nil {
		return fmt.Errorf("malformed X-Amz-Date header %q: %w", amzDate, err)
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		// Empty body hash per SigV4 spec.
		payloadHash = "e3b0c44298fc1c149afbf4c8996fb924" +
			"27ae41e4649b934ca495991b7852b855"
	}

	canonicalReq := buildCanonicalRequest(r, parsed.signedHeaders, payloadHash)
	stringToSign := buildStringToSign(amzDate, parsed.credentialScope, canonicalReq)
	signingKey := deriveV4SigningKey(awsCreds.SecretAccessKey, parsed.date, parsed.region, parsed.service)
	expectedSig := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	if !hmac.Equal([]byte(expectedSig), []byte(parsed.signature)) {
		return fmt.Errorf("%w: signature verification failed", errUnauthenticated)
	}

	return nil
}

// errUnauthenticated is a sentinel that callers can match with errors.Is to distinguish
// authentication failures from internal errors.
var errUnauthenticated = fmt.Errorf("unauthenticated")

// Custom Authentication Implementation

func (ua *UniversalAuthenticator) authenticateCustom(ctx context.Context, provider string, config map[string]interface{}) error {
	// Design decision: custom authentication is provider-specific and must be implemented in a provider-specific Authenticate() override.
	return fmt.Errorf("custom authentication is not supported by this build")
}

// Helper functions for parsing configuration

func parseOAuth2Config(config map[string]interface{}) (*ExtendedOAuth2Config, error) {
	oauth2Config := &ExtendedOAuth2Config{}

	if clientID, ok := config["client_id"].(string); ok {
		oauth2Config.ClientID = clientID
	}
	if clientSecret, ok := config["client_secret"].(string); ok {
		oauth2Config.ClientSecret = clientSecret
	}
	if tokenURL, ok := config["token_url"].(string); ok {
		oauth2Config.TokenURL = tokenURL
	}
	if authURL, ok := config["auth_url"].(string); ok {
		oauth2Config.AuthURL = authURL
	}
	if grantType, ok := config["grant_type"].(string); ok {
		oauth2Config.GrantType = grantType
	}
	if scopes, ok := config["scopes"].([]string); ok {
		oauth2Config.Scopes = scopes
	}

	return oauth2Config, nil
}

func parseAPIKeyConfig(config map[string]interface{}) (*APIKeyConfig, error) {
	apiKeyConfig := &APIKeyConfig{}

	if key, ok := config["key"].(string); ok {
		apiKeyConfig.Key = key
	}
	if header, ok := config["header"].(string); ok {
		apiKeyConfig.Header = header
	}
	if queryParam, ok := config["query_param"].(string); ok {
		apiKeyConfig.QueryParam = queryParam
	}

	return apiKeyConfig, nil
}

func parseBasicAuthConfig(config map[string]interface{}) (*BasicAuthConfig, error) {
	basicConfig := &BasicAuthConfig{}

	if username, ok := config["username"].(string); ok {
		basicConfig.Username = username
	}
	if password, ok := config["password"].(string); ok {
		basicConfig.Password = password
	}

	return basicConfig, nil
}

func parseBearerTokenConfig(config map[string]interface{}) (*BearerTokenConfig, error) {
	bearerConfig := &BearerTokenConfig{}

	if token, ok := config["token"].(string); ok {
		bearerConfig.Token = token
	}

	return bearerConfig, nil
}

func parseJWTConfig(config map[string]interface{}) (*JWTConfig, error) {
	jwtConfig := &JWTConfig{}

	if token, ok := config["token"].(string); ok {
		jwtConfig.Token = token
	}
	if privateKey, ok := config["private_key"].(string); ok {
		jwtConfig.PrivateKey = privateKey
	}
	if algorithm, ok := config["algorithm"].(string); ok {
		jwtConfig.Algorithm = algorithm
	}
	if claims, ok := config["claims"].(map[string]interface{}); ok {
		jwtConfig.Claims = claims
	}

	return jwtConfig, nil
}

// OAuth2Client interface for OAuth2 operations
type OAuth2Client interface {
	StartFlow(ctx context.Context, config *ExtendedOAuth2Config) (*OAuth2Flow, error)
	ExchangeCode(ctx context.Context, flow *OAuth2Flow, authCode string) (*TokenSet, error)
	ClientCredentialsGrant(ctx context.Context, config *ExtendedOAuth2Config) (*TokenSet, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error)
}

// ExtendedOAuth2Config extends the basic OAuth2Config with additional fields
type ExtendedOAuth2Config struct {
	OAuth2Config
	GrantType string `json:"grant_type"` // "authorization_code", "client_credentials", "device_code"
}

// DefaultOAuth2Client implements OAuth2Client interface
type DefaultOAuth2Client struct {
	httpClient *http.Client
	config     *ExtendedOAuth2Config
}

// NewOAuth2Client creates a new OAuth2 client. config is optional; when non-nil,
// it is stored for use by RefreshToken which needs TokenURL and client credentials.
func NewOAuth2Client(httpClient *http.Client, config *ExtendedOAuth2Config) OAuth2Client {
	return &DefaultOAuth2Client{
		httpClient: httpClient,
		config:     config,
	}
}

func (c *DefaultOAuth2Client) StartFlow(ctx context.Context, config *ExtendedOAuth2Config) (*OAuth2Flow, error) {
	// Implementation would create OAuth2 flow with PKCE
	return &OAuth2Flow{
		AuthURL:      config.AuthURL,
		RedirectURI:  config.RedirectURL,
		TokenURL:     config.TokenURL,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Created:      time.Now(),
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}, nil
}

func (c *DefaultOAuth2Client) ExchangeCode(ctx context.Context, flow *OAuth2Flow, authCode string) (*TokenSet, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authCode)
	data.Set("redirect_uri", flow.RedirectURI)
	data.Set("client_id", flow.ClientID)
	data.Set("client_secret", flow.ClientSecret)
	if flow.CodeVerifier != "" {
		data.Set("code_verifier", flow.CodeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", flow.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	tokenSet := &TokenSet{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}
	if tokenResp.Scope != "" {
		tokenSet.Scopes = strings.Fields(tokenResp.Scope)
	}
	return tokenSet, nil
}

func (c *DefaultOAuth2Client) ClientCredentialsGrant(ctx context.Context, config *ExtendedOAuth2Config) (*TokenSet, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	if len(config.Scopes) > 0 {
		data.Set("scope", strings.Join(config.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var tokenResp struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int    `json:"expires_in"`
		Scope            string `json:"scope"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("OAuth2 error: %s - %s", tokenResp.Error, tokenResp.ErrorDescription)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status: %d", resp.StatusCode)
	}

	tokenSet := &TokenSet{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}
	if tokenResp.Scope != "" {
		tokenSet.Scopes = strings.Fields(tokenResp.Scope)
	}
	return tokenSet, nil
}

func (c *DefaultOAuth2Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error) {
	if c.config == nil || c.config.TokenURL == "" {
		return nil, fmt.Errorf("RefreshToken: oauth2 client not configured with token URL and credentials")
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", c.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var tokenResp struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int    `json:"expires_in"`
		Scope            string `json:"scope"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("OAuth2 error: %s - %s", tokenResp.Error, tokenResp.ErrorDescription)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status: %d", resp.StatusCode)
	}

	tokenSet := &TokenSet{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}
	if tokenSet.RefreshToken == "" {
		tokenSet.RefreshToken = refreshToken
	}
	if tokenResp.Scope != "" {
		tokenSet.Scopes = strings.Fields(tokenResp.Scope)
	}
	return tokenSet, nil
}

// generateJWT signs a real JWT using github.com/golang-jwt/jwt/v5.
// If config.Token is non-empty it is returned directly (pre-signed token passthrough).
// config.PrivateKey must be set; an error is returned when it is empty.
// config.Algorithm selects the signing method; defaults to RS256 when empty.
func (ua *UniversalAuthenticator) generateJWT(config *JWTConfig) (string, error) {
	if config.Token != "" {
		return config.Token, nil
	}
	if config.PrivateKey == "" {
		return "", fmt.Errorf("generateJWT: private_key is required")
	}

	algorithm := config.Algorithm
	if algorithm == "" {
		algorithm = "RS256"
	}

	claims := jwt.MapClaims{}
	for k, v := range config.Claims {
		claims[k] = v
	}
	now := time.Now()
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Add(time.Hour).Unix()
	}

	var (
		token *jwt.Token
		key   interface{}
	)
	switch algorithm {
	case "HS256":
		key = []byte(config.PrivateKey)
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	case "HS384":
		key = []byte(config.PrivateKey)
		token = jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	case "HS512":
		key = []byte(config.PrivateKey)
		token = jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	case "RS384":
		pk, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(config.PrivateKey))
		if err != nil {
			return "", fmt.Errorf("generateJWT: failed to parse RSA private key: %w", err)
		}
		key = pk
		token = jwt.NewWithClaims(jwt.SigningMethodRS384, claims)
	case "RS512":
		pk, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(config.PrivateKey))
		if err != nil {
			return "", fmt.Errorf("generateJWT: failed to parse RSA private key: %w", err)
		}
		key = pk
		token = jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	default:
		// RS256 is the default for empty or unrecognised algorithm values.
		pk, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(config.PrivateKey))
		if err != nil {
			return "", fmt.Errorf("generateJWT: failed to parse RSA private key: %w", err)
		}
		key = pk
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	}

	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("generateJWT: failed to sign token: %w", err)
	}
	return signed, nil
}

// AuthMiddleware provides HTTP middleware for automatic authentication
func (ua *UniversalAuthenticator) AuthMiddleware(provider string, method AuthMethod) func(http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return &authRoundTripper{
			next:     next,
			auth:     ua,
			provider: provider,
			method:   method,
		}
	}
}

type authRoundTripper struct {
	next     http.RoundTripper
	auth     *UniversalAuthenticator
	provider string
	method   AuthMethod
}

func (rt *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add authentication headers
	headers, err := rt.auth.GetAuthHeaders(req.Context(), rt.provider, rt.method)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth headers: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Handle token refresh for OAuth2
	if rt.method == AuthMethodOAuth2 {
		if !rt.auth.IsAuthenticated(req.Context(), rt.provider, rt.method) {
			if err := rt.auth.RefreshAuth(req.Context(), rt.provider, rt.method); err != nil {
				return nil, fmt.Errorf("failed to refresh auth: %w", err)
			}

			// Get updated headers after refresh
			headers, err := rt.auth.GetAuthHeaders(req.Context(), rt.provider, rt.method)
			if err != nil {
				return nil, fmt.Errorf("failed to get refreshed auth headers: %w", err)
			}

			for key, value := range headers {
				req.Header.Set(key, value)
			}
		}
	}

	return rt.next.RoundTrip(req)
}

// parseAWSSignatureConfig extracts AWS Signature V4 credentials from a config map.
func parseAWSSignatureConfig(config map[string]interface{}) (*AWSSignatureConfig, error) {
	awsConfig := &AWSSignatureConfig{}
	if v, ok := config["access_key_id"].(string); ok {
		awsConfig.AccessKeyID = v
	}
	if v, ok := config["secret_access_key"].(string); ok {
		awsConfig.SecretAccessKey = v
	}
	if v, ok := config["region"].(string); ok {
		awsConfig.Region = v
	}
	if v, ok := config["service"].(string); ok {
		awsConfig.Service = v
	}
	if awsConfig.AccessKeyID == "" {
		return nil, fmt.Errorf("access_key_id is required")
	}
	if awsConfig.SecretAccessKey == "" {
		return nil, fmt.Errorf("secret_access_key is required")
	}
	return awsConfig, nil
}

// v4ParsedAuth holds the components extracted from an AWS SigV4 Authorization header.
type v4ParsedAuth struct {
	accessKeyID     string
	credentialScope string // date/region/service/aws4_request
	date            string // YYYYMMDD
	region          string
	service         string
	signedHeaders   string // semicolon-separated, already lower-cased
	signature       string
}

// parseV4AuthorizationHeader parses:
//
//	AWS4-HMAC-SHA256 Credential=AKID/date/region/svc/aws4_request, SignedHeaders=..., Signature=...
func parseV4AuthorizationHeader(header string) (*v4ParsedAuth, error) {
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(header, prefix) {
		return nil, fmt.Errorf("expected AWS4-HMAC-SHA256 prefix, got: %.40s", header)
	}

	rest := header[len(prefix):]
	parts := strings.Split(rest, ", ")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 comma-separated components, got %d", len(parts))
	}

	kv := func(s, key string) (string, error) {
		if !strings.HasPrefix(s, key+"=") {
			return "", fmt.Errorf("expected component %q, got: %.40s", key, s)
		}
		return strings.TrimPrefix(s, key+"="), nil
	}

	credential, err := kv(parts[0], "Credential")
	if err != nil {
		return nil, err
	}
	signedHeaders, err := kv(parts[1], "SignedHeaders")
	if err != nil {
		return nil, err
	}
	signature, err := kv(parts[2], "Signature")
	if err != nil {
		return nil, err
	}

	// Credential = AKID/YYYYMMDD/region/service/aws4_request
	credParts := strings.SplitN(credential, "/", 5)
	if len(credParts) != 5 {
		return nil, fmt.Errorf("invalid Credential format: %q", credential)
	}

	return &v4ParsedAuth{
		accessKeyID:     credParts[0],
		credentialScope: strings.Join(credParts[1:], "/"),
		date:            credParts[1],
		region:          credParts[2],
		service:         credParts[3],
		signedHeaders:   signedHeaders,
		signature:       signature,
	}, nil
}

// buildCanonicalRequest constructs the SigV4 canonical request string.
func buildCanonicalRequest(r *http.Request, signedHeadersStr, payloadHash string) string {
	method := r.Method

	// Canonical URI: percent-encode the path, normalise slashes
	rawPath := r.URL.EscapedPath()
	if rawPath == "" {
		rawPath = "/"
	}

	// Canonical query string: sort params by name, then by value
	canonicalQS := canonicalQueryString(r.URL)

	// Canonical headers from signed-headers list
	signedList := strings.Split(signedHeadersStr, ";")
	sort.Strings(signedList)
	var canonicalHeaders strings.Builder
	for _, h := range signedList {
		var val string
		switch h {
		case "host":
			// r.Host takes priority (set explicitly); fall back to URL.Host.
			val = r.Host
			if val == "" {
				val = r.URL.Host
			}
		case "content-length":
			// Go stores content-length in r.ContentLength, not in r.Header.
			if r.ContentLength >= 0 {
				val = strconv.FormatInt(r.ContentLength, 10)
			}
		default:
			vals := r.Header[http.CanonicalHeaderKey(h)]
			val = strings.TrimSpace(strings.Join(vals, ","))
		}
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(val)
		canonicalHeaders.WriteByte('\n')
	}

	return strings.Join([]string{
		method,
		rawPath,
		canonicalQS,
		canonicalHeaders.String(),
		signedHeadersStr,
		payloadHash,
	}, "\n")
}

// canonicalQueryString returns the SigV4-canonical query string for a URL.
func canonicalQueryString(u *url.URL) string {
	query := u.Query()
	if len(query) == 0 {
		return ""
	}
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := query[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// buildStringToSign constructs the SigV4 string-to-sign.
func buildStringToSign(amzDate, credentialScope, canonicalRequest string) string {
	hash := sha256.Sum256([]byte(canonicalRequest))
	return strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hex.EncodeToString(hash[:]),
	}, "\n")
}

// deriveV4SigningKey derives the SigV4 signing key from the secret access key and scope.
func deriveV4SigningKey(secretKey, date, region, service string) []byte {
	kSecret := []byte("AWS4" + secretKey)
	kDate := hmacSHA256(kSecret, []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// hmacSHA256 computes HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
