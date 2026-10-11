// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// errNotSupportedInModule is returned by the delegated and refresh methods of
// HandshakeTokenProvider.
var errNotSupportedInModule = errors.New("not supported in a workflow module")

// EncodeHandshakeToken serializes the controller-issued credential carried in
// WorkflowHandshakeRequest.auth_token. Only access_token, token_type,
// expires_at, scope and tenant_id are copied: never a refresh token, a client
// ID or a client secret. tenant_id is the Microsoft 365 tenant the token was
// issued for, which the modules check against their configured tenant; the
// CFGMS tenant travels separately as the handshake tenant_id.
func EncodeHandshakeToken(token *AccessToken) (string, error) {
	if token == nil || token.Token == "" {
		return "", errors.New("no access token to encode")
	}
	payload := AccessToken{
		Token:     token.Token,
		TokenType: token.TokenType,
		ExpiresAt: token.ExpiresAt,
		Scope:     token.Scope,
		TenantID:  token.TenantID,
	}
	// #nosec G117 -- deliberately serializes only the short-lived Graph access
	// token for the controller->module handshake; no refresh token or client
	// secret is copied into payload.
	b, err := json.Marshal(&payload)
	if err != nil {
		return "", fmt.Errorf("encode handshake token: %w", err)
	}
	return string(b), nil
}

// HandshakeTokenProvider is the Provider a workflow module uses. It holds the
// one access token the controller delivered in the module handshake and never
// reaches a secret store or token endpoint.
type HandshakeTokenProvider struct {
	httpClient *http.Client

	// token and tenantID are set by Bind during the handshake, which the
	// adapter completes before it serves any Get/Set/Test.
	mu       sync.RWMutex
	token    *AccessToken
	tenantID string
}

// NewHandshakeTokenProvider returns a provider with no session bound.
func NewHandshakeTokenProvider() *HandshakeTokenProvider {
	return &HandshakeTokenProvider{httpClient: &http.Client{Timeout: 30 * time.Second}}
}

// Bind records the session tenant and the delivered credential. An empty
// authToken binds the tenant with no credential, so GetAccessToken fails closed.
func (p *HandshakeTokenProvider) Bind(tenantID, authToken string) error {
	// Parse before touching the bound state, so a malformed repeat handshake
	// cannot drop a credential that was already delivered.
	var tok *AccessToken
	if authToken != "" {
		var parsed AccessToken
		if err := json.Unmarshal([]byte(authToken), &parsed); err != nil {
			return errors.New("handshake credential is malformed")
		}
		if parsed.Token == "" {
			return errors.New("handshake credential carries no access token")
		}
		tok = &parsed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tenantID = tenantID
	p.token = tok
	return nil
}

// GetAccessToken returns the delivered token only for the bound tenant while it
// has not expired.
func (p *HandshakeTokenProvider) GetAccessToken(_ context.Context, tenantID string) (*AccessToken, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.token == nil {
		return nil, NewAuthenticationError(tenantID, "NO_CREDENTIAL", "No M365 credential was delivered to this module session", nil)
	}
	if tenantID != p.tenantID {
		return nil, NewAuthenticationError(tenantID, "TENANT_MISMATCH", "No M365 credential was delivered for this tenant", nil)
	}
	if p.token.IsExpired() {
		return nil, NewAuthenticationError(tenantID, "CREDENTIAL_EXPIRED", "The M365 credential delivered to this module session expired", ErrTokenExpired)
	}
	tok := *p.token
	return &tok, nil
}

// GetDelegatedAccessToken is not supported in a workflow module.
func (p *HandshakeTokenProvider) GetDelegatedAccessToken(_ context.Context, tenantID string, _ *UserContext) (*AccessToken, error) {
	return nil, NewAuthenticationError(tenantID, "NOT_SUPPORTED", "delegated tokens are "+errNotSupportedInModule.Error(), errNotSupportedInModule)
}

// RefreshToken is not supported in a workflow module.
func (p *HandshakeTokenProvider) RefreshToken(_ context.Context, _ string) (*AccessToken, error) {
	return nil, fmt.Errorf("token refresh is %w", errNotSupportedInModule)
}

// RefreshDelegatedToken is not supported in a workflow module.
func (p *HandshakeTokenProvider) RefreshDelegatedToken(_ context.Context, _ string, _ *UserContext) (*AccessToken, error) {
	return nil, fmt.Errorf("delegated token refresh is %w", errNotSupportedInModule)
}

// IsTokenValid checks expiry.
func (p *HandshakeTokenProvider) IsTokenValid(token *AccessToken) bool {
	return token != nil && !token.IsExpired()
}

// ValidatePermissions applies the same check as OAuth2Provider.ValidatePermissions.
func (p *HandshakeTokenProvider) ValidatePermissions(ctx context.Context, token *AccessToken, requiredScopes []string) error {
	return validateTokenPermissions(ctx, p.httpClient, token, requiredScopes)
}

var _ Provider = (*HandshakeTokenProvider)(nil)
