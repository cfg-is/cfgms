// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"strings"
)

// SetGDAPResolver sets a resolver whose Partner Center endpoints (see
// GDAPRelationshipResolver.SetEndpoints) are used for partner-delegated token
// minting. It does not select a partner or customer: those come from the CFGMS
// tenant's stored OAuth2Config on every call.
func (p *OAuth2Provider) SetGDAPResolver(resolver *GDAPRelationshipResolver) {
	p.gdapResolver = resolver
}

// storedTokenUsable reports whether a token read back from the credential store
// may be served for a tenant configured as config. A Partner Center token is never
// a Graph token, and for a delegated tenant only a token minted against the
// configured customer tenant is acceptable (a stale direct token left over from
// before the tenant was marked delegated is not).
func storedTokenUsable(config *OAuth2Config, token *AccessToken) bool {
	if strings.Contains(token.Scope, "api.partnercenter.microsoft.com") {
		return false
	}
	if config.PartnerDelegated {
		return token.TenantID != "" && strings.EqualFold(token.TenantID, config.CustomerTenantID)
	}
	return true
}

// partnerResolver builds the relationship resolver for one CFGMS tenant's
// delegated config. The partner credentials are the config's own client
// credentials — never a lookup of another tenant's stored config — and the
// persisted Partner Center token is scoped to the CFGMS tenant.
func (p *OAuth2Provider) partnerResolver(cfgmsTenantID string, config *OAuth2Config) *GDAPRelationshipResolver {
	r := NewGDAPRelationshipResolver(p.httpClient, config.PartnerTenantID)
	if p.gdapResolver != nil {
		r.SetEndpoints(p.gdapResolver.gdapClient.baseURL, p.gdapResolver.gdapClient.tokenBaseURL)
	}
	r.SetCredentialStore(p.credentialStore)
	r.SetClientCredentials(config.ClientID, config.ClientSecret)
	r.SetTokenKeyID(cfgmsTenantID)
	return r
}

// getPartnerDelegatedToken mints an app-only Graph token against the customer
// M365 tenant named in the CFGMS tenant's own stored config, using the partner's
// client credentials, after validating that the partner's GDAP relationship with
// that customer is active and grants config.GDAPRequiredRoles.
//
// The customer tenant is read only from config, which GetAccessToken loaded with
// CredentialStore.GetConfig(cfgmsTenantID); it is not a parameter here.
func (p *OAuth2Provider) getPartnerDelegatedToken(ctx context.Context, cfgmsTenantID string, config *OAuth2Config) (*AccessToken, error) {
	switch {
	case config.PartnerTenantID == "":
		return nil, NewAuthenticationError(cfgmsTenantID, "DELEGATED_CONFIG_INVALID",
			"Partner-delegated configuration has no partner tenant", nil)
	case config.CustomerTenantID == "":
		return nil, NewAuthenticationError(cfgmsTenantID, "DELEGATED_CONFIG_INVALID",
			"Partner-delegated configuration has no customer tenant", nil)
	case config.ClientID == "" || config.ClientSecret == "":
		return nil, NewAuthenticationError(cfgmsTenantID, "DELEGATED_CONFIG_INVALID",
			"Partner-delegated configuration has no partner client credentials", nil)
	}

	// Validate the relationship before any request reaches the customer tenant.
	if _, err := p.partnerResolver(cfgmsTenantID, config).ValidateGDAPAccess(ctx, config.CustomerTenantID, config.GDAPRequiredRoles); err != nil {
		return nil, NewAuthenticationError(cfgmsTenantID, "GDAP_ACCESS_REFUSED",
			"Partner GDAP relationship does not permit access to the customer tenant", err)
	}

	// The partner app's client-credentials grant against the customer tenant's
	// own token endpoint is the GDAP app-only token flow.
	msp := &MSPOAuth2Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		TenantID:     config.PartnerTenantID,
		AuthorityURL: config.AuthorityURL,
	}
	token, err := p.getClientCredentialsToken(ctx, msp.ToLegacyOAuth2Config(config.CustomerTenantID))
	if err != nil {
		return nil, err
	}

	// The token's tid must be the intended customer tenant. A non-JWT or a token
	// without a tid claim (opaque tokens) is accepted: the claim cannot be read, and
	// the token endpoint was already addressed by the customer tenant ID.
	if tid, tidErr := extractJWTTenantID(token.Token); tidErr == nil && !strings.EqualFold(tid, config.CustomerTenantID) {
		return nil, NewAuthenticationError(cfgmsTenantID, "TENANT_MISMATCH",
			"Delegated token was issued for a different tenant than the configured customer tenant", nil)
	}

	token.TenantID = config.CustomerTenantID
	return token, nil
}
