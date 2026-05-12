// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package network_activedirectory

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"

	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// AuthenticationManager handles different authentication methods for Active Directory
type AuthenticationManager struct {
	config      *ADModuleConfig
	secretStore secretsinterfaces.SecretStore
	krb5Config  *config.Config
	krb5Client  *client.Client
}

// NewAuthenticationManager creates a new authentication manager
func NewAuthenticationManager(config *ADModuleConfig, secretStore secretsinterfaces.SecretStore) *AuthenticationManager {
	return &AuthenticationManager{
		config:      config,
		secretStore: secretStore,
	}
}

// resolvePassword retrieves the service account password from the secret store.
func (a *AuthenticationManager) resolvePassword(ctx context.Context) (string, error) {
	if a.secretStore == nil {
		return "", fmt.Errorf("ADModuleConfig: no SecretStore configured")
	}
	if a.config.PasswordSecretKey == "" {
		return "", fmt.Errorf("ADModuleConfig.PasswordSecretKey is required for auth_method %q; store the password in pkg/secrets and set password_secret_key", a.config.AuthMethod)
	}
	secret, err := a.secretStore.GetSecret(ctx, a.config.PasswordSecretKey)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve password from secret store (key=%q): %w", a.config.PasswordSecretKey, err)
	}
	return secret.Value, nil
}

// Authenticate authenticates to Active Directory using the configured method
func (a *AuthenticationManager) Authenticate(ctx context.Context, conn *ldap.Conn) error {
	switch a.config.AuthMethod {
	case "simple":
		return a.authenticateSimple(ctx, conn)
	case "kerberos":
		return a.authenticateKerberos(ctx, conn)
	case "ntlm":
		return a.authenticateNTLM(ctx, conn)
	default:
		return fmt.Errorf("unsupported authentication method: %s", a.config.AuthMethod)
	}
}

// authenticateSimple performs simple bind authentication
func (a *AuthenticationManager) authenticateSimple(ctx context.Context, conn *ldap.Conn) error {
	if a.config.Username == "" {
		return fmt.Errorf("username and password required for simple authentication")
	}

	password, err := a.resolvePassword(ctx)
	if err != nil {
		return fmt.Errorf("simple authentication failed: %w", err)
	}

	// Convert username to proper format
	userDN := a.config.Username

	// Handle different username formats
	if !strings.Contains(userDN, "@") && !strings.Contains(userDN, "=") {
		// Plain username - convert to UPN format
		userDN = fmt.Sprintf("%s@%s", userDN, a.config.Domain)
	} else if strings.Contains(userDN, "\\") {
		// DOMAIN\username format - convert to UPN
		parts := strings.Split(userDN, "\\")
		if len(parts) == 2 {
			userDN = fmt.Sprintf("%s@%s", parts[1], a.config.Domain)
		}
	}

	// Perform bind
	if err := conn.Bind(userDN, password); err != nil {
		return fmt.Errorf("simple bind failed for user %s: %w", userDN, err)
	}

	return nil
}

// authenticateKerberos performs Kerberos authentication
func (a *AuthenticationManager) authenticateKerberos(ctx context.Context, conn *ldap.Conn) error {
	if a.config.Username == "" {
		return fmt.Errorf("username and password required for Kerberos authentication")
	}

	password, err := a.resolvePassword(ctx)
	if err != nil {
		return fmt.Errorf("kerberos authentication failed: %w", err)
	}

	// Initialize Kerberos configuration
	if err := a.initializeKerberos(); err != nil {
		return fmt.Errorf("failed to initialize Kerberos: %w", err)
	}

	// Create Kerberos credentials
	creds := credentials.New(a.config.Username, strings.ToUpper(a.config.Domain))
	creds.WithPassword(password)

	// Create Kerberos client
	krb5Client := client.NewWithPassword(creds.UserName(), strings.ToUpper(a.config.Domain), creds.Password(), a.krb5Config)

	// Login to get TGT
	if err := krb5Client.Login(); err != nil {
		return fmt.Errorf("kerberos login failed: %w", err)
	}

	a.krb5Client = krb5Client

	// For LDAP, we can use the TGT to get a service ticket
	// However, go-ldap doesn't directly support Kerberos SASL
	// go-ldap lacks native SASL/GSSAPI support; uses simple bind with the Kerberos-authenticated principal.
	// A future implementation would use SASL GSSAPI for proper Kerberos-based LDAP binding.

	userPrincipal := fmt.Sprintf("%s@%s", a.config.Username, strings.ToUpper(a.config.Domain))
	if err := conn.Bind(userPrincipal, password); err != nil {
		return fmt.Errorf("kerberos-authenticated bind failed: %w", err)
	}

	return nil
}

// authenticateNTLM performs NTLM authentication
func (a *AuthenticationManager) authenticateNTLM(ctx context.Context, conn *ldap.Conn) error {
	// NTLM for LDAP requires SASL/NTLM binding not available in go-ldap; callers must use 'simple' or 'kerberos'.
	return fmt.Errorf("NTLM authentication requires SASL implementation - use 'simple' or 'kerberos' authentication methods")
}

// initializeKerberos sets up Kerberos configuration
func (a *AuthenticationManager) initializeKerberos() error {
	if a.krb5Config != nil {
		return nil // Already initialized
	}

	// Create basic Kerberos configuration
	// In a production environment, this would read from /etc/krb5.conf or Windows registry
	realm := strings.ToUpper(a.config.Domain)

	configText := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    %s = {
        kdc = %s
        admin_server = %s
        default_domain = %s
    }

[domain_realm]
    .%s = %s
    %s = %s`,
		realm,
		realm, a.config.DomainController, a.config.DomainController, strings.ToLower(a.config.Domain),
		strings.ToLower(a.config.Domain), realm,
		strings.ToLower(a.config.Domain), realm)

	cfg, err := config.NewFromString(configText)
	if err != nil {
		return fmt.Errorf("failed to create Kerberos configuration: %w", err)
	}

	a.krb5Config = cfg
	return nil
}

// RefreshCredentials refreshes authentication credentials (for long-running connections)
func (a *AuthenticationManager) RefreshCredentials(ctx context.Context, conn *ldap.Conn) error {
	switch a.config.AuthMethod {
	case "kerberos":
		if a.krb5Client != nil {
			// For gokrb5 v8, we need to re-authenticate rather than renew
			// In a production implementation, you'd check ticket expiration first
			return a.authenticateKerberos(ctx, conn)
		}
		return nil

	case "simple", "ntlm":
		// Simple bind and NTLM don't typically need refresh
		return nil

	default:
		return fmt.Errorf("credential refresh not supported for auth method: %s", a.config.AuthMethod)
	}
}

// Close cleans up authentication resources
func (a *AuthenticationManager) Close() error {
	if a.krb5Client != nil {
		// In gokrb5, there's no explicit close method
		// The client will be garbage collected
		a.krb5Client = nil
	}

	a.krb5Config = nil
	return nil
}

// GetAuthenticationStatus returns the current authentication status
func (a *AuthenticationManager) GetAuthenticationStatus() map[string]interface{} {
	status := map[string]interface{}{
		"auth_method": a.config.AuthMethod,
		"username":    a.config.Username,
		"domain":      a.config.Domain,
	}

	switch a.config.AuthMethod {
	case "kerberos":
		if a.krb5Client != nil {
			status["kerberos_initialized"] = true
			// In a production implementation, you might check ticket expiration
			status["ticket_status"] = "active"
		} else {
			status["kerberos_initialized"] = false
			status["ticket_status"] = "none"
		}

	case "simple":
		status["bind_type"] = "simple"

	case "ntlm":
		status["ntlm_status"] = "not_implemented"
	}

	return status
}
