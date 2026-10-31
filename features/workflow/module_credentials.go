// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/moduleset"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// cfgmsPublisher is the publisher identity of the CFGMS-published M365
// workflow modules.
const cfgmsPublisher = "cfgms"

// isCredentialedModule reports whether the bundle's manifest identifies a
// CFGMS-published M365 workflow module: its manifest name is in the
// moduleset set and its publisher is cfgmsPublisher.
func isCredentialedModule(b *bundle.Bundle) bool {
	if b == nil || b.Manifest == nil || b.Manifest.Publisher != cfgmsPublisher {
		return false
	}
	return moduleset.Contains(b.Manifest.Name)
}

// verifyCFGMSSignature checks, at issue time, that b carries at least one
// signature from publisher cfgms that verifies against id. It is called only
// when id is a usable key; a build with the placeholder key skips it (see
// WorkflowModuleFactory.warnUnboundCredentials). Errors name the module and the
// tenant only.
func verifyCFGMSSignature(b *bundle.Bundle, id trust.PublisherIdentity, moduleName, tenantID string) error {
	store := trust.NewInMemoryTrustStore()
	if err := store.AddPublisher(id); err != nil {
		return fmt.Errorf("workflow: module %q cannot be issued an M365 credential for tenant %q: CFGMS publisher identity unusable", moduleName, tenantID)
	}
	for _, sig := range b.Signatures {
		if sig.Publisher != cfgmsPublisher {
			continue
		}
		if trust.VerifyBundleSignature(b, sig, store) == nil {
			return nil
		}
	}
	return fmt.Errorf("workflow: module %q cannot be issued an M365 credential for tenant %q: the bundle carries no valid CFGMS publisher signature", moduleName, tenantID)
}

// M365CredentialIssuer mints the Graph access token delivered to an M365
// workflow module in its handshake. The tenant's connection is read from the
// controller's own secret store on every issue; the client secret never leaves
// this process and only the short-lived token crosses the module contract.
type M365CredentialIssuer struct {
	provider *auth.OAuth2Provider
}

// NewM365CredentialIssuer returns an issuer over store, or nil when the engine
// has no secret store (every credentialed module is then refused).
func NewM365CredentialIssuer(store secretsif.SecretStore) *M365CredentialIssuer {
	if store == nil {
		return nil
	}
	// A nil default config: a tenant with no connection on file must fail, never
	// borrow a shared app registration.
	return &M365CredentialIssuer{
		provider: auth.NewOAuth2Provider(auth.NewSecretStoreCredentialStore(store), nil, logging.NewNoopLogger()),
	}
}

// Issue mints a token for cfgmsTenantID and returns the auth_token handshake
// payload. Errors name the module and the CFGMS tenant and never carry the
// client secret or a token.
func (i *M365CredentialIssuer) Issue(ctx context.Context, moduleName, cfgmsTenantID string) (string, error) {
	token, err := i.provider.MintAccessToken(ctx, cfgmsTenantID)
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return "", fmt.Errorf("workflow: module %q: no M365 connection on file for tenant %q: run `cfg tenant m365 set` or `cfg tenant m365 gdap-link` to connect it",
				moduleName, cfgmsTenantID)
		}
		return "", fmt.Errorf("workflow: module %q: cannot issue an M365 credential for tenant %q: %w", moduleName, cfgmsTenantID, err)
	}
	payload, err := auth.EncodeHandshakeToken(token)
	if err != nil {
		return "", fmt.Errorf("workflow: module %q: cannot issue an M365 credential for tenant %q: %w", moduleName, cfgmsTenantID, err)
	}
	return payload, nil
}

// SetHTTPClient replaces the HTTP client used to reach the token endpoint
// (tests point it at an httptest server).
func (i *M365CredentialIssuer) SetHTTPClient(c *http.Client) {
	i.provider.SetHTTPClient(c)
}
