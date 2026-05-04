// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package saas

import "net/http"

// GetTenantKey exposes the unexported getTenantKey method for external test packages.
// Tests use this to construct the correct credential-store key during setup, then call
// public methods that read via the same key.
var GetTenantKey = (*MultiTenantManager).getTenantKey

// SetProviderBaseURL sets the baseURL field of a MicrosoftMultiTenantProvider.
// Tests use this to redirect HTTP calls to an httptest.Server instead of the real Graph API.
var SetProviderBaseURL = func(p *MicrosoftMultiTenantProvider, url string) {
	p.baseURL = url
}

// NewMicrosoftProviderWithConsentStore creates a MicrosoftMultiTenantProvider with a
// caller-supplied ConsentStore. Tests pre-seed the ConsentStore via the public StoreConsent
// method, then pass it here to avoid the 3-level internal-field chain
// (provider.multiTenantManager.consentStore).
var NewMicrosoftProviderWithConsentStore = func(credStore CredentialStore, httpClient *http.Client, cs ConsentStore) *MicrosoftMultiTenantProvider {
	p := NewMicrosoftMultiTenantProvider(credStore, httpClient)
	p.multiTenantManager.consentStore = cs
	return p
}
