// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Delivery-path wiring for RevocationVerifier (Issue #4400). revocation.go's
// FetchAndVerify/RunPeriodicRefresh have existed since Issue #3699 but had no
// production caller — this file adds the piece that was missing: building the URL a
// steward fetches its manifest from. The caller (features/steward/client) still
// builds the mTLS *http.Client and starts the refresh loop; this package continues to
// hold no network client of its own.
package operatorroster

import (
	"fmt"
	"net/url"
	"strings"
)

// ManifestPath is the controller endpoint a steward fetches its per-steward-filtered,
// signed revocation manifest from (Issue #4400) — mirrors the route registered by
// features/controller/api/server.go for handleGetStewardRevocationManifest.
// Steward-authenticated by the caller's own mTLS certificate resolved to a registered
// device, not by certificate:list — see that handler's doc comment for why this is a
// separate endpoint from the fleet-wide, admin-only
// GET /api/v1/certificates/revocation-manifest.
const ManifestPath = "/api/v1/public/steward-revocation-manifest"

// BuildManifestURL builds the full URL FetchAndVerify/RunPeriodicRefresh fetch from,
// given the steward's configured controller HTTPS REST base — the same
// ControllerHTTPSBaseURL used for the self-fetch upgrade download
// (features/steward/client/client_transport_upgrade.go). Refuses an empty, unparsable,
// or non-https base rather than silently degrading a security-sensitive fetch to
// plaintext or an unconfigured destination.
func BuildManifestURL(controllerHTTPSBaseURL string) (string, error) {
	if controllerHTTPSBaseURL == "" {
		return "", fmt.Errorf("controller HTTPS base URL is not configured")
	}
	base, err := url.Parse(controllerHTTPSBaseURL)
	if err != nil {
		return "", fmt.Errorf("parse controller HTTPS base URL: %w", err)
	}
	if base.Scheme != "https" {
		return "", fmt.Errorf("controller HTTPS base URL must use https, got %q", base.Scheme)
	}
	resolved := *base
	resolved.Path = strings.TrimSuffix(base.Path, "/") + ManifestPath
	resolved.RawQuery = ""
	resolved.Fragment = ""
	return resolved.String(), nil
}
