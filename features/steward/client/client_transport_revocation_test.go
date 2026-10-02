// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #4400: end-to-end verification that setupCommandHandler actually wires the
// revocation-manifest fetch, not just that FetchAndVerify works in isolation (which
// revocation_test.go / fetch_test.go already cover). A fake controller stands in for
// GET /api/v1/public/steward-revocation-manifest, and the assertion is on the REAL
// command handler's RevocationVerifier, reached only through the production
// setupCommandHandler code path — the same path Connect calls during normal startup.
package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/steward/operatorroster"
)

// wireManifest and wireSignedManifest mirror the controller's steward-facing wire
// shape (features/controller/api.RevocationManifest/SignedRevocationManifest) just
// enough to serve a minimal, valid body — module_trust.mode "controller" in this test
// skips signature chain verification, so Signature/SignerCertificatePEM are omitted.
type wireManifest struct {
	Kind           string    `json:"kind"`
	Version        int64     `json:"version"`
	IssuedAt       time.Time `json:"issued_at"`
	RevokedSerials []string  `json:"revoked_serials"`
}

type wireSignedManifest struct {
	Manifest wireManifest `json:"manifest"`
}

// TestSetupCommandHandler_RevocationManifestFetchedOnStartup is the REQUIRED end-to-end
// test (Issue #4400 AC): after setupCommandHandler runs — the real function Connect
// calls during normal steward startup — the resulting handler's RevocationVerifier has
// already fetched and verified a manifest from the fake controller, entirely through
// production wiring (BuildManifestURL, buildHTTPClientForUpgrade,
// RunPeriodicRefresh), with no test code calling FetchAndVerify directly.
func TestSetupCommandHandler_RevocationManifestFetchedOnStartup(t *testing.T) {
	const revokedSerial = "999888777"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != operatorroster.ManifestPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(wireSignedManifest{
			Manifest: wireManifest{
				Kind:           "operator-cert-revocation",
				Version:        1,
				IssuedAt:       time.Now().UTC(),
				RevokedSerials: []string{revokedSerial},
			},
		}))
	}))
	defer srv.Close()

	c, err := NewTransportClient(&TransportConfig{
		ControllerURL:          "localhost:4433",
		ControllerHTTPSBaseURL: srv.URL,
		ModuleTrustMode:        stewardtypes.ModuleTrustModeController,
		Logger:                 newTestLogger(t),
	})
	require.NoError(t, err)
	c.upgradeHTTPClient = srv.Client() // trust the test server's self-signed cert

	handler, err := c.setupCommandHandler(t.Context(), "steward-revocation-e2e")
	require.NoError(t, err)
	require.NotNil(t, handler.RevocationVerifier())

	require.Eventually(t, func() bool {
		return handler.RevocationVerifier().IsRevoked(revokedSerial)
	}, 2*time.Second, 10*time.Millisecond,
		"the handler's RevocationVerifier must hold a fetched manifest after normal startup wiring")

	assert.False(t, handler.RevocationVerifier().IsRevoked("not-in-the-manifest"),
		"a serial absent from the fetched manifest must not be reported as revoked")
}

// TestSetupCommandHandler_RevocationManifestFetch_NoBaseURL_DegradesSafe verifies that
// an unconfigured ControllerHTTPSBaseURL disables the fetch (logs and continues)
// rather than failing setupCommandHandler — execution availability must not depend on
// this fetch succeeding.
func TestSetupCommandHandler_RevocationManifestFetch_NoBaseURL_DegradesSafe(t *testing.T) {
	c, err := NewTransportClient(&TransportConfig{
		ControllerURL: "localhost:4433",
		Logger:        newTestLogger(t),
	})
	require.NoError(t, err)

	handler, err := c.setupCommandHandler(t.Context(), "steward-revocation-no-url")
	require.NoError(t, err)
	require.NotNil(t, handler.RevocationVerifier())
	assert.False(t, handler.RevocationVerifier().IsRevoked("anything"),
		"with no manifest ever fetched, IsRevoked must answer false, not error or panic")
}
