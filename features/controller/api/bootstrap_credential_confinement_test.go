// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3716: regression tests that the bootstrap admin bundle's confinement holds
// at the mechanism level, not by coincidence (Epic #3711 D4).
//
// These tests cannot live in features/controller/initialization/admin_bundle_test.go
// alongside the marker assertions: features/controller/api imports
// features/controller/initialization (handlers_installer.go), so the reverse import
// needed to exercise extractAdminPrincipal's bootstrap-fallback branch and
// requirePermission's presence gate from the initialization package would be an
// import cycle. They live here instead, next to the mechanisms they exercise.
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// bootstrapFallbackPrincipal returns the exact Principal shape extractAdminPrincipal
// (middleware.go) constructs for a certificate issued by IssueAdminBundle
// (features/controller/initialization/admin_bundle.go): IssueAdminBundle never
// creates a CertBinding for the certificate it issues, so extractAdminPrincipal's
// getAccountByCertSerial lookup always misses and every request authenticated with
// a bootstrap bundle takes the "No binding found: bootstrap fallback" branch — ID is
// the certificate's CommonName, ImplicitAdmin is true, and there is no backing
// account. This holds for the reserved "cfgms-admin" CN used by the system bundle
// issued at first boot, and for any operator name passed to `bootstrap-admin --output`.
func bootstrapFallbackPrincipal(cn string) *Principal {
	return &Principal{
		ID:            cn,
		Name:          "mtls-admin:" + cn,
		Assurance:     session.AssuranceStrong,
		GlobalScope:   true,
		TenantID:      "",
		CertSerial:    "bootstrap-test-serial",
		ImplicitAdmin: true,
	}
}

// TestBootstrapCredential_CannotBeginPresenceCeremony verifies the mechanism the
// confinement claim rests on: handlePresenceBegin (handlers_webauthn.go) can only
// issue an assertion challenge for a principal that resolves to a provisioned
// account holding registered WebAuthn credentials. The bootstrap-fallback
// principal's ID is a certificate CommonName, never a provisioned account username,
// so getAccount(ctx, principal.ID) always misses and the ceremony cannot start — for
// the reserved system-bundle CN and for an arbitrary operator name alike.
func TestBootstrapCredential_CannotBeginPresenceCeremony(t *testing.T) {
	for _, cn := range []string{"cfgms-admin", "alice", "root-operator"} {
		t.Run(cn, func(t *testing.T) {
			server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
			principal := bootstrapFallbackPrincipal(cn)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/presence/begin", nil)
			req = withPrincipal(req, principal)
			rec := httptest.NewRecorder()
			server.handlePresenceBegin(rec, req)

			assert.Equal(t, http.StatusNotFound, rec.Code,
				"a bootstrap-fallback principal must never resolve to an account")
			assert.Equal(t, "ACCOUNT_NOT_FOUND", errCode(t, rec.Body.Bytes()),
				"the ceremony must refuse to start for lack of a bound account, not for lack of credentials")
		})
	}
}

// TestBootstrapCredential_CannotSatisfyUserPresenceGatedPermission asserts the
// confinement through the live presence gate in requirePermission (middleware.go),
// not by checking which permission strings the principal holds. ImplicitAdmin: true
// makes hasPermission succeed for every permission by construction — that is exactly
// what extractAdminPrincipal's bootstrap fallback grants — so a permission-string
// check alone would prove nothing: the bootstrap principal "holds" every permission.
// What actually confines it is that every permission carrying
// RequireUserPresence:true in permissionAssurance demands a fresh X-Presence-Token,
// and TestBootstrapCredential_CannotBeginPresenceCeremony establishes that no such
// token can ever be minted for this principal shape. This test walks every
// currently-registered RequireUserPresence permission — which includes the one
// credential-minting entry, signing-credential:request — and confirms
// requirePermission rejects the bootstrap principal on each one when no token is
// attached, which is the only way a token could ever be attached for this principal.
func TestBootstrapCredential_CannotSatisfyUserPresenceGatedPermission(t *testing.T) {
	server := setupTestServer(t)
	principal := bootstrapFallbackPrincipal("cfgms-admin")

	found := 0
	for permissionID, requirement := range permissionAssurance {
		if !requirement.RequireUserPresence {
			continue
		}
		found++
		permissionID := permissionID
		t.Run(permissionID, func(t *testing.T) {
			parts := strings.SplitN(permissionID, ":", 2)
			require.Len(t, parts, 2, "permission %q must be resource:action", permissionID)

			probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			handler := server.requirePermission(parts[0], parts[1])(probe)

			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req = withPrincipal(req, principal)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusUnauthorized, rec.Code,
				"bootstrap-fallback principal must be blocked by the presence gate on %s despite ImplicitAdmin", permissionID)
			assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`,
				"401 must carry the presence step-up challenge for %s", permissionID)
		})
	}
	require.NotZero(t, found,
		"permissionAssurance must contain at least one RequireUserPresence entry for this test to be meaningful")
}
