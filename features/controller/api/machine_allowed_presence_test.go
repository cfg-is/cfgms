// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// machineAllowedCase is one installer/upgrade route behind requirePermission. gated
// routes need a passkey tap from a human principal; the rest are presence-exempt.
type machineAllowedCase struct {
	method, template, path string
	resource, action       string
	permission             string
	gated                  bool
}

var machineAllowedCases = []machineAllowedCase{
	{http.MethodPut, "/api/v1/installer/artifacts/{platform}/{arch}", "/api/v1/installer/artifacts/linux/amd64", "installer", "upload", "installer:upload", true},
	{http.MethodDelete, "/api/v1/installer/artifacts/{platform}/{arch}", "/api/v1/installer/artifacts/linux/amd64", "installer", "delete", "installer:delete", true},
	{http.MethodPost, "/api/v1/installer/steward-binaries/{version}/{platform}/{arch}", "/api/v1/installer/steward-binaries/v1/linux/amd64", "installer", "publish:steward", "installer:publish:steward", true},
	{http.MethodPost, "/api/v1/rollout", "/api/v1/rollout", "installer", "dispatch:steward", "installer:dispatch:steward", true},
	{http.MethodPost, "/api/v1/stewards/upgrade", "/api/v1/stewards/upgrade", "installer", "dispatch:steward", "installer:dispatch:steward", true},
	{http.MethodPost, "/api/v1/rollout/{rollout_id}/halt", "/api/v1/rollout/r1/halt", "installer", "dispatch:steward", "installer:dispatch:steward", false},
	{http.MethodPost, "/api/v1/stewards/upgrade/{upgrade_id}/rollback", "/api/v1/stewards/upgrade/u1/rollback", "installer", "dispatch:steward", "installer:dispatch:steward", false},
}

func machineAllowedRequest(c machineAllowedCase, p *Principal) *http.Request {
	req := httptest.NewRequest(c.method, c.path, strings.NewReader(`{"x":1}`))
	return withPrincipal(req, p)
}

func machineAllowedPrincipal(id string, level session.AssuranceLevel, perms ...string) *Principal {
	return &Principal{ID: id, Assurance: level, Permissions: perms, TenantID: "test-tenant"}
}

func TestMachineAllowed_HumanStrongNeedsTapOnGatedRoutes(t *testing.T) {
	server := setupTestServer(t)
	for _, c := range machineAllowedCases {
		t.Run(c.method+" "+c.template, func(t *testing.T) {
			p := machineAllowedPrincipal("human", session.AssuranceStrong, c.permission)
			rec := serveOnRoute(server, c.method, c.template, c.resource, c.action, presenceOK, machineAllowedRequest(c, p))
			if !c.gated {
				assert.Equal(t, http.StatusOK, rec.Code, "stop action must reach the handler without a tap")
				return
			}
			assertPresenceChallenge(t, rec, c.permission)

			req := machineAllowedRequest(c, p)
			req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(t, server, "human", req, c.permission))
			rec = serveOnRoute(server, c.method, c.template, c.resource, c.action, presenceOK, req)
			assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

func TestMachineAllowed_HumanBasicGetsMinChallenge(t *testing.T) {
	server := setupTestServer(t)
	for _, c := range machineAllowedCases {
		t.Run(c.method+" "+c.template, func(t *testing.T) {
			p := machineAllowedPrincipal("basic", session.AssuranceBasic, c.permission)
			rec := serveOnRoute(server, c.method, c.template, c.resource, c.action, presenceOK, machineAllowedRequest(c, p))
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			challenge := rec.Header().Get("WWW-Authenticate")
			assert.Contains(t, challenge, "CFGMS-StepUp")
			assert.NotContains(t, challenge, "presence=")
		})
	}
}

func TestMachineAllowed_APIKeyReachesHandlerWithoutToken(t *testing.T) {
	server := setupTestServer(t)
	for _, c := range machineAllowedCases {
		t.Run(c.method+" "+c.template, func(t *testing.T) {
			p := machineAllowedPrincipal("key", session.AssuranceMachine, c.permission)
			rec := serveOnRoute(server, c.method, c.template, c.resource, c.action, presenceOK, machineAllowedRequest(c, p))
			assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

func TestMachineAllowed_APIKeyWithoutPermissionForbidden(t *testing.T) {
	server := setupTestServer(t)
	for _, c := range machineAllowedCases {
		t.Run(c.method+" "+c.template, func(t *testing.T) {
			p := machineAllowedPrincipal("key", session.AssuranceMachine, "installer:read")
			rec := serveOnRoute(server, c.method, c.template, c.resource, c.action, presenceOK, machineAllowedRequest(c, p))
			assert.Equal(t, http.StatusForbidden, rec.Code)
		})
	}
}

// AllowMachine is a code-only opt-in: a permission without it still refuses API keys.
func TestMachineAllowed_OnlyTheInstallerPermissionsAndConfigPush(t *testing.T) {
	want := map[string]bool{
		"installer:upload": true, "installer:delete": true,
		"installer:publish:steward": true, "installer:dispatch:steward": true,
		"config:push": true, // Issue #5419: scoped API keys keep pushing config
	}
	for perm, req := range permissionAssurance {
		assert.Equal(t, want[perm], req.AllowMachine, "AllowMachine on %q", perm)
	}
}

// A tenant override that raises Min or demands presence cannot change AllowMachine.
func TestMachineAllowed_OverrideCannotClearIt(t *testing.T) {
	strong := int(session.AssuranceStrong)
	server := serverWithOverride(t, business.AssurancePolicyOverride{
		PermissionID: "installer:dispatch:steward", MinOverride: &strong, RequireUserPresence: true,
	})
	req, found, err := server.resolveAssuranceRequirement(t.Context(), "test-tenant", "installer:dispatch:steward")
	require.NoError(t, err)
	require.True(t, found)
	assert.True(t, req.AllowMachine)
}
