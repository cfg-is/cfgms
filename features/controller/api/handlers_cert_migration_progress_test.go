// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
)

func migrationProgressRequest(principal *Principal, scope ctxkeys.TenantScope) *http.Request {
	ctx := context.WithValue(context.Background(), principalContextKey, principal)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scope)
	return httptest.NewRequest("GET", "/api/v1/certificates/signing/migration", nil).WithContext(ctx)
}

type migrationProgressBody struct {
	Data SigningMigrationProgressResponse `json:"data"`
}

func newMigrationProgressFixture(t *testing.T) (*electFixture, *service.StewardSigningMigrationService) {
	t.Helper()
	f := newElectFixture(t)
	acks, err := cert.NewFileSigningTrustAckStore(t.TempDir())
	require.NoError(t, err)
	svc := service.NewStewardSigningMigrationService(f.nodes[0], acks, logging.NewNoopLogger())
	svc.SetControllerService(f.server.controllerService)
	f.server.SetStewardSigningMigrationService(svc)
	t.Cleanup(svc.Stop)
	return f, svc
}

func TestHandleGetSigningMigrationProgress_DeniesUnderprivilegedCallers(t *testing.T) {
	f, _ := newMigrationProgressFixture(t)
	_, _, err := f.nodes[0].ElectSharedSigningSerial(context.Background(), f.serials[0])
	require.NoError(t, err)

	cases := map[string]struct {
		principal *Principal
		scope     ctxkeys.TenantScope
	}{
		"non_strong":     {&Principal{ID: "weak", Assurance: session.AssuranceMachine, CertSerial: "s"}, ctxkeys.NewRootScope()},
		"tenant_scoped":  {&Principal{ID: "scoped", Assurance: session.AssuranceStrong, TenantID: "client-1", CertSerial: "s"}, ctxkeys.NewTenantScope("client-1")},
		"no_cert_serial": {&Principal{ID: "noserial", Assurance: session.AssuranceStrong}, ctxkeys.NewRootScope()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			f.server.handleGetSigningMigrationProgress(rec, migrationProgressRequest(tc.principal, tc.scope))
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.NotContains(t, rec.Body.String(), f.serials[0])
		})
	}
}

func TestHandleGetSigningMigrationProgress_NotWired(t *testing.T) {
	f := newElectFixture(t)
	rec := httptest.NewRecorder()
	f.server.handleGetSigningMigrationProgress(rec, migrationProgressRequest(strongRootPrincipal(), ctxkeys.NewRootScope()))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleGetSigningMigrationProgress_ConflictBeforeElection(t *testing.T) {
	f, _ := newMigrationProgressFixture(t)
	rec := httptest.NewRecorder()
	f.server.handleGetSigningMigrationProgress(rec, migrationProgressRequest(strongRootPrincipal(), ctxkeys.NewRootScope()))
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
}

func TestHandleGetSigningMigrationProgress_ReportsCountsAndBoundedList(t *testing.T) {
	f, _ := newMigrationProgressFixture(t)
	ctx := context.Background()
	_, _, err := f.nodes[0].ElectSharedSigningSerial(ctx, f.serials[0])
	require.NoError(t, err)

	// A steward in another tenant is counted too: the report is fleet-wide.
	const total = service.MaxMigrationUnconfirmedListed + 20
	for i := 0; i < total; i++ {
		tenantID := "tenant-a"
		if i%2 == 1 {
			tenantID = "tenant-b"
		}
		require.NoError(t, f.server.controllerService.RegisterSteward(fmt.Sprintf("steward-%03d", i), tenantID, "addr", "online"))
	}

	rec := httptest.NewRecorder()
	f.server.handleGetSigningMigrationProgress(rec, migrationProgressRequest(strongRootPrincipal(), ctxkeys.NewRootScope()))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body migrationProgressBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, f.serials[0], body.Data.SharedSerial)
	assert.Equal(t, total, body.Data.Stewards)
	assert.Equal(t, 0, body.Data.Confirmed)
	assert.Len(t, body.Data.Unconfirmed, service.MaxMigrationUnconfirmedListed, "the unconfirmed list is bounded")
	assert.True(t, body.Data.UnconfirmedTruncated)
	assert.Equal(t, "steward-000", body.Data.Unconfirmed[0])
}

func TestHandleGetSigningMigrationProgress_CountsConfirmations(t *testing.T) {
	f := newElectFixture(t)
	acks, err := cert.NewFileSigningTrustAckStore(t.TempDir())
	require.NoError(t, err)
	svc := service.NewStewardSigningMigrationService(f.nodes[0], acks, logging.NewNoopLogger())
	svc.SetControllerService(f.server.controllerService)
	f.server.SetStewardSigningMigrationService(svc)
	ctx := context.Background()
	_, _, err = f.nodes[0].ElectSharedSigningSerial(ctx, f.serials[0])
	require.NoError(t, err)

	for _, id := range []string{"s-a", "s-b", "s-c"} {
		require.NoError(t, f.server.controllerService.RegisterSteward(id, "tenant-a", "addr", "online"))
	}
	require.NoError(t, acks.RecordAck(ctx, "s-b", f.serials[0]))
	require.NoError(t, acks.RecordAck(ctx, "s-c", "some-previous-serial"), "a confirmation of another serial does not count")

	rec := httptest.NewRecorder()
	f.server.handleGetSigningMigrationProgress(rec, migrationProgressRequest(strongRootPrincipal(), ctxkeys.NewRootScope()))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body migrationProgressBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, 3, body.Data.Stewards)
	assert.Equal(t, 1, body.Data.Confirmed)
	assert.Equal(t, []string{"s-a", "s-c"}, body.Data.Unconfirmed)
	assert.False(t, body.Data.UnconfirmedTruncated)
}
