//go:build cfgms_test_endpoints

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestHandleApproveRefresh_AuditFoundByDeviceQuery verifies that an approval recorded
// under the operator principal is still returned by the device-scoped audit query the
// fleet suite uses (GET /api/v1/test/audit/count?action=...&device_id=...).
func TestHandleApproveRefresh_AuditFoundByDeviceQuery(t *testing.T) {
	t.Setenv("CFGMS_ENABLE_TEST_ENDPOINTS", "true")
	pub, _ := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-approve-query",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})
	pendingID := "refresh-approve-query"
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID,
		CSRPEM:    testValidCSRPEM,
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	req := makeAdminRequest(t, http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/approve", nil)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "approve must succeed: %s", rec.Body.String())

	countReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/test/audit/count?action=refresh_admin_approved&device_id="+testDeviceID, nil)
	countRec := httptest.NewRecorder()
	f.server.handleTestAuditCount(countRec, countReq)
	require.Equal(t, http.StatusOK, countRec.Code, countRec.Body.String())
	var out testAuditCountResponse
	require.NoError(t, json.Unmarshal(countRec.Body.Bytes(), &out))
	assert.Equal(t, 1, out.Count, "device-scoped query must return exactly one approval entry")

	entry := f.findAuditAction(t, "refresh_admin_approved")
	require.NotNil(t, entry)
	assert.Equal(t, req.TLS.PeerCertificates[0].Subject.CommonName, entry.UserID)
	assert.Equal(t, testDeviceID, entry.ResourceID)
}
