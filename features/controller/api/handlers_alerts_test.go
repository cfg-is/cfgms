// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newAlertServer creates a minimal test server with an alert store wired.
// store must be non-nil. Uses the existing test registration server infrastructure.
func newAlertServer(t *testing.T, store business.AlertStore) *Server {
	t.Helper()
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetAlertStore(store)
	return server
}

// makeAlertRequest creates an admin-authenticated POST request for alert endpoints.
func makeAlertRequest(t *testing.T, path string, body interface{}) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := makeAdminRequest(t, "POST", path, &buf)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// TestHandleAlertRoundTrip verifies acknowledge then silence against each working
// provider (flatfile + database), asserting state round-trips via GetAlertState.
func TestHandleAlertRoundTrip(t *testing.T) {
	stores := alertStoreProviders(t)
	for name, store := range stores {
		store := store // capture
		t.Run(name, func(t *testing.T) {
			server := newAlertServer(t, store)
			ctx := context.Background()

			alertID := "test-alert-" + name
			tenantID := "" // admin requests have no tenant scope

			// Step 1: acknowledge the alert.
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, makeAlertRequest(t,
				"/api/v1/alerts/"+alertID+"/acknowledge",
				AlertAcknowledgeRequest{Reason: "investigating"},
			))
			assert.Equal(t, http.StatusNoContent, rec.Code, "acknowledge should return 204")

			// Step 2: verify acknowledgement persisted.
			st, err := store.GetAlertState(ctx, tenantID, alertID)
			require.NoError(t, err)
			require.NotNil(t, st, "state should exist after acknowledge")
			assert.True(t, st.Acknowledged, "alert should be acknowledged")
			assert.False(t, st.Silenced, "alert should not be silenced yet")

			// Step 3: silence the alert.
			silenceUntil := time.Now().Add(24 * time.Hour).UTC()
			rec = httptest.NewRecorder()
			server.router.ServeHTTP(rec, makeAlertRequest(t,
				"/api/v1/alerts/"+alertID+"/silence",
				AlertSilenceRequest{Until: silenceUntil},
			))
			assert.Equal(t, http.StatusNoContent, rec.Code, "silence should return 204")

			// Step 4: verify both states persisted.
			st, err = store.GetAlertState(ctx, tenantID, alertID)
			require.NoError(t, err)
			require.NotNil(t, st, "state should exist after silence")
			assert.True(t, st.Acknowledged, "acknowledged state must survive silence")
			assert.True(t, st.Silenced, "alert should now be silenced")
			assert.WithinDuration(t, silenceUntil, st.SilencedUntil, time.Second,
				"silenced_until should round-trip correctly")
		})
	}
}

// TestHandleAlertUnknownID verifies that acknowledging/silencing a previously
// unknown alertID creates a new record and does not panic or return 500.
func TestHandleAlertUnknownID(t *testing.T) {
	stores := alertStoreProviders(t)
	for name, store := range stores {
		store := store // capture
		t.Run(name, func(t *testing.T) {
			server := newAlertServer(t, store)
			ctx := context.Background()

			alertID := "brand-new-alert-" + name
			tenantID := ""

			// Verify the alert state does not exist yet.
			st, err := store.GetAlertState(ctx, tenantID, alertID)
			require.NoError(t, err)
			assert.Nil(t, st, "unknown alertID should return nil state")

			// Acknowledging an unknown alert should create a new record, not 500.
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, makeAlertRequest(t,
				"/api/v1/alerts/"+alertID+"/acknowledge",
				AlertAcknowledgeRequest{},
			))
			assert.Equal(t, http.StatusNoContent, rec.Code, "acknowledge unknown alert must not 500")

			// State must now exist.
			st, err = store.GetAlertState(ctx, tenantID, alertID)
			require.NoError(t, err)
			require.NotNil(t, st, "state should be created by acknowledge")
			assert.True(t, st.Acknowledged)

			// Silencing an unknown alert (a different one) should also create a new record.
			alertID2 := "brand-new-silence-" + name
			silenceUntil := time.Now().Add(time.Hour).UTC()
			rec = httptest.NewRecorder()
			server.router.ServeHTTP(rec, makeAlertRequest(t,
				"/api/v1/alerts/"+alertID2+"/silence",
				AlertSilenceRequest{Until: silenceUntil},
			))
			assert.Equal(t, http.StatusNoContent, rec.Code, "silence unknown alert must not 500")

			st2, err := store.GetAlertState(ctx, tenantID, alertID2)
			require.NoError(t, err)
			require.NotNil(t, st2, "state should be created by silence")
			assert.True(t, st2.Silenced)
		})
	}
}

// TestHandleAlertNoStore verifies that endpoints return 503 when alertStore is nil.
func TestHandleAlertNoStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	// Do NOT wire alertStore — it remains nil.

	for _, path := range []string{
		"/api/v1/alerts/some-id/acknowledge",
		"/api/v1/alerts/some-id/silence",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, makeAlertRequest(t, path, AlertAcknowledgeRequest{}))
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		})
	}
}

// TestHandleAlertMalformedBody verifies that a malformed JSON body is rejected with 400
// on both endpoints, and that no state is written for the alert.
func TestHandleAlertMalformedBody(t *testing.T) {
	for _, path := range []string{
		"/api/v1/alerts/malformed-alert/acknowledge",
		"/api/v1/alerts/malformed-alert/silence",
	} {
		t.Run(path, func(t *testing.T) {
			store := newTestFlatFileAlertStore(t)
			server := newAlertServer(t, store)

			req := makeAdminRequest(t, "POST", path, bytes.NewBufferString(`{"reason": invalid}`))
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code, "malformed JSON must return 400")

			st, err := store.GetAlertState(context.Background(), "", "malformed-alert")
			require.NoError(t, err)
			assert.Nil(t, st, "no state may be written for a rejected request")
		})
	}
}

// TestHandleAcknowledgeAlert_EmptyBody verifies the acknowledge body stays optional:
// an empty body is accepted (204) and the acknowledgement is persisted.
func TestHandleAcknowledgeAlert_EmptyBody(t *testing.T) {
	store := newTestFlatFileAlertStore(t)
	server := newAlertServer(t, store)

	req := makeAdminRequest(t, "POST", "/api/v1/alerts/empty-body-alert/acknowledge", bytes.NewBuffer(nil))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code, "empty body must remain valid for acknowledge")

	st, err := store.GetAlertState(context.Background(), "", "empty-body-alert")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, st.Acknowledged)
}

// TestHandleSilenceAlert_MissingUntil verifies that a missing or zero until field returns 400.
func TestHandleSilenceAlert_MissingUntil(t *testing.T) {
	store := newTestFlatFileAlertStore(t)
	server := newAlertServer(t, store)

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, makeAlertRequest(t,
		"/api/v1/alerts/some-id/silence",
		AlertSilenceRequest{Until: time.Time{}}, // zero time
	))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
