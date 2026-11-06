// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package registration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

func repairClient(t *testing.T, handler http.HandlerFunc) *HTTPClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Timeout: 5 * time.Second, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	return c
}

func TestRepairComplete_SendsTheRepairFieldsToTheRefreshEndpoint(t *testing.T) {
	var path string
	var got map[string]string
	c := repairClient(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"status":"approved","client_cert":"CERT","issuer_chain":"CHAIN"}`))
	})
	resp, err := c.RepairComplete(context.Background(), "dev1", RepairCompleteRequest{
		CSRPEM: "csr", RepairID: "r1", NewIdentityKeyPub: "pub", NewIdentityKeyAlg: "ed25519",
		NewIdentityKeyLevel: "file", OldKeyProof: "old", NewKeyProof: "new",
	})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/stewards/dev1/refresh/complete", path)
	assert.Equal(t, "CERT", resp.ClientCert)
	assert.Equal(t, map[string]string{
		"csr_pem": "csr", "repair_id": "r1", "new_identity_key_pub": "pub", "new_identity_key_alg": "ed25519",
		"new_identity_key_level": "file", "old_key_proof": "old", "new_key_proof": "new",
	}, got)
}

func TestRepairComplete_ClientErrorsAreFinalRefusals_ServerErrorsAreRetryable(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusConflict, http.StatusNotFound, http.StatusForbidden, http.StatusBadRequest} {
		c := repairClient(t, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", status) })
		_, err := c.RepairComplete(context.Background(), "dev1", RepairCompleteRequest{RepairID: "r1"})
		var refused *RepairRefusedError
		require.ErrorAs(t, err, &refused, "HTTP %d", status)
		assert.Equal(t, status, refused.Status)
	}
	for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusRequestTimeout, http.StatusAccepted} {
		c := repairClient(t, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "later", status) })
		_, err := c.RepairComplete(context.Background(), "dev1", RepairCompleteRequest{RepairID: "r1"})
		require.Error(t, err, "HTTP %d", status)
		var refused *RepairRefusedError
		assert.NotErrorAs(t, err, &refused, "HTTP %d may be retried with the same keys", status)
	}
}
