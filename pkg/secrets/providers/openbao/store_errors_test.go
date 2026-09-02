// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package openbao — unit tests for GetSecret's absence classification. These run
// the real OpenBao API client against a local HTTP server that answers with the
// status codes a real OpenBao returns, so no running OpenBao instance is needed.
package openbao

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// kvServer starts an HTTP server that answers every KV v2 read with status and
// body, and returns a store pointed at it.
func kvServer(t *testing.T, status int, body string) *OpenBaoSecretStore {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	store, err := newOpenBaoSecretStore(&OpenBaoConfig{
		Address:   srv.URL,
		Token:     "test-token",
		MountPath: "secret",
	})
	require.NoError(t, err)
	return store
}

// TestGetSecret_AbsentSecretWrapsErrSecretNotFound pins the sentinel callers
// branch on. pkg/cert's cluster-CA load treats a not-found as an unclaimed key
// path it may bootstrap a new fleet CA into, so the sentinel must survive the
// provider boundary rather than being expressed only in the message text.
func TestGetSecret_AbsentSecretWrapsErrSecretNotFound(t *testing.T) {
	store := kvServer(t, http.StatusNotFound, `{"errors":[]}`)

	_, err := store.GetSecret(context.Background(), "root/cluster-ca")
	require.Error(t, err)
	assert.ErrorIs(t, err, interfaces.ErrSecretNotFound)
}

// TestGetSecret_ReadFailureDoesNotWrapErrSecretNotFound is the REQUIRED security
// test for the re-rooting finding. A read denied by policy (a token with
// create/update but not read on the CA key path), an expired token, or a KV
// mount misconfiguration all leave the secret published — reporting any of them
// as absence would let a controller boot publish a new fleet root over the real
// CA and break the chain of every steward certificate already issued.
func TestGetSecret_ReadFailureDoesNotWrapErrSecretNotFound(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"permission denied", http.StatusForbidden, `{"errors":["permission denied"]}`},
		{"token expired", http.StatusForbidden, `{"errors":["permission denied"]}`},
		{"mount misconfigured", http.StatusBadRequest, `{"errors":["no handler for route \"secret/data/root/cluster-ca\""]}`},
		{"backend unavailable", http.StatusServiceUnavailable, `{"errors":["service is unavailable"]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := kvServer(t, tt.status, tt.body)

			_, err := store.GetSecret(context.Background(), "root/cluster-ca")
			require.Error(t, err)
			assert.NotErrorIs(t, err, interfaces.ErrSecretNotFound,
				"a failed read must not be classified as an absent secret")
		})
	}
}
