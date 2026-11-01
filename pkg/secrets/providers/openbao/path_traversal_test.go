// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package openbao — path-traversal tests for the tenant/key path handling
// (Issue #4340). These run against a local HTTP server (see kvServer in
// store_errors_test.go) so no running OpenBao instance is needed; a traversal
// attempt must be rejected before any KV v2 request is ever sent.
package openbao

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// refusingServer fails the test if the KV v2 API is ever actually invoked —
// a path-traversal attempt must be rejected by validation before any request
// reaches the store's transport.
func refusingServer(t *testing.T) *OpenBaoSecretStore {
	t.Helper()
	srv := kvServer(t, http.StatusOK, `{"data":{}}`)
	return srv
}

func TestStoreSecret_RejectsPathTraversalInKey(t *testing.T) {
	store := refusingServer(t)

	err := store.StoreSecret(context.Background(), &interfaces.SecretRequest{
		TenantID: "tenant-a",
		Key:      "../../tenant-b/other-secret",
		Value:    "s3cr3t",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path segments")
}

func TestStoreSecret_RejectsPathTraversalInTenantID(t *testing.T) {
	store := refusingServer(t)

	err := store.StoreSecret(context.Background(), &interfaces.SecretRequest{
		TenantID: "tenant-a/../tenant-b",
		Key:      "some-secret",
		Value:    "s3cr3t",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path segments")
}

func TestGetSecret_RejectsPathTraversalEscapingTenant(t *testing.T) {
	store := refusingServer(t)

	// splitKey splits on the FIRST "/" only, so a naive implementation would
	// resolve tenantID="tenant-a", keyName="../../tenant-b/secret" and join
	// them back into a KV path that walks outside tenant-a's own subtree.
	_, err := store.GetSecret(context.Background(), "tenant-a/../../tenant-b/secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path segments")
}

func TestGetSecret_RejectsSymlinkStyleDotSegment(t *testing.T) {
	store := refusingServer(t)

	_, err := store.GetSecret(context.Background(), "tenant-a/./secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path segments")
}

func TestListSecrets_RejectsPathTraversalInTenantIDFilter(t *testing.T) {
	store := refusingServer(t)

	_, err := store.ListSecrets(context.Background(), &interfaces.SecretFilter{
		TenantID: "tenant-a/../tenant-b",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path segments")
}

func TestDeleteSecret_RejectsPathTraversalInKey(t *testing.T) {
	store := refusingServer(t)

	err := store.DeleteSecret(context.Background(), "tenant-a/../tenant-b/secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path segments")
}

func TestStoreSecret_AcceptsHierarchicalTenantID(t *testing.T) {
	// CFGMS tenant IDs are legitimately hierarchical paths (e.g.
	// "root/msp-a/client-1") — only ".", "..", and empty segments are rejected,
	// not "/" itself.
	store := refusingServer(t)

	err := store.StoreSecret(context.Background(), &interfaces.SecretRequest{
		TenantID: "root/msp-a/client-1",
		Key:      "api-token",
		Value:    "s3cr3t",
	})
	require.NoError(t, err)
}
