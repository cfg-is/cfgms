//go:build integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package openbao — integration tests for LeasedSecret implementation.
// Requires a running OpenBao dev instance:
//
//	docker compose --profile openbao -f docker-compose.test.yml up -d openbao-test
//
// Environment variables:
//
//	OPENBAO_ADDR=http://localhost:8201  (default)
//	OPENBAO_TOKEN=root                  (default for dev mode)
package openbao

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// TestLease_StoreImplementsLeasedSecret verifies the compile-time interface assertion
// is satisfied and LeasedSecret is accessible via type assertion.
func TestLease_StoreImplementsLeasedSecret(t *testing.T) {
	store := testStore(t)

	var ls interfaces.LeasedSecret
	var ok bool
	ls, ok = store.(interfaces.LeasedSecret)
	assert.True(t, ok, "OpenBaoSecretStore must implement interfaces.LeasedSecret")
	assert.NotNil(t, ls)
}

// TestLease_LeaseSecret_KVv2ReturnsNotSupported verifies that LeaseSecret on a
// KV v2 static secret always returns ErrLeaseNotSupported.
// KV v2 is a static secrets engine and does not produce server-managed leases.
func TestLease_LeaseSecret_KVv2ReturnsNotSupported(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, store, tenantID, "lease-kv-key")

	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key: "lease-kv-key", Value: "top-secret", TenantID: tenantID,
	}))

	_, err := store.LeaseSecret(ctx, &interfaces.LeaseRequest{
		Key:      "lease-kv-key",
		TenantID: tenantID,
		TTL:      30 * time.Second,
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, interfaces.ErrLeaseNotSupported),
		"expected ErrLeaseNotSupported, got: %v", err)
}

// TestLease_LeaseSecret_NilRequest verifies that a nil request returns an error.
func TestLease_LeaseSecret_NilRequest(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	_, err := store.LeaseSecret(ctx, nil)
	require.Error(t, err)
}

// TestLease_LeaseSecret_EmptyTenantID verifies that an empty TenantID is rejected.
func TestLease_LeaseSecret_EmptyTenantID(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	_, err := store.LeaseSecret(ctx, &interfaces.LeaseRequest{
		Key: "somekey",
		TTL: 30 * time.Second,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, interfaces.ErrTenantRequired)
}

// TestLease_LeaseSecret_EmptyKey verifies that an empty key is rejected.
func TestLease_LeaseSecret_EmptyKey(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	_, err := store.LeaseSecret(ctx, &interfaces.LeaseRequest{
		TenantID: "tenant1",
		TTL:      30 * time.Second,
	})

	require.Error(t, err)
}

// TestLease_RenewLease_InvalidLeaseID verifies that renewing a non-existent
// lease returns an error from the server.
func TestLease_RenewLease_InvalidLeaseID(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	_, err := store.RenewLease(ctx, "auth/token/invalid-lease-id-that-does-not-exist", 30*time.Second)
	require.Error(t, err, "renewing a non-existent lease should return an error")
}

// TestLease_RenewLease_EmptyLeaseID verifies that an empty leaseID is rejected
// before any server call.
func TestLease_RenewLease_EmptyLeaseID(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	_, err := store.RenewLease(ctx, "", 30*time.Second)
	require.Error(t, err)
}

// TestLease_RevokeLease_EmptyLeaseID verifies that an empty leaseID is rejected
// before any server call.
func TestLease_RevokeLease_EmptyLeaseID(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	err := store.RevokeLease(ctx, "")
	require.Error(t, err)
}

// TestLease_RevokeLease_InvalidLeaseID verifies that revoking a non-existent
// lease returns an error from the server.
func TestLease_RevokeLease_InvalidLeaseID(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	err := store.RevokeLease(ctx, "auth/token/invalid-lease-id-that-does-not-exist")
	require.Error(t, err, "revoking a non-existent lease should return an error")
}
