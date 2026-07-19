// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/providers/database"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// testPostgresConfig returns a database provider config for the test Postgres instance.
// The test is skipped if the instance is not reachable.
func testPostgresConfig(t *testing.T) map[string]interface{} {
	t.Helper()
	password := testutil.GetTestDBPassword()
	if password == "" {
		t.Skip("No test Postgres password available (CFGMS_TEST_DB_PASSWORD not set)")
	}
	port := 5432
	if portStr := os.Getenv("CFGMS_TEST_DB_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	return map[string]interface{}{
		"host":     "localhost",
		"port":     port,
		"database": "cfgms_test",
		"username": "cfgms_test",
		"password": password,
		"sslmode":  "disable",
	}
}

// newClusterSessionTokenStore opens a DatabaseSessionTokenStore backed by the test
// Postgres instance. Skips if the instance is not reachable.
func newClusterSessionTokenStore(t *testing.T) *database.DatabaseSessionTokenStore {
	t.Helper()
	cfg := testPostgresConfig(t)
	p := &database.DatabaseProvider{}
	store, err := p.CreateSessionTokenStore(cfg)
	if err != nil {
		t.Skipf("Postgres session token store not available: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestSessionTokenCrossNodeRoundTrip validates the four-step cross-node property
// required by AC #4 of Issue #2775:
//
//  1. Manager A issues a session — writes hash to the shared Postgres store.
//  2. Manager B (separate instance, same store) validates the token — proves cross-node issuance.
//  3. Manager B revokes the session — deletes all hashes from the shared store.
//  4. Manager A's next Validate call is rejected — proves revocation is visible back to
//     the origin node (the real cross-node-revocation property AC #4 requires).
//
// Both managers share the same *DatabaseSessionTokenStore, which simulates two controller
// processes pointing at the same Postgres DSN without needing two full controller processes.
func TestSessionTokenCrossNodeRoundTrip(t *testing.T) {
	sharedStore := newClusterSessionTokenStore(t)
	ctx := context.Background()

	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}

	// Two managers — same store, simulating node A and node B.
	mgrA := session.NewManager(cfg, sharedStore, time.Now)
	mgrB := session.NewManager(cfg, sharedStore, time.Now)

	// Step 1: Node A issues a session.
	sess, tok, err := mgrA.Issue(ctx, "cross-node-alice", "ctrl", "tenant-1")
	require.NoError(t, err, "Issue on manager A")
	require.NotEmpty(t, tok)

	// Step 2: Node B validates the token — cache miss → store lookup → succeeds.
	got, err := mgrB.Validate(ctx, tok)
	require.NoError(t, err, "Validate on manager B before revocation (cross-node issuance)")
	assert.Equal(t, sess.ID, got.ID)
	assert.Equal(t, "cross-node-alice", got.PrincipalID)

	// Step 3: Node B revokes the session (deletes all hashes from shared store).
	require.NoError(t, mgrB.Revoke(ctx, sess.ID), "Revoke on manager B")

	// Step 4: Node A's Validate must now reject — the store record was deleted by B.
	// This exercises manager.go:154-163 (store-miss → remote revocation detected).
	_, err = mgrA.Validate(ctx, tok)
	require.Error(t, err, "Validate on manager A after cross-node revocation must fail")
	assert.True(t,
		errors.Is(err, session.ErrSessionRevoked) || errors.Is(err, session.ErrSessionNotFound),
		fmt.Sprintf("expected ErrSessionRevoked or ErrSessionNotFound, got: %v", err),
	)
}

// TestSessionTokenCrossNodeIssuance is a simpler check: confirm that manager B can
// validate a session issued by manager A when both share the Postgres store.
func TestSessionTokenCrossNodeIssuance(t *testing.T) {
	sharedStore := newClusterSessionTokenStore(t)
	ctx := context.Background()

	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}

	mgrA := session.NewManager(cfg, sharedStore, time.Now)
	mgrB := session.NewManager(cfg, sharedStore, time.Now)

	_, tok, err := mgrA.Issue(ctx, "cross-node-bob", "ctrl", "tenant-2")
	require.NoError(t, err)

	got, err := mgrB.Validate(ctx, tok)
	require.NoError(t, err, "Validate on manager B (cross-node) must succeed")
	assert.Equal(t, "cross-node-bob", got.PrincipalID)
}

// TestSessionTokenCrossNodeGraceExpiry verifies that a token rotated on manager A is
// rejected by manager B after the grace window elapses — StampGraceExpiry must persist
// the per-hash deadline into the shared store so peer nodes honour it.
func TestSessionTokenCrossNodeGraceExpiry(t *testing.T) {
	sharedStore := newClusterSessionTokenStore(t)
	ctx := context.Background()

	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     20 * time.Millisecond, // very short so tests run fast
	}

	mgrA := session.NewManager(cfg, sharedStore, time.Now)
	mgrB := session.NewManager(cfg, sharedStore, time.Now)

	// Node A: issue → renew; oldToken enters grace.
	_, oldTok, err := mgrA.Issue(ctx, "cross-node-dave", "ctrl", "tenant-3")
	require.NoError(t, err)
	_, newTok, err := mgrA.Renew(ctx, oldTok)
	require.NoError(t, err)

	// Wait for grace window to expire.
	time.Sleep(50 * time.Millisecond)

	// Node B: new token is always valid.
	_, err = mgrB.Validate(ctx, newTok)
	assert.NoError(t, err, "new token must be valid on manager B")

	// Node B: old token's hash_expires_at has passed → must be rejected.
	_, err = mgrB.Validate(ctx, oldTok)
	assert.Error(t, err, "grace-expired old token must be rejected on manager B")
}
