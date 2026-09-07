// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/lease"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// contendingSecretStore wraps a real SecretStore and, on the first ListSecrets
// call only, runs contend before delegating. Its purpose is to give the two-node
// tests a point that is provably *inside* one node's sweep cycle — the cycle has
// been entered, its lease is held and being renewed, and its first store query
// has not returned yet — at which the rival node can attempt the same lease.
//
// Every other method, and ListSecrets itself once contend has run, is served by
// the real store underneath (same wrap-and-delegate shape as errListSecretStore
// in server_test.go; no mock framework), so the sweep runs its real query path.
//
// The rival's attempt is made from inside contend, on the same goroutine as the
// cycle, so the tests carry no cross-goroutine handshake and no wall-clock
// deadline: "node-a's cycle is in flight" is established by control flow rather
// than by waiting for a channel to be closed within some interval. The earlier
// shape ran node-a's cycle in a goroutine and waited up to 2s for it to signal
// that it had reached ListSecrets; that wait was a scheduling and disk-latency
// bet, not a property of the code under test, and it lost under the load of the
// full parallel package run. Do not reintroduce a timed handshake here.
type contendingSecretStore struct {
	secretsif.SecretStore

	// contend is invoked once, during the first ListSecrets call, before that
	// call is delegated to the real store. Set by the test before the cycle
	// starts.
	contend func()

	once      sync.Once
	contended atomic.Bool
}

func (s *contendingSecretStore) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	s.once.Do(func() {
		s.contended.Store(true)
		if s.contend != nil {
			s.contend()
		}
	})
	return s.SecretStore.ListSecrets(ctx, filter)
}

// twoLeaseJobs constructs two lease.SingletonJob values (standing in for two
// cluster nodes) contending for the same lease name against one real (not
// mocked) lease store.
func twoLeaseJobs(t *testing.T, name string) (lease.SingletonJob, lease.SingletonJob) {
	t.Helper()
	leaseStore := pkgtesting.SetupTestLeaseStore(t)
	ttl := 2 * time.Second
	renew := 200 * time.Millisecond
	m1, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)
	m2, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)

	jobA, err := lease.NewSingletonJob(m1, name, "node-a", ttl, renew, nil)
	require.NoError(t, err)
	jobB, err := lease.NewSingletonJob(m2, name, "node-b", ttl, renew, nil)
	require.NoError(t, err)
	return jobA, jobB
}

// twoSweepNodes builds two fully wired servers (each with its own real secret
// store, as setupTestServer provides) standing in for two cluster nodes, and
// wraps node-a's store so node-b can contend from inside node-a's first query.
// Node-b keeps its real store untouched: if the lease failed to exclude it, its
// cycle would run for real and RunIfLeader would report it.
func twoSweepNodes(t *testing.T) (*Server, *Server, *contendingSecretStore) {
	t.Helper()
	serverA := setupTestServer(t)
	serverB := setupTestServer(t)

	contending := &contendingSecretStore{SecretStore: serverA.secretStore}
	serverA.secretStore = contending
	return serverA, serverB, contending
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of the credential-request expiry sweep: the sweep tick handler
// delegates to credentialRequestSweepLease.RunIfLeader (ADR-031 Decision 4),
// so a second node contending for the same lease must not start its own sweep
// while the first's is still in flight.
func TestCredentialRequestSweep_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	jobA, jobB := twoLeaseJobs(t, "credential-request-expiry-test")
	serverA, serverB, contending := twoSweepNodes(t)
	serverA.credentialRequestSweepLease = jobA
	serverB.credentialRequestSweepLease = jobB

	cycle := func(s *Server) func(ctx context.Context) {
		return func(ctx context.Context) {
			s.sweepExpiredCredentialRequests(ctx)
			s.sweepOrphanedCollectedCertificates(ctx)
		}
	}

	// Node-b contends from inside node-a's first ListSecrets: node-a holds the
	// lease and its cycle has not returned. Its own context, not node-a's, so
	// node-a's run context plays no part in the outcome.
	var ranB bool
	contending.contend = func() {
		ranB = serverB.credentialRequestSweepLease.RunIfLeader(context.Background(), cycle(serverB))
	}

	ranA := serverA.credentialRequestSweepLease.RunIfLeader(context.Background(), cycle(serverA))

	require.True(t, contending.contended.Load(),
		"node-a's cycle never reached its first ListSecrets, so node-b never contended")
	assert.True(t, ranA, "node-a must run its cycle")
	assert.False(t, ranB, "node-b must not run its own cycle while node-a's is still in flight")
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of the cli-login expiry sweep (ADR-031 Decision 4).
func TestCliLoginSweep_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	jobA, jobB := twoLeaseJobs(t, "cli-login-request-expiry-test")
	serverA, serverB, contending := twoSweepNodes(t)
	serverA.cliLoginSweepLease = jobA
	serverB.cliLoginSweepLease = jobB

	var ranB bool
	contending.contend = func() {
		ranB = serverB.cliLoginSweepLease.RunIfLeader(context.Background(), serverB.sweepExpiredCliLoginRequests)
	}

	ranA := serverA.cliLoginSweepLease.RunIfLeader(context.Background(), serverA.sweepExpiredCliLoginRequests)

	require.True(t, contending.contended.Load(),
		"node-a's cycle never reached its first ListSecrets, so node-b never contended")
	assert.True(t, ranA, "node-a must run its cycle")
	assert.False(t, ranB, "node-b must not run its own cycle while node-a's is still in flight")
}
