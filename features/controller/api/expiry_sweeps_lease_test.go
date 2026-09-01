// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/lease"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// blockingSecretStore wraps a real SecretStore and blocks the first ListSecrets
// call until released before delegating it, so a test can observe a sweep cycle
// "still in flight" and assert a second node cannot start an overlapping one.
// Every other method — and ListSecrets itself once released — is served by the
// real store underneath (same wrap-and-delegate shape as errListSecretStore in
// server_test.go; no mock framework), so the sweep runs its real query path.
type blockingSecretStore struct {
	secretsif.SecretStore
	started chan struct{}
	release chan struct{}
	once    int32
}

func (s *blockingSecretStore) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	if atomic.CompareAndSwapInt32(&s.once, 0, 1) {
		close(s.started)
		<-s.release
	}
	return s.SecretStore.ListSecrets(ctx, filter)
}

// twoLeaseJobs constructs two lease.SingletonJob values (simulating two
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
// blocks node-a's first ListSecrets so its sweep cycle can be held in flight.
// Node-b keeps its real store untouched: if the lease failed to exclude it, its
// cycle would run for real and RunIfLeader would report it.
func twoSweepNodes(t *testing.T) (*Server, *Server, *blockingSecretStore) {
	t.Helper()
	serverA := setupTestServer(t)
	serverB := setupTestServer(t)

	blocking := &blockingSecretStore{
		SecretStore: serverA.secretStore,
		started:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	serverA.secretStore = blocking
	return serverA, serverB, blocking
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of the credential-request expiry sweep: the sweep tick handler
// delegates to credentialRequestSweepLease.RunIfLeader (ADR-031 Decision 4),
// so a second node contending for the same lease must not start its own sweep
// while the first's is still in flight.
func TestCredentialRequestSweep_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	jobA, jobB := twoLeaseJobs(t, "credential-request-expiry-test")
	serverA, serverB, blocking := twoSweepNodes(t)
	serverA.credentialRequestSweepLease = jobA
	serverB.credentialRequestSweepLease = jobB

	cycle := func(s *Server) func(ctx context.Context) {
		return func(ctx context.Context) {
			s.sweepExpiredCredentialRequests(ctx)
			s.sweepOrphanedCollectedCertificates(ctx)
		}
	}

	doneA := make(chan bool, 1)
	go func() {
		doneA <- serverA.credentialRequestSweepLease.RunIfLeader(context.Background(), cycle(serverA))
	}()

	select {
	case <-blocking.started:
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never started")
	}

	ranB := serverB.credentialRequestSweepLease.RunIfLeader(context.Background(), cycle(serverB))
	assert.False(t, ranB, "node-b must not run its own cycle while node-a's is still in flight")

	close(blocking.release)
	select {
	case ranA := <-doneA:
		assert.True(t, ranA)
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never completed")
	}
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of the cli-login expiry sweep (ADR-031 Decision 4).
func TestCliLoginSweep_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	jobA, jobB := twoLeaseJobs(t, "cli-login-request-expiry-test")
	serverA, serverB, blocking := twoSweepNodes(t)
	serverA.cliLoginSweepLease = jobA
	serverB.cliLoginSweepLease = jobB

	doneA := make(chan bool, 1)
	go func() {
		doneA <- serverA.cliLoginSweepLease.RunIfLeader(context.Background(), serverA.sweepExpiredCliLoginRequests)
	}()

	select {
	case <-blocking.started:
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never started")
	}

	ranB := serverB.cliLoginSweepLease.RunIfLeader(context.Background(), serverB.sweepExpiredCliLoginRequests)
	assert.False(t, ranB, "node-b must not run its own cycle while node-a's is still in flight")

	close(blocking.release)
	select {
	case ranA := <-doneA:
		assert.True(t, ranA)
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never completed")
	}
}
