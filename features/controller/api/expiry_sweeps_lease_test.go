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
// been entered, its lease is held, and its first store query has not returned
// yet — at which the rival node can attempt the same lease.
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

// Lease parameters for the two-node sweep tests.
//
// The property under test is exclusion — node-b must be refused while node-a
// holds the lease — not expiry, and not renewal (renewal across a TTL boundary
// is covered by TestSingletonJob_SlowCycleRenewsAcrossTTL_NoDuplicateRun in
// pkg/lease). The TTL is therefore chosen so that node-a's lease *cannot* lapse
// during a run: 15m is longer than the per-package binary deadline every target
// that runs this package uses (`make test` -timeout=10m, `make test-fast`
// -timeout=2m), so Go panics the binary as a hang long before the row could
// expire. "Node-b acquired because node-a's lease had already expired" is thus
// not a reachable outcome, and the only thing left that can flip ranB to true
// is a genuine exclusivity failure — which is what the assertion is for.
//
// A short TTL (this was 2s) instead makes the test's *premise* a wall-clock bet
// on storage latency, and loses it under load. business.LeaseStore stamps the
// row's expires_at from its own clock when it applies the write — before that
// write is fsynced — so a slow acquire hands the caller a lease that has already
// spent part, or all, of its TTL. Measured on the flatfile store this package's
// helpers use: 808ms for a single acquire round-trip with 32 concurrent writers
// against the same directory, and a full `make test` run applies far more fsync
// pressure than that. Once one acquire round-trip exceeds the TTL, node-a
// returns from TryAcquire holding an already-expired row, node-b's contend
// (microseconds later, and before RunIfLeader's first renewal tick) legitimately
// acquires it, and both nodes report having run — the observed failure. The
// failing run bears this out: it recorded 2.29s for a test that takes 0.11s
// unloaded, against the 2s TTL it was then using. No test-side synchronisation
// can prevent that — the deadline being missed is the store's, not the test's.
// Only a TTL that cannot lapse inside the test removes it.
const (
	sweepTestLeaseTTL   = 15 * time.Minute
	sweepTestLeaseRenew = 1 * time.Minute
)

// twoLeaseJobs constructs two lease.SingletonJob values (standing in for two
// cluster nodes) contending for the same lease name against one real (not
// mocked) lease store.
func twoLeaseJobs(t *testing.T, name string) (lease.SingletonJob, lease.SingletonJob) {
	t.Helper()
	leaseStore := pkgtesting.SetupTestLeaseStore(t)
	ttl := sweepTestLeaseTTL
	renew := sweepTestLeaseRenew
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

// leaseAtContend is the store's own answer to "who holds this lease, and does
// the store still consider it valid?", read at the instant node-b contends. It
// lets the assertions below state their premise rather than assume it: an
// exclusivity verdict is only meaningful against a lease the store still holds
// valid, and a failure that names an expired claim is a different bug from one
// that names a node running while a live claim excluded it.
type leaseAtContend struct {
	holder string
	valid  bool
	err    error
}

// runContendedCycle runs node-a's cycle and, from inside node-a's first
// ListSecrets, has node-b attempt the same lease: node-a holds the lease and
// its cycle has not returned. Each node uses its own context, so node-a's run
// context plays no part in the outcome.
//
// contend runs inline on the test's own goroutine (RunIfLeader calls fn on the
// caller's goroutine), so ranB and observed need no synchronisation and the
// test carries no cross-goroutine handshake — see contendingSecretStore.
func runContendedCycle(t *testing.T, contending *contendingSecretStore, jobA, jobB lease.SingletonJob,
	cycleA, cycleB func(ctx context.Context)) (ranA, ranB bool) {
	t.Helper()

	var observed leaseAtContend
	contending.contend = func() {
		// Read through to the store, immediately before node-b's attempt and
		// under the same store lock discipline, so nothing can interleave
		// between the observation and the attempt it describes.
		observed.holder, _, _, observed.valid, observed.err =
			jobA.Manager.CurrentHolder(context.Background(), jobA.Name)
		ranB = jobB.RunIfLeader(context.Background(), cycleB)
	}

	ranA = jobA.RunIfLeader(context.Background(), cycleA)

	require.True(t, contending.contended.Load(),
		"node-a's cycle never reached its first ListSecrets, so node-b never contended")
	require.NoError(t, observed.err, "reading the lease at the contend point failed")
	require.Equal(t, jobA.HolderID, observed.holder,
		"premise: node-a must still be the recorded holder when node-b contends")
	require.True(t, observed.valid,
		"premise: node-a's lease must still be valid when node-b contends")
	return ranA, ranB
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

	ranA, ranB := runContendedCycle(t, contending,
		serverA.credentialRequestSweepLease, serverB.credentialRequestSweepLease,
		cycle(serverA), cycle(serverB))

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

	ranA, ranB := runContendedCycle(t, contending,
		serverA.cliLoginSweepLease, serverB.cliLoginSweepLease,
		serverA.sweepExpiredCliLoginRequests, serverB.sweepExpiredCliLoginRequests)

	assert.True(t, ranA, "node-a must run its cycle")
	assert.False(t, ranB, "node-b must not run its own cycle while node-a's is still in flight")
}
