// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// blockingIPTrustStore wraps a real business.IPTrustStore and blocks the first
// ListTrustedRanges call until released before delegating it, so a test can
// observe a sweep cycle "still in flight" and assert a second node cannot start
// an overlapping one. Every other method — and ListTrustedRanges itself once
// released — is served by the real store underneath: no mock framework, only
// the timing of one call changes.
type blockingIPTrustStore struct {
	business.IPTrustStore
	started chan struct{}
	release chan struct{}
	once    int32
}

func (s *blockingIPTrustStore) ListTrustedRanges(ctx context.Context, tenantID string) ([]*business.IPTrustEntry, error) {
	if atomic.CompareAndSwapInt32(&s.once, 0, 1) {
		close(s.started)
		<-s.release
	}
	return s.IPTrustStore.ListTrustedRanges(ctx, tenantID)
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of IPTrustExpiryJob: run() delegates to LeaseJob.RunIfLeader
// (ADR-031 Decision 4), so a second job contending for the same lease must not
// start its own sweep while the first job's is still in flight.
func TestIPTrustExpiryJob_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	leaseStore := pkgtesting.SetupTestLeaseStore(t)
	ttl := 2 * time.Second
	renew := 200 * time.Millisecond
	m1, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)
	m2, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)

	leaseJobA, err := lease.NewSingletonJob(m1, "ip-trust-expiry-test", "node-a", ttl, renew, nil)
	require.NoError(t, err)
	leaseJobB, err := lease.NewSingletonJob(m2, "ip-trust-expiry-test", "node-b", ttl, renew, nil)
	require.NoError(t, err)

	// One real storage manager backs both nodes, as a real cluster shares one
	// durable store. Node-a's view of the IP-trust store blocks on the first
	// ListTrustedRanges so its cycle can be held in flight; node-b gets the real
	// store untouched, so a failure to exclude it would run a real sweep.
	sm := pkgtesting.SetupTestStorage(t)
	tenantStore := sm.GetTenantStore()
	require.NoError(t, tenantStore.CreateTenant(context.Background(), &business.TenantData{
		ID: "tenant-1", Name: "tenant-1", Status: business.TenantStatusActive,
	}))
	ipTrustStore := sm.GetIPTrustStore()
	require.NotNil(t, ipTrustStore, "OSS storage manager must provide an IPTrustStore")

	store := &blockingIPTrustStore{
		IPTrustStore: ipTrustStore,
		started:      make(chan struct{}),
		release:      make(chan struct{}),
	}

	jobA := NewIPTrustExpiryJob(IPTrustExpiryConfig{
		Store: store, TenantStore: tenantStore, Logger: logging.NewNoopLogger(), LeaseJob: leaseJobA,
	})
	jobB := NewIPTrustExpiryJob(IPTrustExpiryConfig{
		Store: ipTrustStore, TenantStore: tenantStore, Logger: logging.NewNoopLogger(), LeaseJob: leaseJobB,
	})

	doneA := make(chan bool, 1)
	go func() {
		doneA <- jobA.leaseJob.RunIfLeader(context.Background(), jobA.expireStaleEntries)
	}()

	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never started")
	}

	ranB := jobB.leaseJob.RunIfLeader(context.Background(), jobB.expireStaleEntries)
	assert.False(t, ranB, "node-b must not run its own cycle while node-a's is still in flight")

	close(store.release)
	select {
	case ranA := <-doneA:
		assert.True(t, ranA)
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never completed")
	}
}
