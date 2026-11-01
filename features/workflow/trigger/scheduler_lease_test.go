// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/lease"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of the cron scheduler's due-trigger check: schedulerLoop
// delegates to the lease set by SetLeaseJob (ADR-031 Decision 4), so a second
// scheduler contending for the same lease must not run its own check cycle
// while the first's is still in flight.
func TestCronScheduler_LeaseJob_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	leaseStore := pkgtesting.SetupTestLeaseStore(t)
	ttl := 2 * time.Second
	renew := 200 * time.Millisecond
	m1, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)
	m2, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)

	leaseJobA, err := lease.NewSingletonJob(m1, "workflow-trigger-scheduler-test", "node-a", ttl, renew, nil)
	require.NoError(t, err)
	leaseJobB, err := lease.NewSingletonJob(m2, "workflow-trigger-scheduler-test", "node-b", ttl, renew, nil)
	require.NoError(t, err)

	schedulerA := NewCronScheduler(nil, nil)
	schedulerA.SetLeaseJob(leaseJobA)
	schedulerB := NewCronScheduler(nil, nil)
	schedulerB.SetLeaseJob(leaseJobB)

	started := make(chan struct{})
	release := make(chan struct{})
	var nodeARan, nodeBRan int

	doneA := make(chan bool, 1)
	go func() {
		doneA <- schedulerA.getLeaseJob().RunIfLeader(context.Background(), func(ctx context.Context) {
			nodeARan++
			close(started)
			<-release
		})
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never started")
	}

	ranB := schedulerB.getLeaseJob().RunIfLeader(context.Background(), func(ctx context.Context) {
		nodeBRan++
	})
	assert.False(t, ranB, "node-b must not run its own cycle while node-a's is still in flight")

	close(release)
	select {
	case ranA := <-doneA:
		assert.True(t, ranA)
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never completed")
	}

	assert.Equal(t, 1, nodeARan)
	assert.Equal(t, 0, nodeBRan)
}

// SetLeaseJob wired through TriggerManagerImpl.SetSchedulerLease reaches the
// underlying CronScheduler, proving the manager-level wiring used by server.go
// actually plumbs through (not just CronScheduler's own setter).
func TestTriggerManagerImpl_SetSchedulerLease_ReachesCronScheduler(t *testing.T) {
	manager := NewTriggerManager(nil, nil, nil, nil, nil, nil)
	scheduler := NewCronScheduler(manager, nil)
	manager.scheduler = scheduler

	leaseStore := pkgtesting.SetupTestLeaseStore(t)
	lm, err := lease.NewManager(leaseStore, time.Second, 200*time.Millisecond, 200*time.Millisecond)
	require.NoError(t, err)
	job, err := lease.NewSingletonJob(lm, "reach-test", "node-a", time.Second, 200*time.Millisecond, nil)
	require.NoError(t, err)

	manager.SetSchedulerLease(job)

	assert.NotNil(t, scheduler.getLeaseJob().Manager, "SetSchedulerLease must reach the underlying CronScheduler")
}
