// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Cluster tests for steward actions (Issue #4625): two controller nodes over the
// same PostgreSQL tables. External package placement matches
// cancel_dispatcher_test.go: these tests import features/controller/dispatcher.
// They skip when the test database is unreachable.
package run_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/dispatcher"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/run"
	script "github.com/cfgis/cfgms/features/modules/stdlib/script"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// clusterCP is the control-plane slice a dispatcher uses: SendCommand and
// SubscribeEvents. The embedded nil interface makes any other call fail loudly.
type clusterCP struct {
	cpinterfaces.ControlPlaneProvider
	mu      sync.Mutex
	sent    []*controlplaneTypes.SignedCommand
	handler cpinterfaces.EventHandler
}

func (p *clusterCP) SendCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, cmd)
	return nil
}

func (p *clusterCP) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, h cpinterfaces.EventHandler) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handler = h
	return nil
}

func (p *clusterCP) sentCommands() []*controlplaneTypes.SignedCommand {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*controlplaneTypes.SignedCommand(nil), p.sent...)
}

func (p *clusterCP) inject(ctx context.Context, ev *controlplaneTypes.Event) error {
	p.mu.Lock()
	h := p.handler
	p.mu.Unlock()
	if h == nil {
		return fmt.Errorf("no event handler registered")
	}
	return h(ctx, ev)
}

type auditLog struct {
	mu   sync.Mutex
	jobs []dispatcher.ExpiredActionJob
}

func (a *auditLog) RecordActionExpired(_ context.Context, job dispatcher.ExpiredActionJob) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.jobs = append(a.jobs, job)
}

// countRun counts audited jobs of one run; the shared database may hold stale
// action jobs of other tests, which a sweep legitimately closes too.
func (a *auditLog) countRun(runID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, job := range a.jobs {
		if job.RunID == runID {
			n++
		}
	}
	return n
}

// clusterNode is one controller: its own queue handle, run manager and
// dispatcher over the shared stores.
type clusterNode struct {
	queue   *script.ExecutionQueue
	manager *run.Manager
	d       *dispatcher.Dispatcher
	cp      *clusterCP
	audit   *auditLog
}

func newClusterStorage(t *testing.T) *interfaces.StorageManager {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping PostgreSQL-backed test in short mode")
	}
	port := os.Getenv("CFGMS_TEST_DB_PORT")
	if port == "" {
		port = "5432"
	}
	dsn := fmt.Sprintf("host=localhost port=%s dbname=cfgms_test user=cfgms_test password=%s sslmode=disable",
		port, testutil.GetTestDBPassword())
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skip("PostgreSQL test database not reachable:", err)
	}
	_ = db.Close()

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	sm, err := interfaces.CreateClusterStorageManager(dsn, hex.EncodeToString(key), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	return sm
}

// newClusterNode builds a node. holdsSession decides which node dispatches to
// which steward, as the session registry does in cluster mode.
func newClusterNode(t *testing.T, holdsSession func(string) bool) *clusterNode {
	t.Helper()
	sm := newClusterStorage(t)
	keys := script.NewEphemeralKeyManager()
	t.Cleanup(keys.Stop)
	queue := script.NewExecutionQueue(script.NewExecutionMonitor(), keys, 0, "",
		run.NewSharedQueueStore(sm.GetExecutionQueueStore()), nil, 0)
	t.Cleanup(queue.Stop)
	manager := run.NewManager(run.NewSharedRunStore(sm.GetScriptRunStore()), queue)

	cp := &clusterCP{}
	audit := &auditLog{}
	d, err := dispatcher.New(&dispatcher.Config{
		Queue: queue, ControlPlane: cp, PollInterval: 24 * time.Hour,
		IsLocallyConnected: holdsSession, ActionAudit: audit, Logger: logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	manager.SetDeviceLockReleaser(d)
	d.SetRunCompletionSink(manager)
	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)
	return &clusterNode{queue: queue, manager: manager, d: d, cp: cp, audit: audit}
}

func enqueueClusterAction(t *testing.T, n *clusterNode, device string, proof *run.CommandSignature) (string, string) {
	t.Helper()
	runID, err := run.SynthesizeActionRunForDevices(context.Background(), n.manager, n.queue,
		[]fleet.StewardResult{{ID: device, TenantID: "tenant-x"}}, "tenant-x", "admin", fleet.Filter{},
		script.StewardActionSpec{Verb: "service.restart", TargetKind: "service", TargetName: "spooler"},
		proof, []string{device}, "nonce-"+device, time.Now().Add(time.Minute))
	require.NoError(t, err)
	jobs, err := n.manager.ListRunJobs(context.Background(), runID)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	return runID, jobs[0].ExecutionID
}

// TestStewardAction_AcceptedOnOneNodeDeliveredAndCompletedOnAnother covers the
// cluster path: node A accepts the action, node B holds the steward's session,
// delivers it with the operator envelope intact, and node B records the result
// code that node A then reads.
func TestStewardAction_AcceptedOnOneNodeDeliveredAndCompletedOnAnother(t *testing.T) {
	ctx := context.Background()
	device := fmt.Sprintf("steward-xnode-act-%d", time.Now().UnixNano())
	nodeA := newClusterNode(t, func(string) bool { return false })
	nodeB := newClusterNode(t, func(id string) bool { return id == device })

	proof := &run.CommandSignature{WebAuthnAuthenticatorData: "YWQ", WebAuthnClientDataJSON: "Y2Q", WebAuthnSignature: "c2ln",
		WebAuthnCredentialID: "aWQ", WebAuthnManifest: `{"manifest":{"r":"é \"q\""}}`}
	runID, execID := enqueueClusterAction(t, nodeA, device, proof)

	// Node A does not hold the session: it leaves the entry queued.
	nodeA.d.OnHeartbeat(device)
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, nodeA.cp.sentCommands(), "the node without the session never delivers")

	// Node B delivers it.
	nodeB.d.OnHeartbeat(device)
	require.Eventually(t, func() bool { return len(nodeB.cp.sentCommands()) == 1 }, 5*time.Second, 20*time.Millisecond)
	sent := nodeB.cp.sentCommands()[0]
	assert.Equal(t, controlplaneTypes.CommandStewardAction, sent.Command.Type)
	assert.Equal(t, execID, sent.Command.Params["execution_id"])
	assert.Equal(t, proof.WebAuthnManifest, sent.Command.Params["webauthn_manifest"], "the envelope survives the shared store byte for byte")
	assert.Equal(t, proof.WebAuthnSignature, sent.Command.Params["webauthn_signature"])
	assert.Equal(t, []string{device}, sent.Command.Params["targets"])
	assert.Equal(t, "nonce-"+device, sent.Command.Params["nonce"])

	jobs, err := nodeA.manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, run.JobStatusDispatched, jobs[0].Status, "node A sees node B's dispatch")

	// The steward reports to node B; node A reads the recorded result code.
	require.NoError(t, nodeB.cp.inject(ctx, &controlplaneTypes.Event{
		ID: "evt-" + execID, Type: controlplaneTypes.EventScriptCompleted, StewardID: device, Timestamp: time.Now(),
		Details: map[string]interface{}{"execution_id": execID, "exit_code": float64(1), "result_code": "self_protect"},
	}))
	jobs, err = nodeA.manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, "self_protect", jobs[0].ResultCode, "a completion received on another node records the result code")
	assert.Equal(t, run.JobStatusFailed, jobs[0].Status)
	r, err := nodeA.manager.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, run.RunStatusFailed, r.Status)
	assert.Equal(t, run.RunKindStewardAction, r.Kind)
}

// TestStewardAction_ConcurrentSweepsAcrossNodesAuditOnce races both nodes'
// sweeps over one stale job in the shared database: one terminal status, one
// audit event.
func TestStewardAction_ConcurrentSweepsAcrossNodesAuditOnce(t *testing.T) {
	ctx := context.Background()
	device := fmt.Sprintf("steward-sweep-act-%d", time.Now().UnixNano())
	nodeA := newClusterNode(t, func(string) bool { return false })
	nodeB := newClusterNode(t, func(string) bool { return false })
	runID, _ := enqueueClusterAction(t, nodeA, device,
		&run.CommandSignature{Algorithm: "ecdsa-sha256", Value: "v", PublicKey: "k"})

	at := time.Now().Add(script.StewardActionTTL + time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		node := nodeA
		if i%2 == 1 {
			node = nodeB
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each node's poll-loop sweep runs ExpireActionJobs on its manager.
			closed, err := node.manager.ExpireActionJobs(ctx, at)
			assert.NoError(t, err)
			for _, job := range closed {
				node.audit.RecordActionExpired(ctx, job)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, nodeA.audit.countRun(runID)+nodeB.audit.countRun(runID), "exactly one audit event across the cluster")
	jobs, err := nodeB.manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, run.JobStatusExpired, jobs[0].Status)
	assert.Equal(t, run.ResultCodeExpired, jobs[0].ResultCode)
}
