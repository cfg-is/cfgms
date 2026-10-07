// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package run

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
)

// controllerNode is one controller's view of the cluster-shared stores: its own
// ExecutionQueue and run Manager instances over the same database tables.
type controllerNode struct {
	queue   *scriptmodule.ExecutionQueue
	manager *Manager
}

func newControllerNode(t *testing.T) controllerNode {
	t.Helper()
	sm := newTestClusterStorage(t)
	queue := scriptmodule.NewExecutionQueue(scriptmodule.NewExecutionMonitor(), scriptmodule.NewEphemeralKeyManager(),
		0, "", NewSharedQueueStore(sm.GetExecutionQueueStore()), nil, 0)
	return controllerNode{queue: queue, manager: NewManager(NewSharedRunStore(sm.GetScriptRunStore()), queue)}
}

// TestSharedStores_RunAcceptedOnOneNodeCompletesOnAnother reproduces Issue
// #4528: a command run accepted by node A for a steward whose session is on
// node B must be claimable and completable by node B, and node A must then
// report the completed run.
func TestSharedStores_RunAcceptedOnOneNodeCompletesOnAnother(t *testing.T) {
	ctx := context.Background()
	nodeA := newControllerNode(t)
	nodeB := newControllerNode(t)
	device := fmt.Sprintf("steward-xnode-%d", time.Now().UnixNano())

	runID, err := SynthesizeCommandRun(ctx, nodeA.manager, nodeA.queue,
		&staticFleetQuery{results: []fleet.StewardResult{{ID: device, TenantID: "tenant-x"}}},
		"tenant-x", "admin", fleet.Filter{IDs: []string{device}}, "hostname", scriptmodule.ShellPowerShell,
		nil, nil, nil, "nonce-"+device, time.Now().Add(time.Hour))
	require.NoError(t, err)

	// Node B sees the run node A created.
	run, err := nodeB.manager.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, RunStatusRunning, run.Status)

	// Node B (holding the session) claims the work; node A finds nothing left to claim.
	claimed, err := nodeB.queue.DequeueForDevice(device)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	execID := claimed[0].ExecutionID

	// Node B resolves the run linkage from the shared queue, as its dispatcher's
	// completion handler does, and records the result.
	var jobID string
	for _, qe := range nodeB.queue.PeekForDevice(device) {
		if qe.ExecutionID == execID {
			assert.Equal(t, runID, qe.Metadata["workflow_run_id"], "run linkage survives the shared store")
			jobID, _ = qe.Metadata["job_id"].(string)
		}
	}
	require.NotEmpty(t, jobID, "node B must find node A's job linkage")
	require.NoError(t, nodeB.queue.AcknowledgeCompletion(execID, device, scriptmodule.QueueStateCompleted, &scriptmodule.ExecutionResult{ExitCode: 0}))
	require.NoError(t, nodeB.manager.RecordJobResult(ctx, runID, jobID, execID, false, "HOST-B", "", 0))

	// Node A reports the completed run and captured output.
	run, err = nodeA.manager.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, RunStatusCompleted, run.Status)
	jobs, err := nodeA.manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.Equal(t, "HOST-B", jobs[0].Output)
}

// TestSharedStores_ActionEnvelopeSurvivesRoundTripAcrossNodes enqueues a steward
// action through node A's store and dequeues it through node B's: Kind, Action
// and the whole operator envelope arrive unchanged (Issue #4625).
func TestSharedStores_ActionEnvelopeSurvivesRoundTripAcrossNodes(t *testing.T) {
	ctx := context.Background()
	nodeA := newControllerNode(t)
	nodeB := newControllerNode(t)
	device := fmt.Sprintf("steward-envelope-%d", time.Now().UnixNano())
	proof := &CommandSignature{
		Algorithm: "ecdsa-sha256", Value: "c2ln+/==", PublicKey: "-----BEGIN PUBLIC KEY-----\n<k>&\n-----END PUBLIC KEY-----\n",
	}
	expiresAt := time.Now().Add(time.Minute)
	spec := scriptmodule.StewardActionSpec{Verb: "service.stop", TargetKind: "service", TargetName: "spooler", Parameters: map[string]string{"a": "b"}}

	runID, err := SynthesizeActionRunForDevices(ctx, nodeA.manager, nodeA.queue,
		[]fleet.StewardResult{{ID: device, TenantID: "tenant-x"}}, "tenant-x", "admin", fleet.Filter{},
		spec, proof, []string{device, "other"}, "nonce-"+device, expiresAt)
	require.NoError(t, err)

	run, err := nodeB.manager.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, RunKindStewardAction, run.Kind, "the run kind survives the shared run store")
	assert.JSONEq(t, `{"verb":"service.stop","target_kind":"service","target_name":"spooler","parameters":{"a":"b"}}`, string(run.ActionJSON))

	claimed, err := nodeB.queue.DequeueForDevice(device)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	qe := claimed[0]
	assert.Equal(t, scriptmodule.QueueKindStewardAction, qe.Kind)
	require.NotNil(t, qe.Action)
	assert.Equal(t, spec, *qe.Action)
	assert.Equal(t, scriptmodule.StewardActionTimeout, qe.Timeout)
	assert.Equal(t, proof.Algorithm, qe.Metadata["signature_algorithm"])
	assert.Equal(t, proof.Value, qe.Metadata["signature_value"])
	assert.Equal(t, proof.PublicKey, qe.Metadata["signature_public_key"])
	assert.Equal(t, "nonce-"+device, qe.Metadata["nonce"])
	assert.Equal(t, expiresAt.UTC().Format(time.RFC3339), qe.Metadata["expires_at"])
	assert.ElementsMatch(t, []interface{}{device, "other"}, qe.Metadata["targets"])
}
