// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestServer_New_WiresWorkflowScriptExecutor is the composition-root wiring test
// for the workflow script step (Issue #5851): the engine New builds must carry the
// script executor, built over the controller's execution queue. It is observed
// through behaviour: a restricted run of a script step must get past "no
// executor" and stop at the executor's own fail-closed refusal (no approver is
// wired until the approver adapter's story lands), with nothing queued.
func TestServer_New_WiresWorkflowScriptExecutor(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir := t.TempDir()
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Workflow Script Wiring Test",
			Country:      "US",
			ValidityDays: 3650,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "failed to create test CA")

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "workflow-script-wiring-controller",
				Organization: "Workflow Script Wiring Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		Storage: createTestStorageConfig(tempDir, "workflow-script-wiring"),
	}

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })
	require.NotNil(t, srv.workflowEngine, "the workflow engine must be initialized")
	require.NotNil(t, srv.executionQueue, "the execution queue must be initialized")

	wf := workflow.Workflow{
		Name: "gather-inventory",
		Steps: []workflow.Step{{Name: "collect", Type: workflow.StepTypeScript, Config: map[string]interface{}{
			"script_id": "inventory", "script_version": "1.0.0", "devices": []interface{}{"dev-1"},
		}}},
	}
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "client-1")

	exec, err := srv.workflowEngine.ExecuteRestrictedWorkflow(ctx, wf, nil,
		workflow.RestrictedRun{RunID: "run-1", GrantID: "grant-1", Ceiling: "msp"})
	require.NoError(t, err)
	select {
	case <-exec.Done:
	case <-time.After(15 * time.Second):
		t.Fatal("the workflow did not finish")
	}

	assert.Equal(t, workflow.StatusFailed, exec.GetStatus())
	assert.NotContains(t, exec.GetError(), "script executor not configured",
		"the production engine must have the script executor")
	assert.Contains(t, exec.GetError(), "no script approver",
		"the executor refuses a restricted step until an approver is wired")
	assert.Zero(t, srv.executionQueue.GetTotalQueueDepth(), "nothing was queued")

	// The unrestricted path refuses a script step before anything starts.
	_, err = srv.workflowEngine.ExecuteWorkflow(ctx, wf, nil)
	require.ErrorIs(t, err, workflow.ErrScriptStepNotRestricted)
}
