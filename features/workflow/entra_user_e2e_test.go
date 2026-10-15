// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package workflow

import (
	"context"
	"os"
	"os/exec"
	goruntime "runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/runtime"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// [REQUIRED TEST] Issue #4325: with the m365-entra-user bundle published and
// approved, WorkflowModuleFactory.CreateModuleInstance resolves it, fork/execs
// it, and a workflow step reaches the module over gRPC. This test builds the
// real cmd/main.go binary (proving it exists and compiles, per the acceptance
// criteria — but does not stop there), publishes a publisher-signed bundle
// through the same cache APIs the controller's module approval pipeline uses,
// and drives a real Get() call through the fork/exec'd process's gRPC server.
//
// A connection is stored for the test's CFGMS tenant in a real controller
// secret store; the controller mints the Graph token and hands it to the module
// in the handshake (Issue #4891). The RPC reaches the module's real Get logic
// (cache -> credential issue -> fork/exec -> handshake -> gRPC -> adapter ->
// entra_user.Get -> tenant check -> auth.Provider) and fails at the module's
// tenant agreement check, without depending on outbound network access.
func TestWorkflowModuleFactory_IntegrationWithEntraUserModule(t *testing.T) {
	binDir := t.TempDir()
	bin := binDir + "/cfgms-module-m365-entra-user" + exeSuffix()
	// Path is relative to the features/workflow/ package directory where tests run.
	buildCmd := exec.Command("go", "build", "-o", bin, "./modules/m365/entra_user/cmd")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build m365-entra-user module binary: %s: %v", out, err)
	}

	b := newControllerBundle(t, "m365-entra-user", "cfgms", "0.1.0", bin, nil)
	require.Len(t, b.Signatures, 1)
	sig := b.Signatures[0].Signature

	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	require.NoError(t, err)
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusApproved))

	// The signature must survive the publish round trip intact (Issue #4325
	// acceptance criteria: "signature forwarded intact").
	stored, err := c.Get(b.ContentAddress())
	require.NoError(t, err)
	require.Len(t, stored.Signatures, 1)
	assert.Equal(t, "cfgms", stored.Signatures[0].Publisher)
	assert.Equal(t, sig, stored.Signatures[0].Signature)

	rt := runtime.NewModuleRuntime(shortRuntimeDir(t))
	factory := NewWorkflowModuleFactory(c, rt).(*WorkflowModuleFactory)

	// The controller holds the connection `cfg tenant m365 set` stored; the
	// forked module process holds no secret store and reads no M365 environment
	// settings. The controller mints the Graph token and delivers it, with the
	// execution tenant, in the module handshake (Issue #4891).
	store, _, _ := newSOPSStoreAt(t, t.TempDir())
	require.NoError(t, auth.NewSecretStoreCredentialStore(store).StoreConfig("e2e-tenant", &auth.OAuth2Config{
		ClientID: "e2e-client-id", ClientSecret: testClientSecret, TenantID: testM365Tenant, UseClientCredentials: true,
	}))
	factory.useSecretStore(store)
	te := newTokenEndpoint(t)
	factory.credentials.SetHTTPClient(te.cl)

	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "e2e-tenant")
	mod, err := factory.CreateTenantModuleInstance(ctx, "m365-entra-user", "e2e-tenant")
	require.NoError(t, err, "CreateTenantModuleInstance must resolve the published, approved bundle")
	require.NotNil(t, mod)
	assert.EqualValues(t, 1, te.hits.Load(), "the controller mints exactly one token for the session")

	handle, ok := mod.(*runtime.ModuleHandle)
	require.True(t, ok, "CreateTenantModuleInstance must return *runtime.ModuleHandle")
	t.Cleanup(func() { _ = handle.Stop() })

	// Drive a real Get() through the fork/exec'd process's gRPC server. The
	// handshake bound the execution tenant inside the module process, so the
	// module no longer refuses with "tenant context required", and the delivered
	// token is the one its auth provider hands out, so it does not fail with a
	// credential error. The resource names a different M365 tenant than the one
	// the delivered token was issued for, so the module stops at its own tenant
	// agreement check before any Graph request — proving the whole path ran
	// without outbound network access.
	_, err = mod.Get(ctx, "00000000-0000-0000-0000-000000000000:someone@example.com")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "tenant context required")
	assert.NotContains(t, err.Error(), "authenticate with Microsoft Graph")
	assert.Contains(t, err.Error(), "does not match the M365 tenant configured for this workflow execution",
		"error must come from the module's tenant agreement check, after authentication: %v", err)
}

// exeSuffix returns the platform executable suffix (".exe" on Windows, empty
// elsewhere) so exec.Command can resolve a binary built with "go build -o":
// on Windows, exec.LookPath requires a PATHEXT-recognized extension.
func exeSuffix() string {
	if goruntime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// shortRuntimeDir returns a runtimeDir for the module runtime. On Unix it is
// a temp dir under /tmp with a predictably short path so socket paths
// constructed from it fit within the macOS sun_path limit (103 bytes) —
// t.TempDir() on macOS generates paths that are too long. On Windows
// runtimeDir is unused by makeSocketPath (named pipes are identified by
// name, not filesystem path — see runtime/socket_windows.go), so t.TempDir()
// is fine there.
func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	if goruntime.GOOS == "windows" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp("/tmp", "cfgms-wf-m365-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
