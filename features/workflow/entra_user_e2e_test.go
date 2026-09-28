// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	goruntime "runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
	featuremodules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/workflow/runtime"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// [REQUIRED TEST] Issue #4325: with the m365-entra-user bundle published and
// approved, WorkflowModuleFactory.CreateModuleInstance resolves it, fork/execs
// it, and a workflow step reaches the module over gRPC. This test builds the
// real cmd/main.go binary (proving it exists and compiles, per the acceptance
// criteria — but does not stop there), publishes a publisher-signed bundle
// through the same cache APIs the controller's module approval pipeline uses,
// and drives a real Get() call through the fork/exec'd process's gRPC server.
//
// The module has no M365 credentials configured for the test's CFGMS tenant,
// so the RPC is expected to reach the module's real Set/Get logic and fail at
// the Microsoft Graph authentication step — not at connection, resolution, or
// module-lookup. That failure shape is what proves the full path (cache ->
// fork/exec -> gRPC -> adapter -> entra_user.Get -> ctx tenant check ->
// auth.Provider) executed for real, without depending on outbound network
// access or real M365 credentials in CI.
func TestWorkflowModuleFactory_IntegrationWithEntraUserModule(t *testing.T) {
	binDir := t.TempDir()
	bin := binDir + "/cfgms-module-m365-entra-user"
	// Path is relative to the features/workflow/ package directory where tests run.
	buildCmd := exec.Command("go", "build", "-o", bin, "./modules/m365/entra_user/cmd")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build m365-entra-user module binary: %s: %v", out, err)
	}

	binBytes, err := os.ReadFile(bin) //#nosec G304 -- bin is a path this test just built under t.TempDir()
	require.NoError(t, err)

	meta := &featuremodules.ModuleMetadata{
		Name:      "m365-entra-user",
		Version:   "0.1.0",
		Publisher: "cfgms",
		Executors: []string{"controller"},
		Kind:      "workflow",
	}
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)

	osArch := goruntime.GOOS + "-" + goruntime.GOARCH
	contentHash, err := bundle.ComputeContentHash(map[string][]byte{osArch: binBytes}, manifestBytes)
	require.NoError(t, err)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sig := ed25519.Sign(privKey, []byte(contentHash))
	_ = pubKey // the cache layer under test here does not verify signatures; captured for documentation only.

	b := &bundle.Bundle{
		Manifest:    meta,
		Binaries:    map[string]string{osArch: bin},
		ContentHash: contentHash,
		Signatures: []bundle.BundleSignature{
			{Publisher: "cfgms", Algorithm: "ed25519", Signature: sig},
		},
	}

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

	// Use /tmp explicitly so the socket path fits within macOS's 103-byte
	// sun_path limit — t.TempDir() on macOS generates paths that are too long.
	runtimeDir, err := os.MkdirTemp("/tmp", "cfgms-wf-m365-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	rt := runtime.NewModuleRuntime(runtimeDir)
	factory := NewWorkflowModuleFactory(c, rt)

	// The forked module process builds its auth provider from its own
	// environment (inherited from this test process via os.Environ()) — see
	// cmd/main.go's buildAuthProvider. No M365 credentials are seeded here:
	// the point of this test is reachability, not a successful Graph call.
	t.Setenv("CFGMS_M365_SECRETS_DIR", t.TempDir())

	mod, err := factory.CreateModuleInstance("m365-entra-user")
	require.NoError(t, err, "CreateModuleInstance must resolve the published, approved bundle")
	require.NotNil(t, mod)

	handle, ok := mod.(*runtime.ModuleHandle)
	require.True(t, ok, "CreateModuleInstance must return *runtime.ModuleHandle")
	t.Cleanup(func() { _ = rt.Stop(handle) })

	// Drive a real Get() call through the fork/exec'd process's gRPC server.
	//
	// ctx here carries ctxkeys.TenantID, but plain context.Context values do
	// not cross a gRPC hop (grpc-go propagates deadlines/cancellation, not
	// arbitrary Value entries), and neither this runtime nor the engine wires
	// WorkflowHandshakeRequest's tenant_id field yet (see adapter.NewWorkflow's
	// Handshake doc) — so the module process sees an empty execution tenant.
	// It must still refuse cleanly with entra_user's own fail-closed tenant
	// check, which is itself proof the RPC reached and executed the module's
	// real Get() logic on the other side of the socket, rather than failing at
	// connection or module resolution.
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "e2e-tenant")
	_, err = mod.Get(ctx, "some-m365-tenant:someone@example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant context required",
		"error must come from the module's real Get() logic, not a transport/resolution failure: %v", err)
}
