// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/dispatcher"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// libraryRunFixture is a tenant script library, an execution queue resolving from
// it, and a steward handler trusting one signing key — all real components.
type libraryRunFixture struct {
	repo    *script.TenantScriptRepository
	queue   *script.ExecutionQueue
	handler *Handler
	events  func() []*cpTypes.Event
	key     *rsa.PrivateKey
}

func newLibraryRunFixture(t *testing.T) *libraryRunFixture {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	repo, err := script.NewTenantScriptRepository(sm.GetConfigStore())
	require.NoError(t, err)

	queue := script.NewExecutionQueue(script.NewExecutionMonitor(), nil, 0, "", nil, repo, 0)
	t.Cleanup(queue.Stop)

	key := sigTestRSAKey(t)
	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  cb,
		Logger:    newTestLogger(t),
		SigningConfig: script.ModuleSigningConfig{
			TrustMode: script.TrustModeTrustedKeys,
			TrustedKeys: []script.TrustedKeyEntry{{
				Name:       "library-signing-key",
				Thumbprint: computeThumbprintFromPEM(sigTestPubKeyPEM(key)),
			}},
		},
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	return &libraryRunFixture{repo: repo, queue: queue, handler: h, events: getEvents, key: key}
}

// seed stores a library script for tenant. content is what is stored; the stored
// signature (when signer is non-nil) covers signedContent.
func (f *libraryRunFixture) seed(t *testing.T, tenant, id, content, signedContent string, signer *rsa.PrivateKey) {
	t.Helper()
	vs := &script.VersionedScript{
		Metadata: &script.ScriptMetadata{
			ID:       id,
			Name:     id,
			Version:  &script.Version{Major: 1},
			Shell:    script.ShellType(platformShell()),
			Platform: []string{"linux", "windows", "darwin"},
		},
		Content: content,
	}
	if signer != nil {
		vs.Signature = &script.ScriptSignature{
			Algorithm: "rsa-sha256",
			Signature: sigTestSignRSASHA256(t, signer, []byte(signedContent)),
			PublicKey: sigTestPubKeyPEM(signer),
		}
	}
	gr, err := f.repo.ForTenant(tenant)
	require.NoError(t, err)
	require.NoError(t, gr.Create(vs))
}

// run resolves a library run the way the dispatcher does and hands the resulting
// params to the steward handler.
func (f *libraryRunFixture) run(t *testing.T, tenant, id, execID string) error {
	t.Helper()
	exec := &script.QueuedExecution{
		ExecutionID: execID,
		ScriptRef:   id,
		Shell:       script.ShellType(platformShell()),
		Metadata:    map[string]interface{}{"tenant_id": tenant},
	}
	prepared, err := f.queue.PrepareExecutionForDevice(context.Background(), "steward-test", "", exec)
	require.NoError(t, err)

	params := dispatcher.BuildScriptCommandParams(exec, prepared)
	err = f.handler.HandleCommand(context.Background(), testSignedCommandWithParams(execID, cpTypes.CommandExecuteScript, params))
	f.handler.Wait()
	return err
}

func (f *libraryRunFixture) completed() *cpTypes.Event {
	return firstEventOfType(f.events(), cpTypes.EventScriptCompleted)
}

func TestLibraryRun_SignedByTrustedKey_Executed(t *testing.T) {
	f := newLibraryRunFixture(t)
	body := echoScriptBody("library-ok")
	f.seed(t, "tenant-a", "signed-script", body, body, f.key)

	require.NoError(t, f.run(t, "tenant-a", "signed-script", "lib-e2e-ok"))
	assert.NotNil(t, f.completed(), "a signed library script from a trusted key must execute")
}

func TestLibraryRun_Unsigned_Refused(t *testing.T) {
	f := newLibraryRunFixture(t)
	f.seed(t, "tenant-a", "unsigned-script", echoScriptBody("nope"), "", nil)

	err := f.run(t, "tenant-a", "unsigned-script", "lib-e2e-unsigned")
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Nil(t, f.completed())
}

func TestLibraryRun_TamperedAfterSigning_Refused(t *testing.T) {
	f := newLibraryRunFixture(t)
	f.seed(t, "tenant-a", "tampered-script", echoScriptBody("tampered"), echoScriptBody("original"), f.key)

	err := f.run(t, "tenant-a", "tampered-script", "lib-e2e-tampered")
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Nil(t, f.completed())
}

func TestLibraryRun_UntrustedKey_Refused(t *testing.T) {
	f := newLibraryRunFixture(t)
	body := echoScriptBody("untrusted")
	f.seed(t, "tenant-a", "untrusted-script", body, body, sigTestRSAKey(t))

	err := f.run(t, "tenant-a", "untrusted-script", "lib-e2e-untrusted")
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Nil(t, f.completed())
}

func TestLibraryRun_OtherTenantsScript_NotResolved(t *testing.T) {
	f := newLibraryRunFixture(t)
	body := echoScriptBody("a-only")
	f.seed(t, "tenant-a", "a-script", body, body, f.key)

	_, err := f.queue.PrepareExecutionForDevice(context.Background(), "steward-test", "", &script.QueuedExecution{
		ExecutionID: "lib-e2e-cross", ScriptRef: "a-script", Shell: script.ShellType(platformShell()),
		Metadata: map[string]interface{}{"tenant_id": "tenant-b"},
	})
	require.Error(t, err)
}
