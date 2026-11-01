// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package adapter_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/adapter"
	"github.com/cfgis/cfgms/features/modules/stdlib/file"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// stubServer satisfies the GracefulStop interface used by Shutdown.
type stubServer struct {
	stopped chan struct{}
}

func newStubServer() *stubServer { return &stubServer{stopped: make(chan struct{})} }

func (s *stubServer) GracefulStop() { close(s.stopped) }

func TestHandshakeReturnsModuleName(t *testing.T) {
	srv := adapter.New(file.New(), "file", newStubServer())
	resp, err := srv.Handshake(context.Background(), &proto.HandshakeRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, []string{"file"}, resp.GetCapabilities())
}

func TestSetConfiguresThenSetsDirectory(t *testing.T) {
	tmpBase := t.TempDir()
	targetPath := filepath.Join(tmpBase, "adapter-dir")
	configYAML := `
type: directory
state: present
allowed_base_path: ` + tmpBase + `
`
	srv := adapter.New(file.New(), "file", newStubServer())
	resp, err := srv.Set(context.Background(), &proto.SetRequest{
		ResourceId: targetPath,
		ConfigData: configYAML,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.GetApplied(), "adapter should report Applied=true on success")
	assert.Empty(t, resp.GetError(), "no error on a valid directory config")
}

func TestSetInvalidYAMLReturnsErrorInResponse(t *testing.T) {
	srv := adapter.New(file.New(), "file", newStubServer())
	resp, err := srv.Set(context.Background(), &proto.SetRequest{
		ResourceId: "/tmp/x",
		ConfigData: ":\tthis: is: not: yaml",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.GetError(), "invalid YAML must surface as error field, not gRPC error")
	assert.False(t, resp.GetApplied())
}

func TestTestReturnsInComplianceWhenStateMatches(t *testing.T) {
	tmpBase := t.TempDir()
	targetPath := filepath.Join(tmpBase, "compliant-dir")
	configYAML := `
type: directory
state: present
allowed_base_path: ` + tmpBase + `
`
	m := file.New()
	srv := adapter.New(m, "file", newStubServer())

	// Create the directory first so Get() can find it.
	_, err := srv.Set(context.Background(), &proto.SetRequest{
		ResourceId: targetPath,
		ConfigData: configYAML,
	})
	require.NoError(t, err)

	// Test should find the directory present and in compliance.
	testResp, err := srv.Test(context.Background(), &proto.TestRequest{
		ResourceId: targetPath,
		ConfigData: `state: present`,
	})
	require.NoError(t, err)
	require.NotNil(t, testResp)
	assert.True(t, testResp.GetInCompliance(), "state=present should be in compliance after Set")
}

func TestShutdownCallsGracefulStop(t *testing.T) {
	stub := newStubServer()
	srv := adapter.New(file.New(), "file", stub)
	_, err := srv.Shutdown(context.Background(), &proto.ShutdownRequest{})
	require.NoError(t, err)
	// GracefulStop is dispatched in a goroutine; wait on the closed channel.
	select {
	case <-stub.stopped:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("GracefulStop was not called within 100ms")
	}
}

// tenantEchoModule returns the ctxkeys.TenantID it sees from Get.
type tenantEchoModule struct{}

type echoState struct{ tenant string }

func (e echoState) AsMap() map[string]interface{} { return map[string]interface{}{"tenant": e.tenant} }
func (e echoState) ToYAML() ([]byte, error)       { return []byte("tenant: " + e.tenant), nil }
func (e echoState) FromYAML([]byte) error         { return nil }
func (e echoState) Validate() error               { return nil }
func (e echoState) GetManagedFields() []string    { return []string{"tenant"} }
func (tenantEchoModule) Get(ctx context.Context, _ string) (modules.ConfigState, error) {
	t, _ := ctx.Value(ctxkeys.TenantID).(string)
	return echoState{tenant: t}, nil
}
func (tenantEchoModule) Set(ctx context.Context, _ string, _ modules.ConfigState) error {
	if t, _ := ctx.Value(ctxkeys.TenantID).(string); t == "" {
		return errors.New("no tenant")
	}
	return nil
}

// [REQUIRED TEST] Issue #4891
func TestWorkflowServer_HandshakeBindsTenant(t *testing.T) {
	ctx := context.Background()
	var gotTenant, gotToken string
	srv := adapter.NewWorkflow(tenantEchoModule{}, "m", newStubServer(),
		adapter.WithHandshakeHandler(func(tenantID, authToken string) error {
			gotTenant, gotToken = tenantID, authToken
			return nil
		}))

	// Refused before a tenant is bound.
	_, err := srv.Get(ctx, &proto.GetRequest{ResourceId: "r"})
	require.Error(t, err)
	_, err = srv.Set(ctx, &proto.SetRequest{ResourceId: "r"})
	require.Error(t, err)
	_, err = srv.Test(ctx, &proto.TestRequest{ResourceId: "r"})
	require.Error(t, err)

	// A handshake with no tenant is refused and binds nothing.
	_, err = srv.Handshake(ctx, &proto.WorkflowHandshakeRequest{})
	require.Error(t, err)
	_, err = srv.Get(ctx, &proto.GetRequest{ResourceId: "r"})
	require.Error(t, err)

	_, err = srv.Handshake(ctx, &proto.WorkflowHandshakeRequest{TenantId: "t1", AuthToken: "tok"})
	require.NoError(t, err)
	assert.Equal(t, "t1", gotTenant)
	assert.Equal(t, "tok", gotToken)

	resp, err := srv.Get(ctx, &proto.GetRequest{ResourceId: "r"})
	require.NoError(t, err)
	assert.Contains(t, resp.ConfigData, "t1")
	setResp, err := srv.Set(ctx, &proto.SetRequest{ResourceId: "r"})
	require.NoError(t, err)
	assert.True(t, setResp.Applied)
	tr, err := srv.Test(ctx, &proto.TestRequest{ResourceId: "r", ConfigData: "tenant: t1"})
	require.NoError(t, err)
	assert.True(t, tr.InCompliance)

	// A different tenant cannot rebind the session; the same tenant may re-handshake.
	_, err = srv.Handshake(ctx, &proto.WorkflowHandshakeRequest{TenantId: "t2"})
	require.Error(t, err)
	resp, err = srv.Get(ctx, &proto.GetRequest{ResourceId: "r"})
	require.NoError(t, err)
	assert.Contains(t, resp.ConfigData, "t1")
	_, err = srv.Handshake(ctx, &proto.WorkflowHandshakeRequest{TenantId: "t1"})
	require.NoError(t, err)
}

func TestWorkflowServer_HandshakeHandlerErrorBindsNothing(t *testing.T) {
	ctx := context.Background()
	srv := adapter.NewWorkflow(tenantEchoModule{}, "m", newStubServer(),
		adapter.WithHandshakeHandler(func(string, string) error { return errors.New("bad credential") }))
	_, err := srv.Handshake(ctx, &proto.WorkflowHandshakeRequest{TenantId: "t1", AuthToken: "secret-tok"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret-tok")
	_, err = srv.Get(ctx, &proto.GetRequest{ResourceId: "r"})
	require.Error(t, err)
}

func TestWorkflowServer_WithoutOptionIsTenantAgnostic(t *testing.T) {
	srv := adapter.NewWorkflow(tenantEchoModule{}, "m", newStubServer())
	_, err := srv.Handshake(context.Background(), &proto.WorkflowHandshakeRequest{})
	require.NoError(t, err)
	_, err = srv.Get(context.Background(), &proto.GetRequest{ResourceId: "r"})
	require.NoError(t, err)
}
