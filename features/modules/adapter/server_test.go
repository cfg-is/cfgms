// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package adapter_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/modules/adapter"
	"github.com/cfgis/cfgms/features/modules/file"
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
permissions: 493
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
permissions: 493
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
