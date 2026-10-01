// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package adapter_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	featuremodules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/adapter"
	"github.com/cfgis/cfgms/features/steward/modules/runtime"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/contract"
)

// fakeModuleServer is a minimal, hand-written ModuleService implementation
// used only to control what a "module" returns for a given RPC — real gRPC
// server and client, not a mock of modules.Module or of the adapter itself.
// It mirrors the shape of runtime package's testdata/echo_module fixture.
type fakeModuleServer struct {
	proto.UnimplementedModuleServiceServer
	getResp *proto.GetResponse
	getErr  error
	setResp *proto.SetResponse
	setErr  error
}

func (s *fakeModuleServer) Get(_ context.Context, _ *proto.GetRequest) (*proto.GetResponse, error) {
	return s.getResp, s.getErr
}

func (s *fakeModuleServer) Set(_ context.Context, _ *proto.SetRequest) (*proto.SetResponse, error) {
	return s.setResp, s.setErr
}

// startFakeServer starts srv on a loopback TCP listener and returns a dialed
// client plus a cleanup. The real generated client and server are used over a
// real network connection, so a transport-level failure is a real one.
func startFakeServer(t *testing.T, srv proto.ModuleServiceServer) contract.StewardModuleClient {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcSrv := grpc.NewServer()
	proto.RegisterModuleServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return proto.NewModuleServiceClient(conn)
}

// TestClient_Get_ModuleSideErrorIsDistinctFromSuccess verifies a gRPC-level
// error from the module's Get surfaces as an error from the adapter, not as a
// zero-valued ConfigState.
func TestClient_Get_ModuleSideErrorIsDistinctFromSuccess(t *testing.T) {
	client := startFakeServer(t, &fakeModuleServer{
		getErr: status.Error(codes.Internal, "module Get failed"),
	})
	c := adapter.NewClient(client, "fake")

	state, err := c.Get(context.Background(), "res-1")
	require.Error(t, err)
	assert.Nil(t, state)
	assert.Contains(t, err.Error(), "module Get failed")
}

// TestClient_Get_EmptyConfigDataMapsToNilState verifies the adapter's
// documented mapping: an empty ConfigData (the module's Get returned a nil
// ConfigState) becomes a nil ConfigState, not a populated-looking zero value.
func TestClient_Get_EmptyConfigDataMapsToNilState(t *testing.T) {
	client := startFakeServer(t, &fakeModuleServer{
		getResp: &proto.GetResponse{},
	})
	c := adapter.NewClient(client, "fake")

	state, err := c.Get(context.Background(), "res-1")
	require.NoError(t, err)
	assert.Nil(t, state)
}

// TestClient_Get_TransportErrorIsReturned verifies a transport-level failure
// (no listener at all behind the dialed address) surfaces as an error, not a
// successful nil result.
func TestClient_Get_TransportErrorIsReturned(t *testing.T) {
	// Dial an address nothing is listening on.
	conn, err := grpc.NewClient("127.0.0.1:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	c := adapter.NewClient(proto.NewModuleServiceClient(conn), "fake")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	state, err := c.Get(ctx, "res-1")
	require.Error(t, err)
	assert.Nil(t, state)
}

// TestClient_Set_ModuleSideErrorInResponseBodyIsReturned verifies the
// highest-risk mapping: moduleSet (server.go) puts a module Set failure in
// SetResponse.Error rather than as a gRPC error. A client that only checked
// the gRPC error would record this as a successful apply.
func TestClient_Set_ModuleSideErrorInResponseBodyIsReturned(t *testing.T) {
	client := startFakeServer(t, &fakeModuleServer{
		setResp: &proto.SetResponse{Applied: false, Error: "permission denied writing resource"},
	})
	c := adapter.NewClient(client, "fake")

	err := c.Set(context.Background(), "res-1", &testConfigState{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied writing resource")
}

// TestClient_Set_AppliedFalseWithNoErrorIsTreatedAsFailure verifies the other
// half of the same mapping: Applied == false with an empty Error string must
// not be treated as success.
func TestClient_Set_AppliedFalseWithNoErrorIsTreatedAsFailure(t *testing.T) {
	client := startFakeServer(t, &fakeModuleServer{
		setResp: &proto.SetResponse{Applied: false},
	})
	c := adapter.NewClient(client, "fake")

	err := c.Set(context.Background(), "res-1", &testConfigState{})
	require.Error(t, err)
}

// TestClient_Set_TransportErrorIsReturned verifies a gRPC transport error from
// Set surfaces as an error.
func TestClient_Set_TransportErrorIsReturned(t *testing.T) {
	client := startFakeServer(t, &fakeModuleServer{
		setErr: status.Error(codes.Unavailable, "connection reset"),
	})
	c := adapter.NewClient(client, "fake")

	err := c.Set(context.Background(), "res-1", &testConfigState{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection reset")
}

// TestClient_Set_Success verifies the success path still works: Applied true
// with no Error returns nil.
func TestClient_Set_Success(t *testing.T) {
	client := startFakeServer(t, &fakeModuleServer{
		setResp: &proto.SetResponse{Applied: true},
	})
	c := adapter.NewClient(client, "fake")

	err := c.Set(context.Background(), "res-1", &testConfigState{})
	require.NoError(t, err)
}

// --- process-exited scenario: a real out-of-process module, killed, then called ---

// echoModuleBin is the path to the compiled echo_module binary shared by the
// process-exited test below. Built once by TestMain from the runtime
// package's own test fixture (features/steward/modules/runtime/testdata) —
// reused, not duplicated, since that fixture already implements exactly the
// minimal ModuleService contract this test needs.
var echoModuleBin string

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	dir, err := os.MkdirTemp("", "adapter-client-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "client_test: failed to create temp dir: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()

	suffix := ""
	if goruntime.GOOS == "windows" {
		suffix = ".exe"
	}
	echoModuleBin = filepath.Join(dir, "echo_module"+suffix)

	cmd := exec.Command("go", "build", "-o", echoModuleBin, "../../steward/modules/runtime/testdata/echo_module")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "client_test: failed to build echo_module: %s: %v\n", out, err)
		return 1
	}

	return m.Run()
}

// shortRuntimeDir mirrors runtime_test.go's shortBaseDir: a short temp dir so
// Unix socket paths built from it stay under the sun_path limit.
func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	if goruntime.GOOS == "windows" {
		return t.TempDir()
	}
	base, err := os.MkdirTemp("/tmp", "cfgms-adapter-rt-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

// TestClient_Get_ModuleProcessExited verifies that calling through the client
// adapter after the underlying module process has exited surfaces as an
// error, not a zero-valued successful ConfigState — exercised against a real
// forked module process via the real steward module runtime, not a stub.
func TestClient_Get_ModuleProcessExited(t *testing.T) {
	rt := runtime.NewModuleRuntime(shortRuntimeDir(t))
	b := &bundle.Bundle{
		Manifest: &featuremodules.ModuleMetadata{
			Name:      "echo",
			Version:   "0.1.0",
			Executors: []string{"steward"},
			Kind:      "steward",
			Publisher: "test",
		},
		ContentHash: "sha256-echo-test-hash",
		Binaries:    map[string]string{goruntime.GOOS + "-" + goruntime.GOARCH: echoModuleBin},
	}

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, nil)
	require.NoError(t, err)

	c := adapter.NewClient(handle.Client, "echo")

	// Confirm the module is genuinely alive before killing it. Calls the raw
	// proto client directly (bypassing the adapter under test) since
	// echo_module's Get returns a plain "echo:<id>" string, not YAML — fine
	// for the runtime package's own lifecycle tests, but not a shape the
	// adapter's Get is meant to parse.
	rawResp, err := handle.Client.Get(context.Background(), &proto.GetRequest{ResourceId: "res-1"})
	require.NoError(t, err)
	require.Equal(t, "echo:res-1", rawResp.GetConfigData())

	// Stop kills the process and waits for it to exit.
	require.NoError(t, rt.Stop(handle))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	state, err := c.Get(ctx, "res-1")
	require.Error(t, err, "Get against an exited module process must return an error")
	assert.Nil(t, state)
}

// testConfigState is a minimal modules.ConfigState used only to drive Set's
// ToYAML call in these tests.
type testConfigState struct{}

func (c *testConfigState) AsMap() map[string]interface{} { return map[string]interface{}{} }
func (c *testConfigState) ToYAML() ([]byte, error)       { return []byte("key: value\n"), nil }
func (c *testConfigState) FromYAML([]byte) error         { return nil }
func (c *testConfigState) Validate() error               { return nil }
func (c *testConfigState) GetManagedFields() []string    { return nil }
