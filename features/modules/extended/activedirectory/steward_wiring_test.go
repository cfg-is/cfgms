// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests that run the module through the real steward executor, module factory
// and credential client. Those packages import this module, so these tests
// live in the external test package.
package activedirectory_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/credentials"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/extended/activedirectory"
	stewardclient "github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

// recordingLogger keeps every message and key/value pair at every level.
type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) add(level, msg string, kv []interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, level+" "+msg+" "+fmt.Sprint(kv...))
}

func (l *recordingLogger) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *recordingLogger) Debug(m string, kv ...interface{}) { l.add("DEBUG", m, kv) }
func (l *recordingLogger) Info(m string, kv ...interface{})  { l.add("INFO", m, kv) }
func (l *recordingLogger) Warn(m string, kv ...interface{})  { l.add("WARN", m, kv) }
func (l *recordingLogger) Error(m string, kv ...interface{}) { l.add("ERROR", m, kv) }
func (l *recordingLogger) Fatal(m string, kv ...interface{}) { l.add("FATAL", m, kv) }
func (l *recordingLogger) DebugCtx(_ context.Context, m string, kv ...interface{}) {
	l.add("DEBUG", m, kv)
}
func (l *recordingLogger) InfoCtx(_ context.Context, m string, kv ...interface{}) {
	l.add("INFO", m, kv)
}
func (l *recordingLogger) WarnCtx(_ context.Context, m string, kv ...interface{}) {
	l.add("WARN", m, kv)
}
func (l *recordingLogger) ErrorCtx(_ context.Context, m string, kv ...interface{}) {
	l.add("ERROR", m, kv)
}
func (l *recordingLogger) FatalCtx(_ context.Context, m string, kv ...interface{}) {
	l.add("FATAL", m, kv)
}

// credentialServer serves IssueInitialCredential with a password from the
// controller's own generator.
type credentialServer struct {
	transportpb.UnimplementedStewardTransportServer
	password string
	mu       sync.Mutex
	requests []*transportpb.IssueInitialCredentialRequest
}

func (s *credentialServer) IssueInitialCredential(_ context.Context, req *transportpb.IssueInitialCredentialRequest) (*transportpb.IssueInitialCredentialResponse, error) {
	s.mu.Lock()
	s.requests = append(s.requests, req)
	s.mu.Unlock()
	return &transportpb.IssueInitialCredentialResponse{Password: s.password}, nil
}

// startCredentialTransport serves srv over an in-memory gRPC connection and
// returns the steward's real credential client bound to it.
func startCredentialTransport(t *testing.T, srv *credentialServer) modules.CredentialClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	transportpb.RegisterStewardTransportServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	tc := transportpb.NewStewardTransportClient(conn)
	return stewardclient.NewCredentialClient(func() transportpb.StewardTransportClient { return tc })
}

func newExecutor(t *testing.T, f *factory.ModuleFactory, logger logging.Logger, mode config.DriftMode) *execution.Executor {
	t.Helper()
	e, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:  logger,
		Factory: f,
		ErrorHandling: config.ErrorHandlingConfig{
			ModuleLoadFailure:  config.ActionFail,
			ResourceFailure:    config.ActionWarn,
			ConfigurationError: config.ActionFail,
		},
		DriftMode: mode,
	})
	require.NoError(t, err)
	return e
}

func newFactory(logger logging.Logger) *factory.ModuleFactory {
	return factory.New(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{
		ModuleLoadFailure:  config.ActionFail,
		ResourceFailure:    config.ActionWarn,
		ConfigurationError: config.ActionFail,
	}, logger)
}

func userResource(name, sam string) config.ResourceConfig {
	return config.ResourceConfig{
		Name:   name,
		Module: "activedirectory.user",
		Config: map[string]interface{}{
			"sam_account_name": sam,
			"display_name":     "J Doe",
			"ou":               "OU=Staff,DC=acme-corp,DC=example",
		},
	}
}

func TestSetUser_CreatesWithIssuedPasswordAndNeverLogsIt(t *testing.T) {
	password, err := credentials.GeneratePassword()
	require.NoError(t, err)
	srv := &credentialServer{password: password}
	client := startCredentialTransport(t, srv)

	logger := &recordingLogger{}
	d := activedirectory.NewFakeDirectory()
	stateDir := t.TempDir()
	module := activedirectory.NewTestModule(logger, d, stateDir, activedirectory.NewDeclaredSet())
	require.NoError(t, module.(modules.CredentialClientInjectable).SetCredentialClient(client))
	f := newFactory(logger)
	f.RegisterModule("activedirectory", module)
	e := newExecutor(t, f, logger, config.DriftModeApply)

	cfg := config.StewardConfig{Resources: []config.ResourceConfig{userResource("jdoe", "jdoe")}}
	report := e.ExecuteConfiguration(context.Background(), cfg)
	require.Equal(t, 1, report.SuccessfulCount, "report: %+v", report)

	// The user was created with the issued password, requested for the cfg
	// resource name and kind.
	_, created := d.Lookup("jdoe")
	require.True(t, created)
	assert.Equal(t, []string{password}, d.Passwords(), "the password reached the write script on stdin")
	require.Len(t, srv.requests, 1)
	assert.Equal(t, "jdoe", srv.requests[0].GetResourceId())
	assert.Equal(t, "activedirectory.user", srv.requests[0].GetKind())

	// A second pass is a no-op and requests nothing.
	report = e.ExecuteConfiguration(context.Background(), cfg)
	assert.Equal(t, 1, report.SuccessfulCount)
	assert.Len(t, srv.requests, 1)
	assert.Equal(t, []string{"create_user"}, d.WriteOps())

	// The password is nowhere: logs, errors, module state, inventory, or the
	// bindings file.
	var surfaces []string
	surfaces = append(surfaces, logger.all())
	surfaces = append(surfaces, report.Errors...)
	for _, r := range report.ResourceResults {
		surfaces = append(surfaces, r.Error, fmt.Sprint(r.StateDiff))
	}
	for _, id := range []string{"user:jdoe", "directory_user", "status"} {
		st, err := module.Get(context.Background(), id)
		require.NoError(t, err)
		surfaces = append(surfaces, fmt.Sprint(st.AsMap()))
		y, _ := st.ToYAML()
		surfaces = append(surfaces, string(y))
	}
	data, err := os.ReadFile(filepath.Join(stateDir, activedirectory.BindingFileName))
	require.NoError(t, err)
	surfaces = append(surfaces, string(data))
	for _, s := range surfaces {
		assert.NotContains(t, s, password)
	}
}

func TestManagedFlag_ExecutorAndSweepShareDeclaredSetViaFactory(t *testing.T) {
	t.Setenv("CFGMS_ACTIVEDIRECTORY_STATE_DIR", t.TempDir())
	d := activedirectory.NewFakeDirectory()
	activedirectory.UseFakeDirectory(t, d)
	asmith := d.AddUser("asmith")
	other := d.AddUser("other")

	managedFlags := func(t *testing.T, mod modules.Module) map[string]interface{} {
		t.Helper()
		st, err := mod.Get(context.Background(), "directory_user")
		require.NoError(t, err)
		out := map[string]interface{}{}
		objects, ok := st.AsMap()[modules.PerObjectKey].([]interface{})
		require.True(t, ok)
		for _, o := range objects {
			obj := o.(map[string]interface{})
			out[obj["id"].(string)] = obj["attrs"].(map[string]interface{})["managed"]
		}
		return out
	}

	run := func(t *testing.T, executorFactory, sweepFactory *factory.ModuleFactory) {
		e := newExecutor(t, executorFactory, logging.NewNoopLogger(), config.DriftModeMonitor)
		cfg := config.StewardConfig{Resources: []config.ResourceConfig{userResource("asmith", "asmith")}}
		e.ExecuteConfiguration(context.Background(), cfg)

		sweepModule, err := sweepFactory.LoadModule("activedirectory")
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{asmith: true, other: false}, managedFlags(t, sweepModule),
			"the sweep's instance sees the executor's declared set")

		// Removing the resource from the configuration clears the flag.
		e.ExecuteConfiguration(context.Background(), config.StewardConfig{})
		assert.Equal(t, map[string]interface{}{asmith: false, other: false}, managedFlags(t, sweepModule))
		assert.Empty(t, d.WriteOps(), "observing and monitoring never write")
	}

	t.Run("same factory", func(t *testing.T) {
		f := newFactory(logging.NewNoopLogger())
		run(t, f, f)
	})
	t.Run("executor and sweep factories", func(t *testing.T) {
		executorFactory := newFactory(logging.NewNoopLogger())
		sweepFactory := newFactory(logging.NewNoopLogger())
		executorModule, err := executorFactory.LoadModule("activedirectory")
		require.NoError(t, err)
		sweepModule, err := sweepFactory.LoadModule("activedirectory")
		require.NoError(t, err)
		require.NotSame(t, executorModule, sweepModule, "production shape: two different instances")
		run(t, executorFactory, sweepFactory)
	})
}

func TestMonitorMode_DoesNotCreate(t *testing.T) {
	t.Setenv("CFGMS_ACTIVEDIRECTORY_STATE_DIR", t.TempDir())
	d := activedirectory.NewFakeDirectory()
	activedirectory.UseFakeDirectory(t, d)
	srv := &credentialServer{password: "unused-Password-1"}

	f := newFactory(logging.NewNoopLogger())
	f.SetCredentialClient(startCredentialTransport(t, srv))
	e := newExecutor(t, f, logging.NewNoopLogger(), config.DriftModeMonitor)

	group := config.ResourceConfig{Name: "finance", Module: "activedirectory.group", Config: map[string]interface{}{
		"sam_account_name": "finance", "members_present": []interface{}{"asmith"},
	}}
	cfg := config.StewardConfig{Resources: []config.ResourceConfig{userResource("jdoe", "jdoe"), group}}
	report := e.ExecuteConfiguration(context.Background(), cfg)

	assert.Equal(t, 2, report.NonCompliantCount, "missing objects are reported as drift: %+v", report)
	assert.Empty(t, d.WriteOps(), "monitor mode runs no write script")
	assert.Empty(t, srv.requests, "monitor mode requests no password")
	_, exists := d.Lookup("jdoe")
	assert.False(t, exists)
}
