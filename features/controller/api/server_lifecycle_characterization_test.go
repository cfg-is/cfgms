// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// Characterization tests for New and Server.Close (Issue #5870). They pin what
// construction wires from its optional dependencies and the order and error text
// of Close's teardown, so both functions can be split without changing what a
// caller sees. Fixtures come from the existing tests in this package.

// serverlifecycleCharOpts selects the dependencies serverlifecycleCharNew hands to New.
type serverlifecycleCharOpts struct {
	logger     logging.Logger
	mutateCfg  func(*config.Config)
	withHealth bool
	noRoot     bool
}

// serverlifecycleCharNew builds a Server through New with the same fixtures as
// buildTestServer, but lets a test choose the logger, the config and whether the
// three health dependencies are present. The Server is closed on cleanup.
//
//duplication:justified features/controller/api/server_test.go -- buildTestServer and setupTestServerWithLogger fix every New argument, and the cases here need to vary the config, logger and health dependencies
func serverlifecycleCharNew(t *testing.T, o serverlifecycleCharOpts) (*Server, error) {
	t.Helper()
	setTestSecretsEnv(t)
	withDefaultEmbeddedSPA(t)

	cfg := config.DefaultConfig()
	cfg.ExternalURL = "https://localhost:8080"
	cfg.Certificate.EnableCertManagement = false
	if o.mutateCfg != nil {
		o.mutateCfg(cfg)
	}
	logger := o.logger
	if logger == nil {
		logger = logging.NewNoopLogger()
	}

	storageManager := pkgtesting.SetupTestStorage(t)
	rbacManager := rbac.NewManagerWithStorage(storageManager.GetAuditStore(), storageManager.GetRBACStore())
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)
	if !o.noRoot {
		seedTestRootTenant(t, tenantManager)
	}
	testTenantStores.Store(tenantManager, tenantStore)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)
	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	var collector *health.Collector
	var alerts health.AlertManager
	var traces health.TraceManager
	if o.withHealth {
		collector = health.NewCollector(nil, nil, nil, nil)
		alerts = health.NewAlertManager([]health.Threshold{}, health.SMTPConfig{})
		traces = health.NewTraceManager(time.Hour)
	}

	server, err := New(cfg, logger, controllerService, configService, nil, rbacService, nil,
		tenantManager, rbacManager, nil, nil, nil, "", collector, auditMgr, nil, nil, nil, alerts, traces)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Close(closeCtx); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	})
	return server, nil
}

func serverlifecycleCharMustNew(t *testing.T, o serverlifecycleCharOpts) *Server {
	t.Helper()
	server, err := serverlifecycleCharNew(t, o)
	require.NoError(t, err)
	return server
}

// serverlifecycleCharFreeAddr returns a loopback address whose port was free a
// moment ago. The metrics listener needs a fixed address (port 0 is rejected), so
// the port is released here and bound again by Start.
func serverlifecycleCharFreeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// serverlifecycleCharStartable builds a Server that Start can bind: ephemeral public
// port, a real certificate manager and a fixed-port metrics address.
func serverlifecycleCharStartable(t *testing.T) (*Server, string) {
	t.Helper()
	t.Setenv("CFGMS_HTTP_LISTEN_ADDR", "127.0.0.1:0")
	server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})
	metricsAddr := serverlifecycleCharFreeAddr(t)
	server.cfg.MetricsListenAddr = metricsAddr
	server.cfg.Certificate.EnableCertManagement = true
	server.certManager = newTLSTestCertManager(t)
	return server, metricsAddr
}

func serverlifecycleCharRequireBindable(t *testing.T, addr string) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	require.NoError(t, err, "the port must be free once Close returns")
	require.NoError(t, l.Close())
}

func serverlifecycleCharCloseCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ---- New ----

func TestServerlifecycleChar_New_NilConfig(t *testing.T) {
	server, err := New(nil, logging.NewNoopLogger(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "", nil, nil, nil, nil, nil, nil, nil)
	require.EqualError(t, err, "config cannot be nil")
	assert.Nil(t, server)
}

func TestServerlifecycleChar_New_SecretStoreFailure(t *testing.T) {
	_, err := serverlifecycleCharNew(t, serverlifecycleCharOpts{mutateCfg: func(c *config.Config) {
		t.Setenv("CFGMS_SECRETS_KEY_FILE", "")
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize secret store: ")
	assert.Contains(t, err.Error(), "CFGMS_SECRETS_KEY_FILE is required")
}

func TestServerlifecycleChar_New_HealthDetailHandler(t *testing.T) {
	t.Run("absent without the health dependencies", func(t *testing.T) {
		server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})
		assert.Nil(t, server.healthDetailHandler)
		assert.Nil(t, server.healthCollector)
	})

	t.Run("built when all three dependencies are present", func(t *testing.T) {
		server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{withHealth: true})
		assert.NotNil(t, server.healthDetailHandler)
		assert.NotNil(t, server.healthCollector)
	})
}

func TestServerlifecycleChar_New_HealthDetailHandlerNeedsAllThree(t *testing.T) {
	setTestSecretsEnv(t)
	withDefaultEmbeddedSPA(t)
	cfg := config.DefaultConfig()
	cfg.ExternalURL = "https://localhost:8080"
	collector := health.NewCollector(nil, nil, nil, nil)
	alerts := health.NewAlertManager([]health.Threshold{}, health.SMTPConfig{})
	traces := health.NewTraceManager(time.Hour)

	cases := []struct {
		name   string
		alerts health.AlertManager
		traces health.TraceManager
	}{
		{"missing alert manager", nil, traces},
		{"missing trace manager", alerts, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, err := New(cfg, logging.NewNoopLogger(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "",
				collector, nil, nil, nil, nil, tc.alerts, tc.traces)
			require.NoError(t, err)
			t.Cleanup(func() { _ = server.Close(context.Background()) })
			assert.Nil(t, server.healthDetailHandler)
		})
	}
}

func TestServerlifecycleChar_New_TrustedProxyCIDRs(t *testing.T) {
	t.Run("invalid CIDR is skipped with a warning and valid ones are kept", func(t *testing.T) {
		logger := &kvCapturingLogger{}
		server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{
			logger: logger,
			mutateCfg: func(c *config.Config) {
				c.Registration = &config.RegistrationConfig{
					TrustedProxies: []string{"10.0.0.0/8", "not-a-cidr", "192.168.0.0/16", "10.1.1.1/33"},
				}
			},
		})

		require.Len(t, server.trustedProxies, 2)
		assert.Equal(t, "10.0.0.0/8", server.trustedProxies[0].String())
		assert.Equal(t, "192.168.0.0/16", server.trustedProxies[1].String())

		var skipped []string
		for _, e := range logger.warnEntries() {
			if e.msg != "Invalid trusted_proxy CIDR, skipping" {
				continue
			}
			for i := 0; i+1 < len(e.kvs); i += 2 {
				if e.kvs[i] == "cidr" {
					skipped = append(skipped, e.kvs[i+1].(string))
				}
			}
		}
		assert.Equal(t, []string{"not-a-cidr", "10.1.1.1/33"}, skipped)
	})

	t.Run("no registration config yields no trusted proxies", func(t *testing.T) {
		server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{
			mutateCfg: func(c *config.Config) { c.Registration = nil },
		})
		assert.Empty(t, server.trustedProxies)
	})
}

func TestServerlifecycleChar_New_WiresServerState(t *testing.T) {
	server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})

	assert.NotNil(t, server.secretStore)
	assert.NotNil(t, server.authDefense)
	assert.NotNil(t, server.router)
	assert.NotNil(t, server.fleetQuery)
	assert.NotNil(t, server.apiKeyIdx)
	assert.NotNil(t, server.approvalHook)
	assert.NotNil(t, server.popVerifier)
	assert.NotNil(t, server.apiKeys)
	assert.Equal(t, defaultRolloutHaltPollInterval, server.rolloutHaltPollInterval)
	assert.Equal(t, defaultDecommissionTimeout, server.decommissionTimeout)

	// A nil HA manager yields singleton leases that always run.
	assert.NotNil(t, server.tenantCrossingExpirySweepLease)
	assert.NotNil(t, server.credentialRequestSweepLease)
	assert.NotNil(t, server.cliLoginSweepLease)
	assert.NotNil(t, server.cliPresenceSweepLease)

	// Every background goroutine is running: its Done channel is still open.
	for name, done := range map[string]chan struct{}{
		"api key cleanup":          server.cleanupDone,
		"credential-request sweep": server.credentialRequestSweepDone,
		"tenant-crossing sweep":    server.tenantCrossingExpirySweepDone,
		"cli-login sweep":          server.cliLoginSweepDone,
		"cli-presence sweep":       server.cliPresenceSweepDone,
		"webauthn sweep":           server.webAuthnCeremonySweepDone,
	} {
		select {
		case <-done:
			t.Fatalf("%s goroutine is not running after New", name)
		default:
		}
	}
}

func TestServerlifecycleChar_New_SeedTestAPIKeys(t *testing.T) {
	apiKey := func(server *Server, key string) *APIKey {
		server.mu.RLock()
		defer server.mu.RUnlock()
		return server.apiKeys[key]
	}

	t.Run("not seeded unless explicitly requested", func(t *testing.T) {
		t.Setenv("CFGMS_API_KEY_EAST", "lifecycle-char-east-unseeded")
		t.Setenv("CFGMS_API_KEY_INSTALLER", "lifecycle-char-installer-unseeded")
		t.Setenv("CFGMS_API_KEY_UPGRADE_TEST", "lifecycle-char-upgrade-unseeded")
		server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})
		assert.Nil(t, apiKey(server, "lifecycle-char-east-unseeded"))
		assert.Nil(t, apiKey(server, "lifecycle-char-installer-unseeded"))
		assert.Nil(t, apiKey(server, "lifecycle-char-upgrade-unseeded"))
	})

	t.Run("region, installer and upgrade keys when requested", func(t *testing.T) {
		t.Setenv("CFGMS_SEED_TEST_API_KEYS", "1")
		t.Setenv("CFGMS_API_KEY_EAST", "lifecycle-char-east")
		t.Setenv("CFGMS_API_KEY_WEST", "lifecycle-char-west")
		t.Setenv("CFGMS_API_KEY_INSTALLER", "lifecycle-char-installer")
		t.Setenv("CFGMS_API_KEY_UPGRADE_TEST", "lifecycle-char-upgrade")
		server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})

		east := apiKey(server, "lifecycle-char-east")
		require.NotNil(t, east)
		assert.Equal(t, "test-tenant-integration", east.TenantID)
		assert.Equal(t, []string{
			"steward:read", "steward:read-dna", "steward:auth-refresh",
			"config:push",
			"workflow:execute", "workflow:read",
			"ha:read-status", "ha:read-cluster", "ha:read-leader", "ha:read-nodes",
		}, east.Permissions)
		assert.NotNil(t, apiKey(server, "lifecycle-char-west"))
		assert.Nil(t, apiKey(server, "CFGMS_API_KEY_CENTRAL"), "an unset variable seeds nothing")

		installer := apiKey(server, "lifecycle-char-installer")
		require.NotNil(t, installer)
		assert.Equal(t, server.rootTenantID(context.Background()), installer.TenantID)
		assert.NotEmpty(t, installer.TenantID)
		assert.Equal(t, []string{"installer:upload", "installer:read", "installer:delete", "steward:list"}, installer.Permissions)

		upgrade := apiKey(server, "lifecycle-char-upgrade")
		require.NotNil(t, upgrade)
		assert.Equal(t, "fleet-root/fleet-child-a", upgrade.TenantID)
		assert.Equal(t, []string{"installer:publish:steward", "installer:dispatch:steward", "installer:read"}, upgrade.Permissions)
	})

	t.Run("installer key is not seeded without a root tenant", func(t *testing.T) {
		t.Setenv("CFGMS_SEED_TEST_API_KEYS", "1")
		t.Setenv("CFGMS_API_KEY_INSTALLER", "lifecycle-char-installer-noroot")
		logger := &kvCapturingLogger{}
		server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{noRoot: true, logger: logger})
		assert.Nil(t, apiKey(server, "lifecycle-char-installer-noroot"))
		var warned bool
		for _, e := range logger.warnEntries() {
			warned = warned || e.msg == "CFGMS_API_KEY_INSTALLER not seeded: no root tenant resolved"
		}
		assert.True(t, warned, "the missing root tenant must be logged")
	})

	t.Run("steward publisher key overrides the binary trust store", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		t.Setenv("CFGMS_SEED_TEST_API_KEYS", "1")
		t.Setenv("CFGMS_TEST_STEWARD_PUBLISHER_KEY", base64.StdEncoding.EncodeToString(pub))
		server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})
		assert.NotNil(t, server.stewardBinaryTrustStore)
		assert.True(t, server.testAutoApproveStewardBinaries)
	})

	t.Run("a malformed publisher key is ignored", func(t *testing.T) {
		t.Setenv("CFGMS_SEED_TEST_API_KEYS", "1")
		for name, value := range map[string]string{
			"not base64":  "%%%not-base64%%%",
			"wrong width": base64.StdEncoding.EncodeToString([]byte("short")),
		} {
			t.Run(name, func(t *testing.T) {
				t.Setenv("CFGMS_TEST_STEWARD_PUBLISHER_KEY", value)
				server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})
				assert.False(t, server.testAutoApproveStewardBinaries)
			})
		}
	})

	t.Run("publisher key is ignored unless seeding is requested", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		t.Setenv("CFGMS_TEST_STEWARD_PUBLISHER_KEY", base64.StdEncoding.EncodeToString(pub))
		server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})
		assert.False(t, server.testAutoApproveStewardBinaries)
	})
}

// ---- Close ----

// A New-built Server stops every goroutine it started: each Done channel closes.
func TestServerlifecycleChar_Close_StopsBackgroundGoroutines(t *testing.T) {
	server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})

	require.NoError(t, server.Close(serverlifecycleCharCloseCtx(t)))

	for name, done := range map[string]chan struct{}{
		"api key cleanup":          server.cleanupDone,
		"credential-request sweep": server.credentialRequestSweepDone,
		"tenant-crossing sweep":    server.tenantCrossingExpirySweepDone,
		"cli-login sweep":          server.cliLoginSweepDone,
		"cli-presence sweep":       server.cliPresenceSweepDone,
		"webauthn sweep":           server.webAuthnCeremonySweepDone,
	} {
		select {
		case <-done:
		default:
			t.Errorf("%s goroutine still running after Close", name)
		}
	}
}

func TestServerlifecycleChar_Close_TwiceIsSafe(t *testing.T) {
	server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})
	ctx := serverlifecycleCharCloseCtx(t)

	require.NoError(t, server.Close(ctx))
	require.NoError(t, server.Close(ctx))
	require.NoError(t, server.Stop())
}

// serverlifecycleCharStage is one once-guarded teardown step that waits for a
// goroutine: closing stop must be answered by closing done, and a done that never
// closes makes Close fail with msg once ctx expires.
type serverlifecycleCharStage struct {
	name string
	msg  string
	stop *chan struct{}
	done *chan struct{}
}

func serverlifecycleCharStages(s *Server) []serverlifecycleCharStage {
	return []serverlifecycleCharStage{
		{"cleanup", "api server close: timed out waiting for cleanup goroutine", &s.stopCleanup, &s.cleanupDone},
		{"credential-request sweep", "api server close: timed out waiting for credential-request sweep goroutine", &s.stopCredentialRequestSweep, &s.credentialRequestSweepDone},
		{"tenant-crossing sweep", "api server close: timed out waiting for tenant-crossing expiry sweep goroutine", &s.stopTenantCrossingExpirySweep, &s.tenantCrossingExpirySweepDone},
		{"cli-login sweep", "api server close: timed out waiting for cli-login sweep goroutine", &s.stopCliLoginSweep, &s.cliLoginSweepDone},
		{"cli-presence sweep", "api server close: timed out waiting for cli-presence sweep goroutine", &s.stopCliPresenceSweep, &s.cliPresenceSweepDone},
		{"webauthn sweep", "api server close: timed out waiting for WebAuthn ceremony sweep goroutine", &s.stopWebAuthnCeremonySweep, &s.webAuthnCeremonySweepDone},
	}
}

// serverlifecycleCharLiteral builds a *Server literal, as several tests in this
// package do, whose goroutines all answer their stop signal except the stages named
// in stalled. Stages after the cleanup goroutine are nil-guarded in Close, so
// the literal only allocates them when withSweeps is true.
func serverlifecycleCharLiteral(withSweeps bool, stalled ...string) *Server {
	s := &Server{logger: logging.NewNoopLogger()}
	s.stopCleanup, s.cleanupDone = make(chan struct{}), make(chan struct{})
	if withSweeps {
		s.stopCredentialRequestSweep, s.credentialRequestSweepDone = make(chan struct{}), make(chan struct{})
		s.stopTenantCrossingExpirySweep, s.tenantCrossingExpirySweepDone = make(chan struct{}), make(chan struct{})
		s.stopCliLoginSweep, s.cliLoginSweepDone = make(chan struct{}), make(chan struct{})
		s.stopCliPresenceSweep, s.cliPresenceSweepDone = make(chan struct{}), make(chan struct{})
		s.stopWebAuthnCeremonySweep, s.webAuthnCeremonySweepDone = make(chan struct{}), make(chan struct{})
	}
	for _, st := range serverlifecycleCharStages(s) {
		stalledStage := false
		for _, name := range stalled {
			stalledStage = stalledStage || name == st.name
		}
		if stalledStage || *st.stop == nil {
			continue
		}
		stop, done := *st.stop, *st.done
		go func() {
			<-stop
			close(done)
		}()
	}
	return s
}

func serverlifecycleCharShortCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func TestServerlifecycleChar_Close_LiteralServerSkipsUnsetSweeps(t *testing.T) {
	s := serverlifecycleCharLiteral(false)
	require.NoError(t, s.Close(serverlifecycleCharCloseCtx(t)))
}

func TestServerlifecycleChar_Close_GoroutineTimeouts(t *testing.T) {
	probe := serverlifecycleCharLiteral(true)
	for _, st := range serverlifecycleCharStages(probe) {
		t.Run(st.name, func(t *testing.T) {
			s := serverlifecycleCharLiteral(true, st.name)
			err := s.Close(serverlifecycleCharShortCtx(t))
			require.Error(t, err)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Contains(t, err.Error(), st.msg)
		})
	}
}

func TestServerlifecycleChar_Close_FirstErrorWins(t *testing.T) {
	s := serverlifecycleCharLiteral(true, "cleanup", "cli-login sweep", "webauthn sweep")
	err := s.Close(serverlifecycleCharShortCtx(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out waiting for cleanup goroutine")
	assert.NotContains(t, err.Error(), "cli-login")
	assert.NotContains(t, err.Error(), "WebAuthn")
}

func TestServerlifecycleChar_Close_WaitsForInFlightWork(t *testing.T) {
	t.Run("break-glass notifications", func(t *testing.T) {
		s := serverlifecycleCharLiteral(true)
		s.crossingNotifyWG.Add(1)
		defer s.crossingNotifyWG.Done()
		err := s.Close(serverlifecycleCharShortCtx(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api server close: timed out waiting for break-glass notifications")
	})

	t.Run("cert-binding last-used persistence", func(t *testing.T) {
		s := serverlifecycleCharLiteral(true)
		s.certBindingLastUsedWG.Add(1)
		defer s.certBindingLastUsedWG.Done()
		err := s.Close(serverlifecycleCharShortCtx(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api server close: timed out waiting for cert-binding last-used persistence")
	})

	t.Run("api key index scans", func(t *testing.T) {
		s := serverlifecycleCharLiteral(true)
		s.apiKeyIndexWG.Add(1)
		defer s.apiKeyIndexWG.Done()
		err := s.Close(serverlifecycleCharShortCtx(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api server close: timed out waiting for cert-binding last-used persistence")
	})

	t.Run("a goroutine that finishes during Close does not fail it", func(t *testing.T) {
		s := serverlifecycleCharLiteral(true)
		s.crossingNotifyWG.Add(1)
		go func() {
			time.Sleep(50 * time.Millisecond)
			s.crossingNotifyWG.Done()
		}()
		require.NoError(t, s.Close(serverlifecycleCharCloseCtx(t)))
	})
}

func TestServerlifecycleChar_Close_StopsDeliveryServer(t *testing.T) {
	s := serverlifecycleCharLiteral(true)
	s.deliveryGRPCServer = grpc.NewServer()
	require.NoError(t, s.Close(serverlifecycleCharCloseCtx(t)))
}

// serverlifecycleCharBlockedHTTPServer returns an http.Server that is serving one
// request which never completes, so Shutdown can only end by ctx expiring.
func serverlifecycleCharBlockedHTTPServer(t *testing.T) *http.Server {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	})}
	go func() { _ = srv.Serve(l) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	require.NoError(t, err)
	<-entered
	t.Cleanup(func() {
		close(release)
		_ = conn.Close()
		_ = srv.Close()
	})
	return srv
}

func TestServerlifecycleChar_Close_HTTPShutdownFailures(t *testing.T) {
	cases := []struct {
		name   string
		attach func(*Server, *http.Server)
		logMsg string
	}{
		{"public API", func(s *Server, h *http.Server) { s.httpServer = h }, "Failed to shutdown HTTP server gracefully"},
		{"private metrics", func(s *Server, h *http.Server) { s.metricsHTTPServer = h }, "Failed to shutdown private metrics server gracefully"},
		{"private Raft", func(s *Server, h *http.Server) { s.internalHTTPServer = h }, "Failed to shutdown private Raft server gracefully"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger := &errorCapturingLogger{}
			s := serverlifecycleCharLiteral(true)
			s.logger = logger
			tc.attach(s, serverlifecycleCharBlockedHTTPServer(t))

			err := s.Close(serverlifecycleCharShortCtx(t))
			require.Error(t, err)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			logger.mu.Lock()
			defer logger.mu.Unlock()
			require.Len(t, logger.entries, 1)
			assert.Equal(t, tc.logMsg, logger.entries[0].msg)
		})
	}
}

// ---- Close and the listeners Start creates ----

// Start, Close, Start again: the second Start binds the same fixed metrics port,
// and the second Close (whose once-guarded body no longer runs) still releases it.
func TestServerlifecycleChar_StartCloseStart_RebindsFixedMetricsPort(t *testing.T) {
	server, metricsAddr := serverlifecycleCharStartable(t)
	ctx := serverlifecycleCharCloseCtx(t)

	require.NoError(t, server.Start())
	require.NoError(t, server.Close(ctx))

	err := server.Start()
	require.NoError(t, err, "second Start must not fail with address already in use")
	assert.NotNil(t, server.metricsTLSListener)
	assert.Equal(t, metricsAddr, server.metricsTLSListener.Addr().String())

	require.NoError(t, server.Close(ctx))
	serverlifecycleCharRequireBindable(t, metricsAddr)
}

// A Start followed at once by Close leaves no listener open and forgets the ones it closed.
func TestServerlifecycleChar_StartThenImmediateClose_ReleasesListeners(t *testing.T) {
	server, metricsAddr := serverlifecycleCharStartable(t)

	require.NoError(t, server.Start())
	publicAddr := server.publicTLSListener.Addr().String()
	require.NoError(t, server.Close(serverlifecycleCharCloseCtx(t)))

	server.mu.Lock()
	assert.Nil(t, server.publicTLSListener)
	assert.Nil(t, server.metricsTLSListener)
	assert.Nil(t, server.internalTLSListener)
	server.mu.Unlock()
	serverlifecycleCharRequireBindable(t, metricsAddr)
	serverlifecycleCharRequireBindable(t, publicAddr)
}

// Listeners installed after the once-guarded teardown has already run are still
// closed by a later Close: that is why the listener close sits outside the once.
func TestServerlifecycleChar_Close_ClosesListenersOutsideOnce(t *testing.T) {
	server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})
	ctx := serverlifecycleCharCloseCtx(t)
	require.NoError(t, server.Close(ctx))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	server.mu.Lock()
	server.metricsTLSListener = l
	server.mu.Unlock()

	require.NoError(t, server.Close(ctx))

	server.mu.Lock()
	assert.Nil(t, server.metricsTLSListener)
	server.mu.Unlock()
	_, acceptErr := l.Accept()
	require.Error(t, acceptErr, "the listener must be closed by the second Close")
	serverlifecycleCharRequireBindable(t, addr)
}

// A Server that never started has no listeners to close.
func TestServerlifecycleChar_Close_WithoutStartHasNoListeners(t *testing.T) {
	server := serverlifecycleCharMustNew(t, serverlifecycleCharOpts{})
	require.NoError(t, server.Close(serverlifecycleCharCloseCtx(t)))
	assert.Nil(t, server.publicTLSListener)
	assert.Nil(t, server.metricsTLSListener)
	assert.Nil(t, server.internalTLSListener)
}

// A delivery RPC that never completes holds GracefulStop past ctx: Close reports
// the timeout instead of hanging, and the hard Stop released in the background
// ends the RPC.
func TestServerlifecycleChar_Close_DeliveryServerDrainTimeout(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	entered := make(chan struct{})
	deliveryServer := grpc.NewServer(grpc.UnknownServiceHandler(func(_ interface{}, stream grpc.ServerStream) error {
		close(entered)
		<-stream.Context().Done()
		return stream.Context().Err()
	}))
	go func() { _ = deliveryServer.Serve(l) }()

	conn, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	clientStream, err := conn.NewStream(context.Background(), &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/lifecycle.char/Block")
	require.NoError(t, err)
	require.NoError(t, clientStream.SendMsg(&emptypb.Empty{}))
	<-entered

	s := serverlifecycleCharLiteral(true)
	s.deliveryGRPCServer = deliveryServer
	err = s.Close(serverlifecycleCharShortCtx(t))
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "api server close: timed out stopping internal delivery server")
}
