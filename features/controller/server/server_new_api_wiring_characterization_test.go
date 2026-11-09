// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/config"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
)

// Characterization tests for the data plane, config handler, health collector,
// installer blob store, platform monitor and HTTP API server region of New
// (Issue #5864). They pin the observable behavior of that region (what the
// returned Server holds, log lines, error text, check order and the Issue #4058
// close-once contract) so the region can be split into helpers without
// changing it. They reuse the servernewChar and servernewhatransportChar
// helpers of the sibling characterization files; every new helper, type and
// test here carries the servernewapiwiringChar prefix.
//
// Measured with go test -coverprofile before the refactor (the whole package's
// tests, New at 88.6% of statements), the branches of this region that remain
// uncovered cannot be reached from New with real components:
//   - the cluster-mode installer blob store branch: cluster mode needs a live
//     Postgres before New reaches this region (the storage stage refuses
//     first), so only the S3 factory call the branch makes is pinned;
//   - "gRPC data plane provider not registered" and a failing data plane
//     Initialize: the data plane registry has no unregister and panics on a
//     duplicate registration, so the registered provider cannot be replaced;
//   - the system collector failure warning, "failed to initialize system
//     monitor" and the content approval store error: they fail only on a
//     programming error in the inputs New itself builds;
//   - the entity graph configstore, tenantsync, correlator and DNA-sync writer
//     errors, and every NewBackgroundLoopLease error (entity graph, credential
//     expiry, M365 inventory, IP-trust and pending-registration expiry,
//     workflow trigger scheduler, manual-review expiry): they fail only when a
//     provider is nil or the HA manager rejects a fixed job name;
//   - the credential store/service and M365 inventory/convergence construction
//     errors, and the module trust store error: they fail only on invalid
//     inputs New has already validated in an earlier stage;
//   - the PendingRegistrationStore backstop of the manual-review workflow:
//     storage requirement validation refuses that composition first;
//   - a routing store wired to the API server (cluster mode only, needs
//     Postgres) and a git-sync syncer that fails to start.

// servernewapiwiringCharKeyHeader is the API key header the HTTP API reads.
const servernewapiwiringCharKeyHeader = "X-API-Key"

// servernewapiwiringCharHookLogger is a recordingLogger that runs a hook when
// an Info message is logged. It lets a test change the environment at an exact
// point of New, between two stages, without touching production code.
type servernewapiwiringCharHookLogger struct {
	*recordingLogger
	trigger string
	hook    func()
	fired   bool
}

func (l *servernewapiwiringCharHookLogger) Info(msg string, kvs ...interface{}) {
	l.recordingLogger.Info(msg, kvs...)
	if !l.fired && msg == l.trigger {
		l.fired = true
		l.hook()
	}
}

// servernewapiwiringCharStatusRequest performs GET /api/v1/ha/status against
// the Server's real HTTP router with a freshly generated test API key.
func servernewapiwiringCharStatusRequest(t *testing.T, cfg *config.Config) (*Server, api.HAStatusResponse) {
	t.Helper()
	keyBytes := make([]byte, 16)
	_, err := rand.Read(keyBytes)
	require.NoError(t, err)
	key := "servernew-api-wiring-" + hex.EncodeToString(keyBytes)
	t.Setenv("CFGMS_SEED_TEST_API_KEYS", "1")
	t.Setenv("CFGMS_API_KEY_EAST", key)

	srv := servernewCharNewServer(t, cfg, &recordingLogger{})
	require.NotNil(t, srv.httpServer)
	// The seeded key is scoped to the integration tenant; the assurance lookup
	// behind the permission check needs that tenant to exist.
	mustCreateTenantForWiring(t, srv.storageManager.GetTenantStore(), "test-tenant-integration", "test-tenant-integration", "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ha/status", nil)
	req.Header.Set(servernewapiwiringCharKeyHeader, key)
	rec := httptest.NewRecorder()
	srv.httpServer.GetRouter().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var status api.HAStatusResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&status))
	return srv, status
}

func TestServernewapiwiringChar_DataPlane(t *testing.T) {
	t.Run("without a transport no data plane or config handler is built", func(t *testing.T) {
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewCharConfig(t), logger)

		assert.Nil(t, srv.controlPlane)
		assert.Nil(t, srv.dataPlaneProvider)
		assert.Nil(t, srv.configHandler)
		assert.Empty(t, srv.signerCertSerial)
		assert.True(t, logger.containsAny("Transport config not set"))
		assert.False(t, logger.containsAny("Initializing gRPC data plane provider..."))
	})

	t.Run("with a transport the grpc data plane and the config handler are wired", func(t *testing.T) {
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewhatransportCharTransportConfig(t), logger)

		require.NotNil(t, srv.controlPlane)
		require.NotNil(t, srv.dataPlaneProvider)
		assert.Equal(t, "grpc", srv.dataPlaneProvider.Name())
		assert.Same(t, dataplaneInterfaces.GetProvider("grpc"), srv.dataPlaneProvider)
		assert.NotNil(t, srv.configHandler)
		assert.NotEmpty(t, srv.signerCertSerial, "the registration handler reports the boot signer serial")
		assert.True(t, logger.containsAny("Initializing gRPC data plane provider..."))
		assert.True(t, logger.containsAny("gRPC data plane provider initialized"))
		assert.False(t, logger.containsAny("Transport config not set"))
	})
}

func TestServernewapiwiringChar_HealthCollectors(t *testing.T) {
	t.Run("collectors are built and handed to the Server", func(t *testing.T) {
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewCharConfig(t), logger)

		assert.NotNil(t, srv.healthCollector)
		assert.NotNil(t, srv.alertManager)
		assert.NotNil(t, srv.healthTraceManager)
		assert.True(t, logger.containsAny("Health collectors initialized (Story #417)"))
	})

	t.Run("collectors are also built when a transport is configured", func(t *testing.T) {
		srv := servernewCharNewServer(t, servernewhatransportCharTransportConfig(t), &recordingLogger{})

		assert.NotNil(t, srv.healthCollector)
		assert.NotNil(t, srv.alertManager)
		assert.NotNil(t, srv.healthTraceManager)
	})
}

func TestServernewapiwiringChar_InstallerBlobStore(t *testing.T) {
	t.Run("single node uses a filesystem store rooted at the resolved path", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		logger := &recordingLogger{}
		servernewCharNewServer(t, cfg, logger)

		root := resolveInstallerBlobRoot(cfg)
		assert.DirExists(t, root)
		assert.True(t, logger.containsAny("Installer artifact blob store initialized"))
		assert.True(t, logger.containsAny(root))
		assert.False(t, logger.containsAny("Cluster mode: S3 installer blob store initialized"))
	})

	t.Run("an explicit blob root is used", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.BlobStorage.Root = filepath.Join(t.TempDir(), "explicit-installers")
		servernewCharNewServer(t, cfg, &recordingLogger{})

		assert.DirExists(t, cfg.BlobStorage.Root)
	})

	t.Run("a root that cannot be created is refused and closes the stores once", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		cfg := servernewCharConfig(t)
		file := filepath.Join(t.TempDir(), "not-a-directory")
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
		cfg.BlobStorage.Root = filepath.Join(file, "installers")
		logger := &recordingLogger{}

		srv, err := New(cfg, logger)
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize installer blob store: filesystem blob provider: failed to create root directory")
		assert.False(t, logger.containsAny("Installer artifact blob store initialized"))
		assert.False(t, logger.containsAny("HTTP API server initialized successfully"), "the API server is built after the blob store")
		assert.Equal(t, 1, counting.auditCloses)
	})

	t.Run("the cluster branch builds an S3 store from the installer S3 configuration", func(t *testing.T) {
		t.Setenv("CFGMS_S3_INSTALLER_BUCKET", "")
		t.Setenv("CFGMS_S3_INSTALLER_REGION", "")
		t.Setenv("CFGMS_S3_INSTALLER_ENDPOINT_URL", "")
		cfg := servernewCharConfig(t)
		cfg.HA = &config.HAConfig{Mode: "cluster"}
		cfg.Storage.Cluster = &config.ClusterStorageConfig{
			S3: map[string]interface{}{"bucket": "servernew-installers", "endpoint_url": "http://127.0.0.1:1"},
		}

		s3Cfg := installerS3Config(cfg)
		bucket, _ := s3Cfg["bucket"].(string)
		assert.Equal(t, "servernew-installers", bucket)
		store, err := blob.CreateBlobStoreFromConfig("s3", s3Cfg)
		require.NoError(t, err)
		assert.NotNil(t, store)
	})

	t.Run("the cluster branch without a bucket cannot build an S3 store", func(t *testing.T) {
		t.Setenv("CFGMS_S3_INSTALLER_BUCKET", "")
		cfg := servernewCharConfig(t)
		cfg.HA = &config.HAConfig{Mode: "cluster"}

		store, err := blob.CreateBlobStoreFromConfig("s3", installerS3Config(cfg))
		assert.Nil(t, store)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'bucket' is required")
	})
}

func TestServernewapiwiringChar_PlatformMonitor(t *testing.T) {
	srv := servernewCharNewServer(t, servernewCharConfig(t), &recordingLogger{})

	assert.NotNil(t, srv.systemMonitor)
}

func TestServernewapiwiringChar_APIServer(t *testing.T) {
	t.Run("the API server is built and wired to the optional capabilities the region owns", func(t *testing.T) {
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewCharConfig(t), logger)

		require.NotNil(t, srv.httpServer)
		assert.True(t, logger.containsAny("HTTP API server initialized successfully"))
		assert.NotNil(t, srv.stewardEventManager)
		assert.Same(t, srv.stewardEventManager, srv.httpServer.GetStewardEventLoggingManager())
		assert.NotNil(t, srv.httpServer.EntityGraphProvider())
		assert.NotNil(t, srv.httpServer.EntityGraphWatchProvider())
	})

	t.Run("the entity edge write path is the entity graph provider", func(t *testing.T) {
		srv := servernewCharNewServer(t, servernewCharConfig(t), &recordingLogger{})

		require.NotNil(t, srv.egProvider)
		assert.NotNil(t, srv.httpServer.EntityGraphWriteProvider())
		assert.Equal(t, srv.egProvider, srv.httpServer.EntityGraphWriteProvider())
		assert.NotNil(t, srv.egTenantSyncWriter)
		assert.NotNil(t, srv.egCorrelatorWriter)
		assert.NotNil(t, srv.egDNAWriter)
	})

	t.Run("with every optional capability present GET /api/v1/ha/status reports none absent", func(t *testing.T) {
		srv, status := servernewapiwiringCharStatusRequest(t, servernewCharConfig(t))

		assert.Equal(t, ha.SingleServerMode.String(), status.Mode)
		assert.Empty(t, status.AbsentCapabilities)
		assert.NotNil(t, srv.haManager)
	})

	t.Run("an absent optional capability is served by GET /api/v1/ha/status", func(t *testing.T) {
		original := pushStoreRequirements
		pushStoreRequirements = append(append([]interfaces.StoreRequirement{}, original...), interfaces.StoreRequirement{
			Subsystem:   "servernewapiwiring-char",
			Store:       interfaces.StoreName("ServernewapiwiringCharAbsentStore"),
			Severity:    interfaces.RequirementOptional,
			Consequence: "characterization capability is degraded (provider: flatfile)",
		})
		t.Cleanup(func() { pushStoreRequirements = original })

		_, status := servernewapiwiringCharStatusRequest(t, servernewCharConfig(t))

		require.Len(t, status.AbsentCapabilities, 1)
		absent := status.AbsentCapabilities[0]
		assert.Equal(t, "ServernewapiwiringCharAbsentStore", absent.Capability)
		assert.Equal(t, "servernewapiwiring-char", absent.Subsystem)
		assert.Equal(t, "flatfile", absent.Provider)
		assert.Equal(t, "characterization capability is degraded (provider: flatfile)", absent.Consequence)
	})

	t.Run("an absent optional capability is logged once at composition", func(t *testing.T) {
		original := pushStoreRequirements
		pushStoreRequirements = append(append([]interfaces.StoreRequirement{}, original...), interfaces.StoreRequirement{
			Subsystem:   "servernewapiwiring-char",
			Store:       interfaces.StoreName("ServernewapiwiringCharAbsentStore"),
			Severity:    interfaces.RequirementOptional,
			Consequence: "characterization capability is degraded",
		})
		t.Cleanup(func() { pushStoreRequirements = original })
		logger := &recordingLogger{}

		servernewCharNewServer(t, servernewCharConfig(t), logger)

		assert.True(t, logger.containsAny("Optional storage capability absent — deployment running in degraded mode"))
	})

	t.Run("a failure constructing the API server closes everything opened earlier", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		logger := &servernewapiwiringCharHookLogger{
			recordingLogger: &recordingLogger{},
			// The last message logged before api.New is called. Everything the
			// earlier stages need from the secrets environment is already
			// built, so withdrawing the key file now fails only the API
			// server's own secret store.
			trigger: "Installer artifact blob store initialized",
		}
		logger.hook = func() { t.Setenv("CFGMS_SECRETS_KEY_FILE", "") }

		srv, err := New(servernewCharConfig(t), logger)
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize HTTP API server: failed to initialize secret store:")
		assert.Contains(t, err.Error(), "CFGMS_SECRETS_KEY_FILE is required")
		assert.False(t, logger.containsAny("HTTP API server initialized successfully"))
		assert.Equal(t, 1, counting.auditCloses, "the stores opened before the API server must be closed exactly once")
	})

	t.Run("a failure after the API server is built closes the stores once", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		cfg := servernewCharConfig(t)
		cfg.DataDir = t.TempDir()
		// The steward event log directory is created right after the API
		// server; a regular file in its place makes that fail.
		require.NoError(t, os.WriteFile(filepath.Join(resolveDNADataRoot(cfg), "steward-events"), []byte("x"), 0o600))
		logger := &recordingLogger{}

		srv, err := New(cfg, logger)
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create steward event log directory")
		assert.True(t, logger.containsAny("HTTP API server initialized successfully"))
		assert.Equal(t, 1, counting.auditCloses)
	})
}

func TestServernewapiwiringChar_RegistrationApprovalHook(t *testing.T) {
	t.Run("ip-trust is the default and wires no manual-review hook", func(t *testing.T) {
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewCharConfig(t), logger)

		assert.Nil(t, srv.manualReviewHook)
		assert.True(t, logger.containsAny("IP-trust registration approval hook wired (Issue #1695)"))
	})

	t.Run("manual-review keeps its hook on the Server", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Registration = &config.RegistrationConfig{Workflow: "manual-review"}
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, cfg, logger)

		assert.NotNil(t, srv.manualReviewHook)
		assert.True(t, logger.containsAny("Manual-review registration approval hook wired (Issue #1599)"))
	})

	t.Run("auto-approve is wired with a deprecation warning", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Registration = &config.RegistrationConfig{Workflow: "auto-approve"}
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, cfg, logger)

		assert.Nil(t, srv.manualReviewHook)
		assert.True(t, logger.containsAny("registration.workflow 'auto-approve' is deprecated"))
		assert.True(t, logger.containsAny("auto-approve registration approval hook wired (deprecated)"))
	})

	t.Run("an unknown workflow falls back to ip-trust with a warning", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Registration = &config.RegistrationConfig{Workflow: "servernewapiwiring-unknown"}
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, cfg, logger)

		assert.Nil(t, srv.manualReviewHook)
		assert.True(t, logger.containsAny("Unknown registration.workflow value, defaulting to ip-trust (Issue #1695)"))
		assert.True(t, logger.containsAny("servernewapiwiring-unknown"))
	})
}

func TestServernewapiwiringChar_ModuleCacheAndGitSync(t *testing.T) {
	t.Run("a module cache is wired by default", func(t *testing.T) {
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewCharConfig(t), logger)

		assert.NotNil(t, srv.moduleCache)
		assert.NotNil(t, srv.observeManifestProvider)
		assert.NotNil(t, srv.httpServer.ModuleTrustStore())
		assert.True(t, logger.containsAny("Tier-2 observe manifest provider wired to module cache"))
	})

	t.Run("a module cache that cannot be created is not fatal and disables Tier-2", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		require.NoError(t, os.WriteFile(filepath.Join(resolveDNADataRoot(cfg), "module-cache"), []byte("x"), 0o600))
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, cfg, logger)

		assert.Nil(t, srv.moduleCache)
		assert.Nil(t, srv.observeManifestProvider)
		assert.True(t, logger.containsAny("Failed to initialize controller module cache; workflow modules will be unavailable"))
		assert.False(t, logger.containsAny("Tier-2 observe manifest provider wired to module cache"))
	})

	t.Run("git sync is wired only when a data directory is configured", func(t *testing.T) {
		without := servernewCharNewServer(t, servernewCharConfig(t), &recordingLogger{})
		assert.Nil(t, without.gitSyncer)
		assert.Nil(t, without.webhookHandler)

		cfg := servernewCharConfig(t)
		cfg.DataDir = t.TempDir()
		logger := &recordingLogger{}
		with := servernewCharNewServer(t, cfg, logger)
		assert.NotNil(t, with.gitSyncer)
		assert.NotNil(t, with.webhookHandler)
		assert.True(t, logger.containsAny("git-sync: syncer started"))
	})
}
