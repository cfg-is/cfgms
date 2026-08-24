// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// buildStorageRequirementsWiringPostgresDSN constructs a Postgres DSN from the
// same env vars used by the cluster storage tests.
func buildStorageRequirementsWiringPostgresDSN() string {
	pw := testutil.GetTestDBPassword()
	port := 5432
	if p := os.Getenv("CFGMS_TEST_DB_PORT"); p != "" {
		if pi, err := strconv.Atoi(p); err == nil {
			port = pi
		}
	}
	dbName := "cfgms_test"
	if v := os.Getenv("CFGMS_TEST_DB_NAME"); v != "" {
		dbName = v
	}
	dbUser := "cfgms_test"
	if v := os.Getenv("CFGMS_TEST_DB_USER"); v != "" {
		dbUser = v
	}
	return fmt.Sprintf("host=localhost port=%d dbname=%s user=%s password=%s sslmode=disable",
		port, dbName, dbUser, pw)
}

// skipStorageRequirementsWiringTestIfNoPostgres skips the test when Postgres is unreachable.
func skipStorageRequirementsWiringTestIfNoPostgres(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Postgres test in short mode")
	}
	dsn := buildStorageRequirementsWiringPostgresDSN()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skip("Postgres not available:", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skip("Postgres not reachable:", err)
	}
	return dsn
}

// TestResolveRegistrationWorkflow_MatchesHookSelection pins the workflow resolution
// that both New's hook switch and collectActiveStorageRequirements read. If these
// two diverge, a subsystem can be constructed without its store requirement having
// been validated — the exact gap Issue #3491 closes.
func TestResolveRegistrationWorkflow_MatchesHookSelection(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"nil config", nil, registrationWorkflowIPTrust},
		{"nil registration section", &config.Config{}, registrationWorkflowIPTrust},
		{"empty workflow defaults to ip-trust", &config.Config{Registration: &config.RegistrationConfig{}}, registrationWorkflowIPTrust},
		{"explicit ip-trust", &config.Config{Registration: &config.RegistrationConfig{Workflow: "ip-trust"}}, registrationWorkflowIPTrust},
		{"explicit manual-review", &config.Config{Registration: &config.RegistrationConfig{Workflow: "manual-review"}}, registrationWorkflowManualReview},
		{"legacy approval_mode alias", &config.Config{Registration: &config.RegistrationConfig{ApprovalMode: "manual-review"}}, registrationWorkflowManualReview},
		{"workflow wins over approval_mode", &config.Config{Registration: &config.RegistrationConfig{Workflow: "ip-trust", ApprovalMode: "manual-review"}}, registrationWorkflowIPTrust},
		{"auto-approve", &config.Config{Registration: &config.RegistrationConfig{Workflow: "auto-approve"}}, registrationWorkflowAutoApprove},
		{"unknown value passes through", &config.Config{Registration: &config.RegistrationConfig{Workflow: "bogus"}}, "bogus"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveRegistrationWorkflow(tc.cfg))
		})
	}
}

// TestCollectActiveStorageRequirements_ManualReviewDeclaresPendingStore verifies that
// the manual-review workflow contributes both registration declarations — the approval
// hook's (api.ManualReviewApprovalHookStoreRequirements) and the expiry job's
// (registration.StoreRequirements) — to the set New validates at startup.
func TestCollectActiveStorageRequirements_ManualReviewDeclaresPendingStore(t *testing.T) {
	for _, cfg := range []*config.Config{
		{Registration: &config.RegistrationConfig{Workflow: "manual-review"}},
		{Registration: &config.RegistrationConfig{ApprovalMode: "manual-review"}},
	} {
		reqs := collectActiveStorageRequirements(cfg)
		require.NotEmpty(t, reqs,
			"manual-review must declare its store requirements, else startup validation is a no-op")

		var registrationReqs []interfaces.StoreRequirement
		for _, req := range reqs {
			if req.Subsystem == "registration" {
				registrationReqs = append(registrationReqs, req)
			}
		}
		require.NotEmpty(t, registrationReqs,
			"manual-review must contribute its own requirements alongside push's unconditional one")

		for _, req := range registrationReqs {
			assert.Equal(t, interfaces.StoreNamePendingRegistration, req.Store)
			assert.Equal(t, interfaces.RequirementRequired, req.Severity,
				"manual-review cannot function without PendingRegistrationStore")
			assert.Equal(t, "registration", req.Subsystem,
				"subsystem name must be operator-readable in the startup error")
		}
	}
}

// TestCollectActiveStorageRequirements_InactiveWorkflowsDeclareNothing verifies the
// gate: a deployment that does not run the manual-review subsystem must not be
// blocked by its requirements. ip-trust and auto-approve never touch
// PendingRegistrationStore, so a provider that declines it must still start. Push's
// requirement is unconditional, so it is still present regardless of workflow.
func TestCollectActiveStorageRequirements_InactiveWorkflowsDeclareNothing(t *testing.T) {
	for _, cfg := range []*config.Config{
		nil,
		{},
		{Registration: &config.RegistrationConfig{}},
		{Registration: &config.RegistrationConfig{Workflow: "ip-trust"}},
		{Registration: &config.RegistrationConfig{Workflow: "auto-approve"}},
		{Registration: &config.RegistrationConfig{Workflow: "bogus"}},
	} {
		for _, req := range collectActiveStorageRequirements(cfg) {
			assert.NotEqual(t, "registration", req.Subsystem,
				"only manual-review requires PendingRegistrationStore")
		}
	}
}

// TestCollectActiveStorageRequirements_DecliningProviderBlocksManualReviewStartup
// exercises the wired set — not a hand-composed declaration — against a real
// cluster StorageManager whose "database" provider declined PendingRegistrationStore
// (via pkgtesting.SetupDecliningPendingRegistrationClusterStorage, composed through
// the real CreateClusterStorageManager path). This is the #3400 condition: before
// #3491 the collected set was empty, so ValidateStorageRequirements returned nil and
// the controller started with a substituted approval policy. Skipped when Postgres
// is unreachable.
func TestCollectActiveStorageRequirements_DecliningProviderBlocksManualReviewStartup(t *testing.T) {
	pgDSN := skipStorageRequirementsWiringTestIfNoPostgres(t)

	sm := pkgtesting.SetupDecliningPendingRegistrationClusterStorage(t, pgDSN)
	require.False(t, sm.HasStore(interfaces.StoreNamePendingRegistration),
		"a declining provider must leave PendingRegistrationStore absent from the composed manager")

	manualReview := &config.Config{Registration: &config.RegistrationConfig{Workflow: "manual-review"}}
	err := interfaces.ValidateStorageRequirements(sm, collectActiveStorageRequirements(manualReview))
	require.Error(t, err,
		"manual-review with no PendingRegistrationStore must fail closed at startup")
	assert.Contains(t, err.Error(), "registration")
	assert.Contains(t, err.Error(), string(interfaces.StoreNamePendingRegistration))

	ipTrust := &config.Config{Registration: &config.RegistrationConfig{Workflow: "ip-trust"}}
	require.NoError(t, interfaces.ValidateStorageRequirements(sm, collectActiveStorageRequirements(ipTrust)),
		"a workflow that never uses the store must not be blocked by its absence")
}

// newRegistrationWorkflowTestConfig builds a controller config that New can start,
// with the given registration workflow selected.
func newRegistrationWorkflowTestConfig(t *testing.T, workflow string) *config.Config {
	t.Helper()

	tempDir := t.TempDir()
	// cert.NewManager with StoragePath=tempDir stores the CA at tempDir/ca/;
	// CAPath is tempDir+"/ca" so loadExistingCertificateManager derives StoragePath=tempDir.
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Storage Requirements Test",
			Country:      "US",
			ValidityDays: 3650,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "failed to create test CA")

	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "storage-requirements-controller",
				Organization: "Storage Requirements Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		Storage:      createTestStorageConfig(tempDir, "storage-requirements"),
		Registration: &config.RegistrationConfig{Workflow: workflow},
	}
}

// TestServer_New_ManualReviewStartupValidatesPendingStore drives the real New()
// startup path (not a hand-composed StorageManager) with registration.workflow
// "manual-review": the OSS composite provider supplies PendingRegistrationStore, so
// startup validation passes and the manual-review hook plus the expiry job that
// sweeps its records are both wired. Any provider gap on this path now returns an
// error from New instead of silently substituting a different admission policy.
func TestServer_New_ManualReviewStartupValidatesPendingStore(t *testing.T) {
	cfg := newRegistrationWorkflowTestConfig(t, "manual-review")

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	// The requirements New validated must be the manual-review set, and the
	// composed StorageManager must satisfy them.
	reqs := collectActiveStorageRequirements(cfg)
	require.NotEmpty(t, reqs, "manual-review startup must validate a non-empty requirement set")
	require.NotNil(t, srv.storageManager)
	require.NoError(t, interfaces.ValidateStorageRequirements(srv.storageManager, reqs))

	assert.NotNil(t, srv.manualReviewHook,
		"manual-review hook must be wired, not replaced by a fallback approval policy")
	assert.NotNil(t, srv.pendingExpiryJob,
		"the expiry job that ages out manual-review records must be wired")
}

// TestServer_New_IPTrustStartupRequiresNoPendingStore is the counterpart gate check:
// the default workflow declares nothing, so startup is unaffected by the
// registration requirements and no manual-review hook is installed.
func TestServer_New_IPTrustStartupRequiresNoPendingStore(t *testing.T) {
	cfg := newRegistrationWorkflowTestConfig(t, "ip-trust")

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	for _, req := range collectActiveStorageRequirements(cfg) {
		assert.NotEqual(t, "registration", req.Subsystem,
			"ip-trust must impose no registration store requirement on the deployment")
	}
	assert.Nil(t, srv.manualReviewHook,
		"ip-trust must not install the manual-review hook")
}
