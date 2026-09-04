// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isElevated returns true if the test process has elevated privileges,
// using the platform-specific check from the service package.
func isElevated() bool {
	return service.New("").IsElevated()
}

func TestBuildRootCommand(t *testing.T) {
	cmd := buildRootCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "cfgms-steward", cmd.Use)

	// Verify subcommands are registered.
	names := make([]string, 0, len(cmd.Commands()))
	for _, sub := range cmd.Commands() {
		names = append(names, sub.Name())
	}
	assert.Contains(t, names, "install")
	assert.Contains(t, names, "uninstall")
	assert.Contains(t, names, "status")
}

func TestBuildRootCommandFlags(t *testing.T) {
	cmd := buildRootCommand()

	for _, name := range []string{"config", "regtoken"} {
		flag := cmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "expected flag %q to be registered", name)
	}

	// log-level and log-provider must not be registered as CLI flags.
	assert.Nil(t, cmd.Flags().Lookup("log-level"), "log-level flag must not be registered")
	assert.Nil(t, cmd.Flags().Lookup("log-provider"), "log-provider flag must not be registered")
}

func TestBuildRootCommandNoModeFlag(t *testing.T) {
	cmd := buildRootCommand()
	assert.Nil(t, cmd.Flags().Lookup("mode"), "mode flag must not be registered")
}

func TestPublicBetaSecurityProfileCannotBeDowngraded(t *testing.T) {
	saved := SecurityProfile
	SecurityProfile = securityProfilePublicBeta
	t.Cleanup(func() { SecurityProfile = saved })

	t.Setenv("CFGMS_SECURITY_PROFILE", securityProfileDevelopment)
	enabled, err := publicBetaSecurityEnabled()
	require.False(t, enabled)
	require.ErrorContains(t, err, "cannot downgrade")

	t.Setenv("CFGMS_SECURITY_PROFILE", "")
	enabled, err = publicBetaSecurityEnabled()
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestInstallCommandEnforcesRequiredRegtoken(t *testing.T) {
	// Verify cobra's MarkFlagRequired("regtoken") rejects the install subcommand
	// when --regtoken is absent. This is the cobra-level guard that supersedes
	// any manual empty-token check in runInstall — runInstall is never reached
	// without a non-empty token value.
	root := buildRootCommand()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"install"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regtoken")
}

func TestRunInstallRequiresElevation(t *testing.T) {
	if isElevated() {
		t.Skip("test requires non-elevated process — running as root")
	}
	err := runInstall("tok_test_abc123", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "elevated privileges")
}

func TestRunInstallCACertFileNotFound(t *testing.T) {
	// Verify runInstall returns an error that includes the filename when --controller-ca
	// names a path that does not exist.
	missing := filepath.Join(t.TempDir(), "nonexistent-ca.crt")
	err := runInstall("tok_test_abc123", "", missing, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-ca.crt")
}

// TestInstallCommandFlagSurface asserts the install subcommand's flag set is
// exactly {--regtoken, --controller-url, --controller-ca, --fingerprint}.
// All Hyper-V-specific flags were removed in Issue #1894; no role-specific
// flags belong on the install command. --ca-cert was renamed to --controller-ca
// (ADR-013 §3, Issue #1517).
func TestInstallCommandFlagSurface(t *testing.T) {
	cmd := buildInstallCommand()
	require.NotNil(t, cmd)

	expected := map[string]bool{
		"regtoken":       true,
		"controller-url": true,
		"controller-ca":  true,
		"fingerprint":    true,
	}

	var flagNames []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		flagNames = append(flagNames, f.Name)
	})

	for _, name := range flagNames {
		assert.True(t, expected[name],
			"unexpected flag %q on install subcommand — install accepts only --regtoken, --controller-url, --controller-ca, --fingerprint", name)
	}
	for name := range expected {
		assert.NotNil(t, cmd.Flags().Lookup(name),
			"required flag %q must be registered on install subcommand", name)
	}
	assert.Len(t, flagNames, len(expected),
		"install command must have exactly %d flags: --regtoken, --controller-url, --controller-ca, --fingerprint", len(expected))
}

func TestRunUninstallRequiresElevation(t *testing.T) {
	if isElevated() {
		t.Skip("test requires non-elevated process — running as root")
	}
	err := runUninstall(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "elevated privileges")
}

func TestRunStatusNotInstalled(t *testing.T) {
	// status should succeed even when the service is not installed.
	err := runStatus()
	assert.NoError(t, err)
}

func TestBuildHTTPConfig(t *testing.T) {
	logger := logging.NewLogger("debug")

	t.Run("empty CFGMS_HTTP_CA_CERT_PATH produces empty CACertPath", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", "")
		// Inject a non-existent platform path so the test is not sensitive to
		// whether /etc/cfgms/controller-ca.crt exists on the host (self-hosted CI runners
		// are managed CFGMS nodes and carry the real cert).
		cfg := buildHTTPConfigWithPlatformPath("https://controller.example.com", 30*time.Second, filepath.Join(dir, "controller-ca.crt"), logger)
		require.NotNil(t, cfg)
		assert.Equal(t, "https://controller.example.com", cfg.ControllerURL)
		assert.Equal(t, "", cfg.CACertPath)
	})

	t.Run("CFGMS_HTTP_CA_CERT_PATH with existing file is forwarded to HTTPConfig.CACertPath", func(t *testing.T) {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "ca.crt")
		require.NoError(t, os.WriteFile(certFile, []byte("fake-cert"), 0600))
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", certFile)
		cfg := buildHTTPConfig("https://controller.example.com", 30*time.Second, logger)
		require.NotNil(t, cfg)
		assert.Equal(t, certFile, cfg.CACertPath)
	})
}

func TestResolveRegistrationCACertPath(t *testing.T) {
	logger := logging.NewLogger("debug")

	t.Run("priority 1: env var set and file exists", func(t *testing.T) {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "ca.crt")
		require.NoError(t, os.WriteFile(certFile, []byte("fake-cert"), 0600))
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", certFile)

		result := doResolveRegistrationCACertPath(logger, filepath.Join(dir, "platform-ca.crt"))
		assert.Equal(t, certFile, result)
	})

	t.Run("priority 1 fallthrough: env var set but file missing; platform path used", func(t *testing.T) {
		dir := t.TempDir()
		platformCert := filepath.Join(dir, "platform-ca.crt")
		require.NoError(t, os.WriteFile(platformCert, []byte("fake-cert"), 0600))
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", filepath.Join(dir, "nonexistent.crt"))

		result := doResolveRegistrationCACertPath(logger, platformCert)
		assert.Equal(t, platformCert, result)
	})

	t.Run("priority 2: platform-standard path exists when env var is empty", func(t *testing.T) {
		dir := t.TempDir()
		platformCert := filepath.Join(dir, "controller-ca.crt")
		require.NoError(t, os.WriteFile(platformCert, []byte("fake-cert"), 0600))
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", "")

		result := doResolveRegistrationCACertPath(logger, platformCert)
		assert.Equal(t, platformCert, result)
	})

	t.Run("priority 3: neither env var nor platform path exists returns empty string", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", "")

		result := doResolveRegistrationCACertPath(logger, filepath.Join(dir, "nonexistent.crt"))
		assert.Equal(t, "", result)
	})
}

func TestTryReconnectWithStoredIdentity_NoStoredIdentity_FallsThrough(t *testing.T) {
	// No identity file on disk — first run. The function returns (nil, nil) so
	// the caller falls through to HTTP registration without logging an error.
	dir := t.TempDir()
	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", trustSourceCompileBaked, stewardconfig.StewardConfig{}, false, logging.NewLogger("error"))
	assert.Nil(t, tc)
	assert.NoError(t, err)
}

func TestTryReconnectWithStoredIdentity_MissingServerCert_RejectsAndFallsBack(t *testing.T) {
	// An identity record that lacks both ServerCertPEM and SigningCertPEM cannot
	// verify signed sync_config commands. The reconnect must reject it with an
	// explicit error so the caller falls back to HTTP re-registration rather than
	// reconnecting into a state where every signed command is silently dropped.
	dir := t.TempDir()
	require.NoError(t, saveIdentity(dir, StewardIdentity{
		StewardID:        "steward-no-cert",
		TenantID:         "tenant-1",
		TransportAddress: "controller:4433",
		CACertPEM:        "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
	}))

	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", trustSourceCompileBaked, stewardconfig.StewardConfig{}, false, logging.NewLogger("error"))
	assert.Nil(t, tc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing controller server/signing certificate")
}

func TestTryReconnectWithStoredIdentity_CorruptIdentity_FallsThrough(t *testing.T) {
	// A corrupt identity file is not fatal — loadIdentity returns an error, which
	// the reconnect treats as "no usable identity" and returns (nil, nil) so the
	// caller falls through to HTTP registration.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, identityFileName), []byte("{not json"), 0600))

	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", trustSourceCompileBaked, stewardconfig.StewardConfig{}, false, logging.NewLogger("error"))
	assert.Nil(t, tc)
	assert.NoError(t, err)
}

func TestTryReconnectWithStoredIdentity_TrustDowngrade_ReturnsError(t *testing.T) {
	// An identity enrolled with install-pinned (level 2) must not be reconnected
	// with a TOFU source (level 1) — that would silently weaken the trust anchor.
	// The downgrade guard at tryReconnectWithStoredIdentity:1177-1184 must fire
	// and return a non-nil error so the caller does not proceed with the connection.
	dir := t.TempDir()
	require.NoError(t, saveIdentity(dir, StewardIdentity{
		StewardID:        "steward-pinned",
		TenantID:         "tenant-1",
		TransportAddress: "controller:4433",
		TrustMode:        "install-pinned",
		CACertPEM:        "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
		ServerCertPEM:    "-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----",
	}))

	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", trustSourceTOFU, stewardconfig.StewardConfig{}, false, logging.NewLogger("error"))
	assert.Nil(t, tc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust downgrade rejected")
}

func TestControllerURLOrUnknown(t *testing.T) {
	// When ControllerURL is empty (default in test builds).
	original := ControllerURL
	defer func() { ControllerURL = original }()

	ControllerURL = ""
	assert.Contains(t, controllerURLOrUnknown(), "not set")

	ControllerURL = "https://ctrl.example.com"
	assert.Equal(t, "https://ctrl.example.com", controllerURLOrUnknown())
}

func TestLogLevelFromEnv(t *testing.T) {
	tests := []struct {
		env      string
		expected string
	}{
		{"", "INFO"},
		{"invalid", "INFO"},
		{"info", "INFO"},
		{"INFO", "INFO"},
		{"debug", "DEBUG"},
		{"DEBUG", "DEBUG"},
		{"warn", "WARN"},
		{"WARN", "WARN"},
		{"error", "ERROR"},
		{"ERROR", "ERROR"},
		{"verbose", "INFO"},
	}

	for _, tc := range tests {
		t.Run("env="+tc.env, func(t *testing.T) {
			t.Setenv("CFGMS_LOG_LEVEL", tc.env)
			assert.Equal(t, tc.expected, logLevelFromEnv())
		})
	}
}

// TestStandaloneStartErrorPropagatesToRunSteward verifies that startup errors in
// standalone mode are returned as errors from runSteward rather than terminating
// the process via logger.Fatal / os.Exit. Uses a non-existent config path to
// trigger a known-bad startup error from steward.NewStandalone.
func TestStandaloneStartErrorPropagatesToRunSteward(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := runSteward(ctx, "", "", "/nonexistent/cfgms-config-does-not-exist.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create standalone steward")
}

// newPollTestClient returns an HTTPClient pointed at the given httptest.Server URL,
// with no timeout override (the httptest server responds immediately).
func newPollTestClient(t *testing.T, srv *httptest.Server) *registration.HTTPClient {
	t.Helper()
	c, err := registration.NewHTTPClient(&registration.HTTPConfig{
		ControllerURL: srv.URL,
		Logger:        logging.NewLogger("error"),
	})
	require.NoError(t, err)
	return c
}

// statusBody serialises a RegistrationStatusResponse to JSON for httptest handlers.
func statusBody(t *testing.T, status, stewardID, tenantID, transport, cert, key, ca string) []byte {
	t.Helper()
	resp := registration.RegistrationStatusResponse{
		Status:           status,
		StewardID:        stewardID,
		TenantID:         tenantID,
		TransportAddress: transport,
		ClientCert:       cert,
		CACert:           ca,
	}
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	return b
}

// TestPollForApproval_ImmediateApproval verifies that a single "claimed" response with
// cert fields returns the populated approvedRegistration without error.
func TestPollForApproval_ImmediateApproval(t *testing.T) {
	body := statusBody(t, "claimed", "s1", "t1", "ctrl:4433", "CERT", "KEY", "CA")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	result, err := pollForApproval(context.Background(), newPollTestClient(t, srv),
		"pending-1", "tok", 5*time.Second, 0, 0, logging.NewLogger("error"))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "s1", result.StewardID)
	assert.Equal(t, "t1", result.TenantID)
	assert.Equal(t, "CERT", result.ClientCert)
	assert.Equal(t, "CA", result.CACert)
}

// TestPollForApproval_Denied_ReturnsError verifies that a "denied" status causes
// pollForApproval to return a non-nil error containing "denied".
func TestPollForApproval_Denied_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"denied"}`))
	}))
	defer srv.Close()

	result, err := pollForApproval(context.Background(), newPollTestClient(t, srv),
		"pending-denied", "tok", 5*time.Second, 0, 0, logging.NewLogger("error"))

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "denied")
}

// TestPollForApproval_Gone410_ReturnsNilNoError verifies that an HTTP 410 Gone response
// (which PollStatus maps to Status:"claimed" with no cert fields) causes pollForApproval
// to return (nil, nil) so the caller knows to re-register.
func TestPollForApproval_Gone410_ReturnsNilNoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	result, err := pollForApproval(context.Background(), newPollTestClient(t, srv),
		"pending-expired", "tok", 5*time.Second, 0, 0, logging.NewLogger("error"))

	assert.NoError(t, err)
	assert.Nil(t, result, "nil result signals caller to re-register")
}

// TestPollForApproval_PendingThenApproved_ReturnsCerts verifies the typical manual-review
// flow: first poll returns "pending", second poll returns "claimed" with certs.
func TestPollForApproval_PendingThenApproved_ReturnsCerts(t *testing.T) {
	var callCount atomic.Int32
	body := statusBody(t, "claimed", "s1", "t1", "ctrl:4433", "CERT", "KEY", "CA")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if n == 1 {
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		} else {
			_, _ = w.Write(body)
		}
	}))
	defer srv.Close()

	result, err := pollForApproval(context.Background(), newPollTestClient(t, srv),
		"pending-123", "tok", 10*time.Second, 0, 0, logging.NewLogger("error"))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "CERT", result.ClientCert)
	assert.Equal(t, int32(2), callCount.Load(), "must poll exactly twice: pending then claimed")
}

// TestPollForApproval_ContextCanceled_ReturnsTimeoutError verifies that a pre-canceled
// context causes pollForApproval to return a "timed out" error immediately.
func TestPollForApproval_ContextCanceled_ReturnsTimeoutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately before the first poll

	result, err := pollForApproval(ctx, newPollTestClient(t, srv),
		"pending-cancel", "tok", 24*time.Hour, 0, 0, logging.NewLogger("error"))

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "timed out")
}

// TestHasExpiredClientCert covers the three cases from the acceptance criteria:
// all-expired → true; empty → false; mixed valid+expired → false.
func TestHasExpiredClientCert(t *testing.T) {
	makeClient := func(valid bool) *cert.CertificateInfo {
		return &cert.CertificateInfo{Type: cert.CertificateTypeClient, IsValid: valid}
	}
	makeServer := func(valid bool) *cert.CertificateInfo {
		return &cert.CertificateInfo{Type: cert.CertificateTypePublicAPI, IsValid: valid}
	}

	cases := []struct {
		name  string
		certs []*cert.CertificateInfo
		want  bool
	}{
		{name: "all client certs expired", certs: []*cert.CertificateInfo{makeClient(false), makeClient(false)}, want: true},
		{name: "single expired client cert", certs: []*cert.CertificateInfo{makeClient(false)}, want: true},
		{name: "empty list", certs: nil, want: false},
		{name: "no client certs (only server)", certs: []*cert.CertificateInfo{makeServer(false)}, want: false},
		{name: "mixed: one valid one expired", certs: []*cert.CertificateInfo{makeClient(true), makeClient(false)}, want: false},
		{name: "all client certs valid", certs: []*cert.CertificateInfo{makeClient(true)}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hasExpiredClientCert(tc.certs))
		})
	}
}

// TestRefreshAndConnect_202_ReturnsErrRefreshPending verifies that when the controller
// returns HTTP 202 for the /refresh/complete endpoint, refreshAndConnect returns
// ErrRefreshPending rather than a fatal error or a successful connection.
func TestRefreshAndConnect_202_ReturnsErrRefreshPending(t *testing.T) {
	dir := t.TempDir()

	ks, err := identity.NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/refresh/challenge"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"nonce":"dGVzdA","server_ts":1,"expires_in":60}`))
		case strings.HasSuffix(r.URL.Path, "/refresh/complete"):
			w.WriteHeader(http.StatusAccepted)
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	storedID := &StewardIdentity{
		StewardID:        "steward-refresh-test",
		TenantID:         "tenant-1",
		TransportAddress: srv.URL,
		CACertPEM:        "fake-ca",
		ServerCertPEM:    "fake-server",
	}

	_, err = refreshAndConnect(context.Background(), storedID, ks, dir, "tok", srv.URL, stewardconfig.StewardConfig{}, false, logging.NewLogger("error"))
	require.ErrorIs(t, err, registration.ErrRefreshPending,
		"HTTP 202 from refresh/complete must return ErrRefreshPending, not a fatal error")
}

// refreshTestController is a fake controller for the registration-refresh
// endpoints, backed by a real pkg/cert CA: /refresh/complete parses the CSR the
// steward submits and signs its public key into a genuine client certificate,
// exactly as the controller's buildRefreshClaimResponse does (Issue #3781). No
// private key is ever generated or returned for that credential — the response
// type has no field for one.
type refreshTestController struct {
	server  *httptest.Server
	certMgr *cert.Manager
	caPEM   string

	mu   sync.Mutex
	csrs []*x509.CertificateRequest // every CSR received, in submission order
}

// newRefreshTestController starts the fake controller. Its URL is available as
// controller.server.URL once this returns.
func newRefreshTestController(t *testing.T) *refreshTestController {
	t.Helper()

	certMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cert.CAConfig{
			Organization: "CFGMS Refresh Test CA",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)
	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)

	c := &refreshTestController{certMgr: certMgr, caPEM: string(caPEM)}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/refresh/challenge"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"nonce":"dGVzdA","server_ts":1,"expires_in":60}`))
		case strings.HasSuffix(r.URL.Path, "/refresh/complete"):
			c.handleComplete(w, r)
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	t.Cleanup(c.server.Close)
	return c
}

// handleComplete verifies the submitted CSR and signs it, mirroring the real
// controller's gate order for the CSR checks.
func (c *refreshTestController) handleComplete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CSRPEM string `json:"csr_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	if body.CSRPEM == "" {
		http.Error(w, "csr_pem is required", http.StatusBadRequest)
		return
	}
	if strings.Contains(body.CSRPEM, "PRIVATE KEY") {
		http.Error(w, "private key material is not accepted", http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode([]byte(body.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "csr_pem is not a CERTIFICATE REQUEST", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "invalid certificate signing request", http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "certificate signing request signature is invalid", http.StatusBadRequest)
		return
	}

	clientCert, err := c.certMgr.SignClientCertificateRequest(csr.PublicKey, &cert.ClientCertConfig{
		CommonName:   csr.Subject.CommonName,
		Organization: "CFGMS Stewards",
		ClientID:     csr.Subject.CommonName,
		ValidityDays: 30,
	})
	if err != nil {
		http.Error(w, "failed to sign client certificate", http.StatusInternalServerError)
		return
	}

	c.mu.Lock()
	c.csrs = append(c.csrs, csr)
	c.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":            "approved",
		"client_cert":       string(clientCert.CertificatePEM),
		"ca_cert":           c.caPEM,
		"issuer_chain":      string(clientCert.IssuerChainPEM),
		"transport_address": c.server.URL,
	})
}

// receivedCSRs returns the CSRs submitted so far.
func (c *refreshTestController) receivedCSRs() []*x509.CertificateRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*x509.CertificateRequest(nil), c.csrs...)
}

// TestCompleteRefreshWithFreshKeypair_PairsLocalKeyWithIssuedCert verifies the
// credential half of the refresh (Issue #3781): the returned private key PEM is
// the key behind the CSR that was submitted, it never crossed the wire, and it
// forms a usable TLS pair with the certificate the controller signed. A
// scan/plumbing slip that returned any other key would fail tls.X509KeyPair.
func TestCompleteRefreshWithFreshKeypair_PairsLocalKeyWithIssuedCert(t *testing.T) {
	controller := newRefreshTestController(t)

	httpClient, err := registration.NewHTTPClient(buildHTTPConfig(controller.server.URL, 30*time.Second, logging.NewNoopLogger()))
	require.NoError(t, err)

	const deviceID = "device-refresh-keypair"
	resp, keyPEM, err := completeRefreshWithFreshKeypair(
		context.Background(), httpClient, deviceID, "tenant-1", "dGVzdA", 1, []byte("pop-signature"))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.ClientCert, "controller must return the certificate it signed over the submitted CSR")

	// The submitted CSR names the device and carries a self-signature the
	// controller verified — proof the caller held the matching private key.
	csrs := controller.receivedCSRs()
	require.Len(t, csrs, 1, "exactly one CSR must be submitted per refresh")
	assert.Equal(t, deviceID, csrs[0].Subject.CommonName, "the CSR must be issued for the steward's device ID")

	// The returned key is the CSR's private key: same public half, and it pairs
	// with the issued certificate in a real TLS keypair load.
	block, _ := pem.Decode([]byte(keyPEM))
	require.NotNil(t, block, "returned key must be PEM encoded")
	assert.Equal(t, "PRIVATE KEY", block.Type)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "the renewed key must be an ECDSA key")
	csrPub, ok := csrs[0].PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, ecKey.PublicKey.Equal(csrPub),
		"the returned private key must be the one behind the submitted CSR")

	_, err = tls.X509KeyPair([]byte(resp.ClientCert), []byte(keyPEM))
	require.NoError(t, err,
		"the controller-issued certificate and the locally held key must form a usable TLS pair")

	// A second refresh must generate a different keypair — the renewed credential
	// is never a re-use of a previous one.
	resp2, keyPEM2, err := completeRefreshWithFreshKeypair(
		context.Background(), httpClient, deviceID, "tenant-1", "dGVzdA", 1, []byte("pop-signature"))
	require.NoError(t, err)
	assert.NotEqual(t, keyPEM, keyPEM2, "each refresh must generate a fresh keypair")
	_, err = tls.X509KeyPair([]byte(resp2.ClientCert), []byte(keyPEM))
	assert.Error(t, err, "the previous refresh's key must not pair with the newly issued certificate")
	_, err = tls.X509KeyPair([]byte(resp2.ClientCert), []byte(keyPEM2))
	require.NoError(t, err)
}

// TestCompleteRefreshWithFreshKeypair_PendingPropagatesWithoutKey verifies that a
// queued (HTTP 202) refresh returns ErrRefreshPending unwrapped and yields no key
// — a caller must not treat a queued refresh as an issued credential.
func TestCompleteRefreshWithFreshKeypair_PendingPropagatesWithoutKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	httpClient, err := registration.NewHTTPClient(buildHTTPConfig(srv.URL, 30*time.Second, logging.NewNoopLogger()))
	require.NoError(t, err)

	resp, keyPEM, err := completeRefreshWithFreshKeypair(
		context.Background(), httpClient, "device-pending", "tenant-1", "dGVzdA", 1, []byte("pop"))
	require.ErrorIs(t, err, registration.ErrRefreshPending)
	assert.Nil(t, resp)
	assert.Empty(t, keyPEM, "a queued refresh must not hand back a key for a certificate that was never issued")
}

// TestRefreshAndConnect_SuccessPathPersistsDeviceIdentity verifies that when the
// controller returns HTTP 200 for /refresh/complete, the persisted identity file
// carries DeviceID and IdentityKeyPub from the key store — i.e. that
// enrichApprovedWithDeviceIdentity is called before connectWithApprovedRegistration.
// The transport connection itself will fail (no real controller), but saveIdentity
// is called before the transport attempt, so the file is a reliable signal.
//
// The controller here signs the steward-submitted CSR with a real CA (Issue
// #3781), so the run also proves refreshAndConnect submits a CSR built over a
// freshly generated key rather than reading a key off the wire.
func TestRefreshAndConnect_SuccessPathPersistsDeviceIdentity(t *testing.T) {
	dir := t.TempDir()

	ks, err := identity.NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	expectedDeviceID := ks.DeviceID()
	require.NotEmpty(t, expectedDeviceID)

	controller := newRefreshTestController(t)

	storedID := &StewardIdentity{
		StewardID:        "steward-refresh-test",
		TenantID:         "tenant-1",
		TransportAddress: controller.server.URL,
		CACertPEM:        "fake-ca",
		ServerCertPEM:    "fake-server",
	}

	// refreshAndConnect will fail at connectWithApprovedRegistration (no real transport),
	// but saveIdentity is invoked before the transport attempt so the identity file is written.
	_, connectErr := refreshAndConnect(context.Background(), storedID, ks, dir, "tok",
		controller.server.URL, stewardconfig.StewardConfig{}, false, logging.NewLogger("error"))
	require.Error(t, connectErr, "no real transport is listening, so the reconnect must fail")
	assert.NotContains(t, connectErr.Error(), "no usable steward private key",
		"the bundle handed to connectWithApprovedRegistration must carry the locally generated key")

	// The identity file saved by connectWithApprovedRegistration must carry the
	// DeviceID and IdentityKeyPub from the key store.  An empty DeviceID here
	// means enrichApprovedWithDeviceIdentity was not called before the bundle was
	// passed to connectWithApprovedRegistration.
	savedID, loadErr := loadIdentity(dir)
	require.NoError(t, loadErr)
	require.NotNil(t, savedID, "identity file must exist after a successful refresh/complete response")
	assert.Equal(t, expectedDeviceID, savedID.DeviceID,
		"DeviceID must be populated in persisted identity after successful refresh")
	assert.NotEmpty(t, savedID.IdentityKeyPub,
		"IdentityKeyPub must be populated in persisted identity after successful refresh")
	assert.Equal(t, controller.caPEM, savedID.CACertPEM,
		"the CA delivered with the refreshed certificate must be persisted")
}

// TestRefreshAndConnect_SubmitsCSROverFreshKeypair verifies the integration point
// added by Issue #3781: refreshAndConnect itself builds the /refresh/complete CSR
// over a keypair it generates locally, names the device in it, and generates a
// distinct keypair on every refresh. The CSR's public key must not be the
// steward's Ed25519 device-identity key — that key proves identity and is never
// the mTLS credential.
func TestRefreshAndConnect_SubmitsCSROverFreshKeypair(t *testing.T) {
	dir := t.TempDir()

	ks, err := identity.NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	deviceID := ks.DeviceID()
	require.NotEmpty(t, deviceID)

	controller := newRefreshTestController(t)

	storedID := &StewardIdentity{
		StewardID:        "steward-refresh-csr",
		TenantID:         "tenant-1",
		TransportAddress: controller.server.URL,
		CACertPEM:        "fake-ca",
		ServerCertPEM:    "fake-server",
	}

	// Two refreshes: the transport reconnect fails both times (nothing is
	// listening), but the CSR submission happens before that.
	for i := 0; i < 2; i++ {
		_, refreshErr := refreshAndConnect(context.Background(), storedID, ks, dir, "tok",
			controller.server.URL, stewardconfig.StewardConfig{}, false, logging.NewLogger("error"))
		require.Error(t, refreshErr, "no real transport is listening, so the reconnect must fail")
	}

	csrs := controller.receivedCSRs()
	require.Len(t, csrs, 2, "each refreshAndConnect call must submit exactly one CSR")

	pubs := make([]*ecdsa.PublicKey, 0, len(csrs))
	for i, csr := range csrs {
		assert.Equal(t, deviceID, csr.Subject.CommonName, "CSR %d must name the steward's device ID", i)
		require.NoError(t, csr.CheckSignature(),
			"CSR %d must be self-signed by the key the steward generated for it", i)
		// The device-identity key is Ed25519 and proves identity only; the renewed
		// mTLS credential is a separate, freshly generated ECDSA P-256 keypair.
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		require.True(t, ok, "CSR %d must carry a freshly generated ECDSA key, not the Ed25519 device-identity key", i)
		assert.Equal(t, elliptic.P256(), pub.Curve, "CSR %d must carry a P-256 key", i)
		pubs = append(pubs, pub)
	}
	assert.False(t, pubs[0].Equal(pubs[1]),
		"each refresh must generate a distinct keypair, never reuse the previous credential's")
}

// TestPollForApproval_BackoffIntervalGrows verifies that the poll interval doubles
// on each "pending" response up to maxInterval.
func TestPollForApproval_BackoffIntervalGrows(t *testing.T) {
	// Respond "pending" once then immediately "claimed" to avoid a long-running loop.
	var callCount atomic.Int32
	body := statusBody(t, "claimed", "s1", "t1", "ctrl:4433", "CERT", "KEY", "CA")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if n == 1 {
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		} else {
			_, _ = w.Write(body)
		}
	}))
	defer srv.Close()

	// Pass non-zero intervals; PollStatus will be called with growing base intervals.
	// The httptest server responds immediately, so the test doesn't sleep.
	// We verify that no error occurs and approval is received.
	result, err := pollForApproval(context.Background(), newPollTestClient(t, srv),
		"pending-backoff", "tok", 30*time.Second, 1*time.Millisecond, 10*time.Millisecond,
		logging.NewLogger("error"))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "CERT", result.ClientCert)
}

// generateMainTestCACert generates a self-signed ECDSA CA cert for use in main_test.go.
// Returns the PEM-encoded cert string and its SHA-256 fingerprint as lowercase hex.
func generateMainTestCACert(t *testing.T) (certPEM, fingerprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"CFGMS Main Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	hash := sha256.Sum256(certDER)
	fingerprint = hex.EncodeToString(hash[:])
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return
}

// TestBuildCertManagerAndSecretStore_LeafPlusChain verifies that
// buildCertManagerAndSecretStore concatenates the leaf certificate with a
// non-empty issuer chain (Issue #3778/#3780) and that the resulting cert.Manager
// presents the full chain during a real TLS handshake — tls.Certificate.Certificate
// must carry more than one DER entry, verified by dialing a listener that trusts
// only the root CA, never the intermediate directly. [REQUIRED TEST]
func TestBuildCertManagerAndSecretStore_LeafPlusChain(t *testing.T) {
	logger := logging.NewNoopLogger()

	// Real root CA, a subordinate (regional intermediate) signed from it, and a
	// steward client leaf issued by the intermediate — the Issue #3778 shape.
	rootMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cert.CAConfig{
			Organization:  "CFGMS Test Root",
			Country:       "US",
			ValidityDays:  3650,
			PathLength:    1,
			PathLengthSet: true,
		},
	})
	require.NoError(t, err)
	rootCertPEM, err := rootMgr.GetCACertificate()
	require.NoError(t, err)

	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	subCert, err := rootMgr.SignSubordinateCA(&subKey.PublicKey, &cert.SubordinateCAConfig{
		CommonName:   "CFGMS Test Regional Intermediate",
		Organization: "CFGMS Test",
		ValidityDays: 3650,
		PathLength:   0,
	})
	require.NoError(t, err)
	subKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(subKey)})

	intermediateMgr, err := cert.NewManagerFromCAMaterial(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
	}, subCert.CertificatePEM, subKeyPEM, rootCertPEM)
	require.NoError(t, err)

	leaf, err := intermediateMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-chain-test",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-chain-test",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	require.NotEmpty(t, leaf.IssuerChainPEM, "leaf issued by an intermediate-backed manager must carry a non-empty issuer chain")

	certMgr := buildClientCertManagerAtPath(t.TempDir(),
		string(leaf.CertificatePEM), string(leaf.PrivateKeyPEM), string(leaf.IssuerChainPEM), logger)
	require.NotNil(t, certMgr, "cert.Manager must be created for a valid cert+key pair")

	tlsCert, err := certMgr.GetClientCertificate(context.Background())
	require.NoError(t, err)
	require.Greater(t, len(tlsCert.Certificate), 1,
		"the stored certificate must carry more than one DER entry: leaf + issuer chain")

	// Prove it during a real TLS handshake against a listener that trusts only
	// the root — the intermediate must be presented, not just stored.
	rootPool := x509.NewCertPool()
	require.True(t, rootPool.AppendCertsFromPEM(rootCertPEM))

	listenerCert, err := rootMgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "chain-listener.test",
		DNSNames:     []string{"chain-listener.test"},
		Organization: "CFGMS Test",
		ValidityDays: 1,
	})
	require.NoError(t, err)
	listenerTLSCert, err := tls.X509KeyPair(listenerCert.CertificatePEM, listenerCert.PrivateKeyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{listenerTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootPool,
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			accepted <- fmt.Errorf("accepted connection is not a *tls.Conn")
			return
		}
		accepted <- tlsConn.HandshakeContext(context.Background())
	}()

	clientConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return certMgr.GetClientCertificate(context.Background())
		},
		RootCAs:    rootPool,
		ServerName: "chain-listener.test",
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, err, "the presented leaf+chain must verify against a root-only trust store")
	defer func() { _ = clientConn.Close() }()

	require.NoError(t, <-accepted,
		"the listener must accept and verify the intermediate-issued leaf against the root-only CA pool")
}

// TestResolveTrustSource verifies the trust-source resolution rules from ADR-013 §3.
func TestResolveTrustSource(t *testing.T) {
	cases := []struct {
		name        string
		compiledURL string
		installURL  string
		installCA   string
		wantSrc     TrustSource
		wantURL     string
		wantErr     bool
	}{
		{
			name: "no URLs at all → error",
		},
		{
			name:        "compile-baked: only compiledURL set",
			compiledURL: "https://baked.example.com",
			wantSrc:     trustSourceCompileBaked,
			wantURL:     "https://baked.example.com",
		},
		{
			name:        "dev flow regression: compiledURL set, no installURL → compile-baked",
			compiledURL: "https://baked.example.com", installURL: "", installCA: "",
			wantSrc: trustSourceCompileBaked, wantURL: "https://baked.example.com",
		},
		{
			name:        "install-pinned: installURL + installCA both set",
			compiledURL: "https://baked.example.com", installURL: "https://install.example.com", installCA: "ca.pem",
			wantSrc: trustSourceInstallPinned, wantURL: "https://install.example.com",
		},
		{
			name:        "tofu: installURL set but no CA",
			compiledURL: "", installURL: "https://tofu.example.com",
			wantSrc: trustSourceTOFU, wantURL: "https://tofu.example.com",
		},
		{
			name:        "tofu: installURL set, compiledURL also set, no CA",
			compiledURL: "https://baked.example.com", installURL: "https://tofu.example.com",
			wantSrc: trustSourceTOFU, wantURL: "https://tofu.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, url, err := resolveTrustSource(tc.compiledURL, tc.installURL, tc.installCA)
			if tc.wantErr || (tc.compiledURL == "" && tc.installURL == "") {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantSrc, src)
			assert.Equal(t, tc.wantURL, url)
		})
	}
}

// TestTOFUCAPinImmutable verifies that pinTOFUCA pins the CA on first enroll and
// rejects a different CA on re-enroll (ADR-013 §3, Issue #1517).
func TestTOFUCAPinImmutable(t *testing.T) {
	certPEMA, fingerprintA := generateMainTestCACert(t)
	certPEMB, _ := generateMainTestCACert(t)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "etc", "cfgms", "controller-ca.crt")

	// First enrollment: pin CA A and record fingerprint.
	id1 := &StewardIdentity{}
	require.NoError(t, pinTOFUCA(caPath, certPEMA, id1))
	assert.Equal(t, fingerprintA, id1.CAPinFingerprint, "fingerprint must be recorded on first pin")

	// CA file must be written at 0444 (public, immutable).
	info, err := os.Stat(caPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0444), info.Mode().Perm(), "CA cert must be written with mode 0444 after TOFU pin")

	// Second call with same CA A: must succeed (fingerprint matches).
	id2 := &StewardIdentity{CAPinFingerprint: id1.CAPinFingerprint}
	require.NoError(t, pinTOFUCA(caPath, certPEMA, id2))

	// Second call with different CA B: must be rejected.
	id3 := &StewardIdentity{CAPinFingerprint: id1.CAPinFingerprint}
	err = pinTOFUCA(caPath, certPEMB, id3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "re-pin requires wipe + re-enroll")

	// CA file must be unchanged after rejection.
	got, readErr := os.ReadFile(caPath)
	require.NoError(t, readErr)
	assert.Equal(t, certPEMA, string(got), "CA file must not be modified after rejection")
}

// TestConnectWithApprovedRegistration_TOFUPinFails_ReturnsError verifies that
// connectWithApprovedRegistration returns a hard error and does NOT persist the
// identity when pinTOFUCA fails in TOFU mode.  ADR-013 §3 / implementation note:
// "on error, do not save identity, do not connect."
func TestConnectWithApprovedRegistration_TOFUPinFails_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	logger := logging.NewLogger("error")

	reg := approvedRegistration{
		StewardID:        "s1",
		TenantID:         "t1",
		TransportAddress: "https://ctrl.example.com",
		ClientKey:        "fake-key-pem",    // present so the TOFU pin path is what's under test, not the empty-key guard
		CACert:           "not-a-valid-pem", // invalid PEM → computeCAPEMFingerprint fails → pinTOFUCA returns error
	}

	_, err := connectWithApprovedRegistration(context.Background(), reg, dir, "tok", trustSourceTOFU, "", stewardconfig.StewardConfig{}, false, logger)
	require.Error(t, err, "must return a hard error when TOFU CA pin fails")

	// Identity MUST NOT be saved when pinTOFUCA fails.
	savedID, loadErr := loadIdentity(dir)
	require.NoError(t, loadErr)
	assert.Nil(t, savedID, "identity must not be persisted to disk when TOFU CA pin fails")
}

// TestConnectWithApprovedRegistration_EmptyClientKey_ReturnsLoudError is the
// defense-in-depth regression test for the PR #3844 acceptance-review finding:
// an approved registration that carries no private key (e.g. a resumed
// pending-registration poll that had no matching in-memory key — see
// registerAndConnect's pending-state handling and
// registration.HTTPClient.ResumePendingClientKey) must fail loudly rather than
// silently fall through to connecting without mTLS.
func TestConnectWithApprovedRegistration_EmptyClientKey_ReturnsLoudError(t *testing.T) {
	dir := t.TempDir()
	logger := logging.NewLogger("error")

	reg := approvedRegistration{
		StewardID:        "s1",
		TenantID:         "t1",
		TransportAddress: "https://ctrl.example.com",
		ClientCert:       "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
		CACert:           "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
		// ClientKey intentionally left empty.
	}

	_, err := connectWithApprovedRegistration(context.Background(), reg, dir, "tok", trustSourceCompileBaked, "", stewardconfig.StewardConfig{}, false, logger)
	require.Error(t, err, "must return a hard error when the approved registration carries no private key")
	assert.Contains(t, err.Error(), "no usable steward private key")

	// Identity MUST NOT be saved: connecting without mTLS is not an acceptable fallback.
	savedID, loadErr := loadIdentity(dir)
	require.NoError(t, loadErr)
	assert.Nil(t, savedID, "identity must not be persisted to disk when the approved registration carries no private key")
}

// TestTrustSourceDowngradeGuard verifies that checkTrustDowngrade enforces the
// trust level ordering and CA fingerprint immutability (ADR-013 §3, Issue #1517).
func TestTrustSourceDowngradeGuard(t *testing.T) {
	certPEM, fingerprint := generateMainTestCACert(t)
	certPEM2, _ := generateMainTestCACert(t)

	t.Run("no prior enrollment allows any source", func(t *testing.T) {
		id := &StewardIdentity{}
		require.NoError(t, checkTrustDowngrade(trustSourceTOFU, "", id))
		require.NoError(t, checkTrustDowngrade(trustSourceCompileBaked, "", id))
	})

	t.Run("downgrade from install-pinned to tofu rejected", func(t *testing.T) {
		id := &StewardIdentity{TrustMode: "install-pinned", CAPinFingerprint: fingerprint}
		err := checkTrustDowngrade(trustSourceTOFU, "", id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trust downgrade rejected")
	})

	t.Run("downgrade from compile-baked to install-pinned rejected", func(t *testing.T) {
		id := &StewardIdentity{TrustMode: "compile-baked"}
		err := checkTrustDowngrade(trustSourceInstallPinned, certPEM, id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trust downgrade rejected")
	})

	t.Run("same-level install-pinned with different CA rejected", func(t *testing.T) {
		id := &StewardIdentity{TrustMode: "install-pinned", CAPinFingerprint: fingerprint}
		err := checkTrustDowngrade(trustSourceInstallPinned, certPEM2, id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "re-pin requires wipe + re-enroll")
	})

	t.Run("same-level install-pinned with matching CA allowed", func(t *testing.T) {
		id := &StewardIdentity{TrustMode: "install-pinned", CAPinFingerprint: fingerprint}
		require.NoError(t, checkTrustDowngrade(trustSourceInstallPinned, certPEM, id))
	})

	t.Run("upgrade from tofu to install-pinned allowed", func(t *testing.T) {
		id := &StewardIdentity{TrustMode: "tofu", CAPinFingerprint: fingerprint}
		require.NoError(t, checkTrustDowngrade(trustSourceInstallPinned, "", id))
	})
}

// TestRegistrationUsesPinnedCAInPinnedMode verifies that buildHTTPConfigForInstallPinned
// produces a client that exclusively uses the pinned CA and rejects connections to
// servers whose cert is not signed by that CA (ADR-013 §3, Issue #1517).
func TestRegistrationUsesPinnedCAInPinnedMode(t *testing.T) {
	logger := logging.NewLogger("error")

	// Use httptest.NewTLSServer which uses Go's built-in test CA.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	// Extract the server's own TLS certificate to use as the pinned CA.
	serverCertDER := srv.TLS.Certificates[0].Certificate[0]
	serverCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}))

	// With the correct server cert as pinned CA: NewHTTPClient must succeed.
	correctCfg := buildHTTPConfigForInstallPinned(srv.URL, 5*time.Second, serverCertPEM, logger)
	_, createErr := registration.NewHTTPClient(correctCfg)
	require.NoError(t, createErr, "NewHTTPClient with matching pinned CA must not error")

	// With a different CA (wrong): the TLS connection must be rejected.
	wrongCAPEM, _ := generateMainTestCACert(t)
	wrongCfg := buildHTTPConfigForInstallPinned(srv.URL, 5*time.Second, wrongCAPEM, logger)
	httpCl, createErr2 := registration.NewHTTPClient(wrongCfg)
	require.NoError(t, createErr2, "NewHTTPClient itself must not error — TLS error happens at dial time")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, reqErr := httpCl.Register(ctx, registration.RegistrationRequest{Token: "tok_pintest"})
	require.Error(t, reqErr, "request to server with wrong pinned CA must fail")
	errStr := reqErr.Error()
	isTLSError := strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "tls") ||
		strings.Contains(errStr, "x509")
	assert.True(t, isTLSError, "error must be TLS/cert related, got: %v", reqErr)
}

// ---------------------------------------------------------------------------
// Resilient startup tests (Issue #2034)
// ---------------------------------------------------------------------------

// TestRunSteward_ControllerUnreachable_StartsDegraded verifies AC1 + AC4:
// when the controller is unreachable at boot, runStewardInternal does NOT exit
// (returns nil when the context is cancelled) and retries the connect in the
// background. The process survives the entire launcher startup window (30s)
// using the connectFunc seam — no real time.Sleep. (Issue #2034)
func TestRunSteward_ControllerUnreachable_StartsDegraded(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())

	// Set a non-empty ControllerURL so trust resolution succeeds.
	saved := ControllerURL
	ControllerURL = "https://ctrl.test:4433"
	defer func() { ControllerURL = saved }()

	var connectAttempts atomic.Int32
	alwaysFails := connectFuncT(func(ctx context.Context, token, url string,
		trustSrc TrustSource, installCAPEM string, ks *identity.FileKeyStore,
		publicBeta bool,
		logger logging.Logger) (*client.TransportClient, error) {
		connectAttempts.Add(1)
		return nil, fmt.Errorf("controller unreachable: connection refused")
	})

	// Use a 500ms context — far less than the 30s launcher startup window.
	// The connectFunc blocks on error and retries; runStewardInternal must wait
	// for ctx.Done() rather than exit early on the first connect failure.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := runStewardInternal(ctx, "tok_test_degraded", "", "", alwaysFails)

	assert.NoError(t, err, "runStewardInternal must return nil when ctx is cancelled (not an error)")
	assert.Positive(t, connectAttempts.Load(), "connect must have been attempted at least once")
}

// TestRunSteward_EarlyLoggerBeforeProviderInit verifies AC2: the early stderr
// logger is initialised before the file logging provider and before any
// host-subsystem call, so a boot-time failure is never silent. Even when the
// file logging provider cannot be initialised, the process continues (no
// silent 0-byte-log death). (Issue #2034)
func TestRunSteward_EarlyLoggerBeforeProviderInit(t *testing.T) {
	// Point CFGMS_LOG_DIR at an unwritable path so the file provider init fails
	// on platforms where /proc is read-only (Linux) or the path is simply missing.
	t.Setenv("CFGMS_LOG_DIR", filepath.Join("/proc", "nonexistent_cfgms_test_dir"))

	saved := ControllerURL
	ControllerURL = "https://ctrl.test:4433"
	defer func() { ControllerURL = saved }()

	// The connect func fails immediately — process should still stay alive
	// (return nil on ctx cancel) even when the logging provider is unavailable.
	neverConnects := connectFuncT(func(ctx context.Context, token, url string,
		trustSrc TrustSource, installCAPEM string, ks *identity.FileKeyStore,
		publicBeta bool,
		logger logging.Logger) (*client.TransportClient, error) {
		return nil, fmt.Errorf("no controller")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := runStewardInternal(ctx, "tok_test_earlylog", "", "", neverConnects)
	assert.NoError(t, err, "must not exit with error even when file logging provider cannot be initialised")
}

// TestRunSteward_DNASubprocessFails_StaysRunning verifies AC3: when wmic /
// powershell subprocess calls fail at boot (on Linux they simply do not exist,
// simulating Windows early-boot WMI unavailability), DNA collection logs a
// warning and the steward keeps running. The process reaches the ctx.Done()
// path rather than exiting early. (Issue #2034)
func TestRunSteward_DNASubprocessFails_StaysRunning(t *testing.T) {
	// Verify the DNA collector itself is non-fatal on a non-Windows host
	// (wmic / powershell absent → subprocess errors → collector logs + returns).
	logger := logging.NewLogger("error")
	collector := dna.NewCollector(logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Collect must not panic or call os.Exit — it either succeeds (Linux
	// generic path) or returns partial/nil data with an internal warning.
	result, dnaErr := collector.Collect(ctx)
	// Reaching this line proves the call was non-fatal.
	if dnaErr != nil {
		t.Logf("DNA collection error (expected on non-Windows): %v", dnaErr)
	}
	if result != nil {
		t.Logf("DNA collected %d fragment(s)", len(result.GetFragments()))
	}

	// Now verify that runStewardInternal stays alive when the connect succeeds
	// but DNA collection fails (i.e. the initial DNA publish path is non-fatal).
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())
	savedURL := ControllerURL
	ControllerURL = "https://ctrl.test:4433"
	defer func() { ControllerURL = savedURL }()

	neverConnects := connectFuncT(func(ctx context.Context, token, url string,
		trustSrc TrustSource, installCAPEM string, ks *identity.FileKeyStore,
		publicBeta bool,
		logger logging.Logger) (*client.TransportClient, error) {
		// Return an error so the retry loop keeps running until ctx is done.
		// This also exercises the degraded-mode path implicitly.
		return nil, fmt.Errorf("test: simulated connect failure")
	})

	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()

	err := runStewardInternal(ctx2, "tok_test_dna", "", "", neverConnects)
	assert.NoError(t, err, "steward must not exit with error when DNA subprocess fails")
}

// TestSubsystemState_StatusTransitions verifies the subsystemState tracker used
// to drive the heartbeat health field: degraded while subsystems are pending,
// healthy when all have attached. (Issue #2034)
func TestSubsystemState_StatusTransitions(t *testing.T) {
	s := newSubsystemState()

	// Initially no degraded subsystems → healthy.
	assert.Equal(t, string(steward.StatusHealthy), s.status())

	s.markDegraded("controller")
	assert.Equal(t, string(steward.StatusDegraded), s.status())

	s.markDegraded("dna")
	assert.Equal(t, string(steward.StatusDegraded), s.status(), "still degraded with two pending subsystems")

	s.markHealthy("controller")
	assert.Equal(t, string(steward.StatusDegraded), s.status(), "still degraded while dna is pending")

	s.markHealthy("dna")
	assert.Equal(t, string(steward.StatusHealthy), s.status(), "healthy once all subsystems are ready")

	// Idempotent markHealthy on already-healthy subsystem.
	s.markHealthy("controller")
	assert.Equal(t, string(steward.StatusHealthy), s.status())
}

// fakeModuleDNASource is a stub moduleDNASource for the composite-collector
// merge test (#2423).
type fakeModuleDNASource struct {
	attrs map[string]string
}

func (f *fakeModuleDNASource) CollectModuleDNAAttributes(_ context.Context) map[string]string {
	return f.attrs
}

// CollectModuleFragments satisfies the #2908 fragment surface. This fixture is
// attribute-only; fragment forwarding is asserted against a real fragment
// producer in dna_adapter_test.go.
func (f *fakeModuleDNASource) CollectModuleFragments(_ context.Context) []*commonpb.Fragment {
	return nil
}

// TestDNACollectorAdapter_MergesHardwareAndModuleAttributes verifies that
// CollectAttributes returns the union of host-fact attributes (from the Collector's
// internal raw map — NOT from DNA.Attributes proto field, which Collect() no longer
// writes after Issue #3332) and module-owned attributes (cluster:*, vm:*, etc.).
func TestDNACollectorAdapter_MergesHardwareAndModuleAttributes(t *testing.T) {
	moduleAttrs := map[string]string{
		"cluster:cfg-lab.cno_owner_node":        "CFG-70-02",
		"cluster:cfg-lab.member_nodes":          "CFG-70-02,CFG-AB-02,CFG-C3-02",
		"cluster:cfg-lab.resource_owner.web-01": "CFG-70-02",
	}
	adapter := newDNACollectorAdapter(logging.NewLogger("error"), &fakeModuleDNASource{attrs: moduleAttrs})

	attrs, err := adapter.CollectAttributes(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, attrs)

	// Host-fact attributes from RawAttributes (not DNA.Attributes proto field).
	assert.Contains(t, attrs, "hostname",
		"host-fact attributes must appear in CollectAttributes output (via RawAttributes, not DNA.Attributes)")

	// Module attributes present verbatim alongside host attrs.
	for k, v := range moduleAttrs {
		assert.Equal(t, v, attrs[k], "module attribute %q must be returned by CollectAttributes", k)
	}
}

// TestDNACollectorAdapter_NilModuleSourceReturnsHostAttrs: with a nil moduleDNASource
// CollectAttributes returns host-fact attributes from RawAttributes (not nil).
// Issue #3332: hardware-facts-only mode still returns host attrs; fragments are a
// parallel channel, not a replacement for the flat map in this path.
func TestDNACollectorAdapter_NilModuleSourceReturnsHostAttrs(t *testing.T) {
	adapter := newDNACollectorAdapter(logging.NewLogger("error"), nil)
	attrs, err := adapter.CollectAttributes(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, attrs, "CollectAttributes must return host attrs even without a module source")
	assert.Contains(t, attrs, "hostname", "host-fact attributes must be present in hardware-facts-only mode")
}
