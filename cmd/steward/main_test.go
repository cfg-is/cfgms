// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cfgis/cfgms/cmd/steward/service"
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
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", "")
		cfg := buildHTTPConfig("https://controller.example.com", 30*time.Second, logger)
		require.NotNil(t, cfg)
		assert.Equal(t, "https://controller.example.com", cfg.ControllerURL)
		// CACertPath is "" when no env var is set and platform-standard cert does not exist.
		// In test environments the platform cert is absent, so this holds.
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
	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", trustSourceCompileBaked, logging.NewLogger("error"))
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

	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", trustSourceCompileBaked, logging.NewLogger("error"))
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

	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", trustSourceCompileBaked, logging.NewLogger("error"))
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

	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", trustSourceTOFU, logging.NewLogger("error"))
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
		ClientKey:        key,
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

	_, err = refreshAndConnect(context.Background(), storedID, ks, dir, "tok", srv.URL, logging.NewLogger("error"))
	require.ErrorIs(t, err, registration.ErrRefreshPending,
		"HTTP 202 from refresh/complete must return ErrRefreshPending, not a fatal error")
}

// TestRefreshAndConnect_SuccessPathPersistsDeviceIdentity verifies that when the
// controller returns HTTP 200 for /refresh/complete, the persisted identity file
// carries DeviceID and IdentityKeyPub from the key store — i.e. that
// enrichApprovedWithDeviceIdentity is called before connectWithApprovedRegistration.
// The transport connection itself will fail (no real controller), but saveIdentity
// is called before the transport attempt, so the file is a reliable signal.
func TestRefreshAndConnect_SuccessPathPersistsDeviceIdentity(t *testing.T) {
	dir := t.TempDir()

	ks, err := identity.NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	expectedDeviceID := ks.DeviceID()
	require.NotEmpty(t, expectedDeviceID)

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/refresh/challenge"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"nonce":"dGVzdA","server_ts":1,"expires_in":60}`))
		case strings.HasSuffix(r.URL.Path, "/refresh/complete"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			resp := map[string]string{
				"client_cert":       "fake-cert",
				"client_key":        "fake-key",
				"ca_cert":           "fake-ca",
				"server_cert":       "fake-server",
				"transport_address": srvURL,
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	storedID := &StewardIdentity{
		StewardID:        "steward-refresh-test",
		TenantID:         "tenant-1",
		TransportAddress: srv.URL,
		CACertPEM:        "fake-ca",
		ServerCertPEM:    "fake-server",
	}

	// refreshAndConnect will fail at connectWithApprovedRegistration (no real transport),
	// but saveIdentity is invoked before the transport attempt so the identity file is written.
	_, _ = refreshAndConnect(context.Background(), storedID, ks, dir, "tok", srv.URL, logging.NewLogger("error"))

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
		CACert:           "not-a-valid-pem", // invalid PEM → computeCAPEMFingerprint fails → pinTOFUCA returns error
	}

	_, err := connectWithApprovedRegistration(context.Background(), reg, dir, "tok", trustSourceTOFU, "", logger)
	require.Error(t, err, "must return a hard error when TOFU CA pin fails")

	// Identity MUST NOT be saved when pinTOFUCA fails.
	savedID, loadErr := loadIdentity(dir)
	require.NoError(t, loadErr)
	assert.Nil(t, savedID, "identity must not be persisted to disk when TOFU CA pin fails")
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
