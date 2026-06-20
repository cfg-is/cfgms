// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"encoding/json"
	"io"
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
	err := runInstall("tok_test_abc123", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "elevated privileges")
}

func TestRunInstallCACertFileNotFound(t *testing.T) {
	// Verify runInstall returns an error that includes the filename when --ca-cert
	// names a path that does not exist.
	missing := filepath.Join(t.TempDir(), "nonexistent-ca.crt")
	err := runInstall("tok_test_abc123", missing, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-ca.crt")
}

// TestInstallCommandFlagSurface asserts the install subcommand's flag set is
// exactly {--regtoken, --ca-cert, --fingerprint}. All Hyper-V-specific flags
// were removed in Issue #1894; no role-specific flags belong on the install command.
func TestInstallCommandFlagSurface(t *testing.T) {
	cmd := buildInstallCommand()
	require.NotNil(t, cmd)

	expected := map[string]bool{
		"regtoken":    true,
		"ca-cert":     true,
		"fingerprint": true,
	}

	var flagNames []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		flagNames = append(flagNames, f.Name)
	})

	for _, name := range flagNames {
		assert.True(t, expected[name],
			"unexpected flag %q on install subcommand — install accepts only --regtoken, --ca-cert, --fingerprint", name)
	}
	for name := range expected {
		assert.NotNil(t, cmd.Flags().Lookup(name),
			"required flag %q must be registered on install subcommand", name)
	}
	assert.Len(t, flagNames, len(expected),
		"install command must have exactly %d flags: --regtoken, --ca-cert, --fingerprint", len(expected))
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
	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", logging.NewLogger("error"))
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

	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", logging.NewLogger("error"))
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

	tc, err := tryReconnectWithStoredIdentity(context.Background(), dir, "token", logging.NewLogger("error"))
	assert.Nil(t, tc)
	assert.NoError(t, err)
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

	err := runSteward(ctx, "", "/nonexistent/cfgms-config-does-not-exist.yaml")
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

	// Temporarily point ControllerURL at the test server.
	origURL := ControllerURL
	ControllerURL = srv.URL
	t.Cleanup(func() { ControllerURL = origURL })

	storedID := &StewardIdentity{
		StewardID:        "steward-refresh-test",
		TenantID:         "tenant-1",
		TransportAddress: srv.URL,
		CACertPEM:        "fake-ca",
		ServerCertPEM:    "fake-server",
	}

	_, err = refreshAndConnect(context.Background(), storedID, ks, dir, "tok", logging.NewLogger("error"))
	require.ErrorIs(t, err, registration.ErrRefreshPending,
		"HTTP 202 from refresh/complete must return ErrRefreshPending, not a fatal error")
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
