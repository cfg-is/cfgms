// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/version"
	"github.com/spf13/cobra"

	// Import logging providers to register them
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"

	// Import secrets providers to register them
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

// ControllerURL is the controller address baked in at build time via ldflags.
// Set during build: go build -ldflags "-X main.ControllerURL=https://ctrl.example.com"
// No runtime override is supported — the signed binary is a trust assertion about
// which controller it connects to.
var ControllerURL string

func main() {
	// On Windows: detect if launched by the Service Control Manager and run as
	// a Windows service. This must happen before any cobra / flag parsing.
	if checkAndRunAsWindowsService() {
		return
	}

	rootCmd := buildRootCommand()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// buildRootCommand constructs the cobra command tree for cfgms-steward.
func buildRootCommand() *cobra.Command {
	var (
		configPath string
		regToken   string
	)

	root := &cobra.Command{
		Use:   "cfgms-steward",
		Short: "CFGMS Steward — endpoint configuration management agent",
		Long: fmt.Sprintf(`CFGMS Steward %s

Manages the local endpoint configuration on behalf of a CFGMS controller.

Entry paths:
  cfgms-steward --regtoken TOKEN     Run in foreground (controller-connected)
  cfgms-steward --config path.cfg    Run in standalone mode
  cfgms-steward install --regtoken TOKEN  Install as OS service
  cfgms-steward                      Interactive mode (prompts for token)`, version.Short()),
		// SilenceUsage prevents cobra printing usage on every error.
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRootCommand(cmd, regToken, configPath)
		},
	}

	// Flags used by the root command (foreground run mode).
	root.Flags().StringVar(&configPath, "config", "", "Path to configuration file (enables standalone mode)")
	root.Flags().StringVar(&regToken, "regtoken", "", "Registration token for controller registration")

	// Subcommands.
	root.AddCommand(
		buildInstallCommand(),
		buildUninstallCommand(),
		buildStatusCommand(),
	)

	return root
}

// runRootCommand implements the default (foreground) run behaviour.
// When no meaningful flags are provided it enters interactive mode.
func runRootCommand(cmd *cobra.Command, regToken, configPath string) error {
	// Interactive mode: no flags set and no subcommand selected.
	noFlags := regToken == "" && configPath == ""
	if noFlags {
		return runInteractive()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	return runSteward(ctx, regToken, configPath)
}

// runSteward starts the steward with the given configuration and blocks until
// ctx is cancelled. It is called from both the root cobra command and the
// Windows service handler.
func runSteward(ctx context.Context, regToken, configPath string) error {
	// Initialize global logging provider. File is the only supported provider
	// for the steward binary. Log level is read from CFGMS_LOG_LEVEL (default INFO).
	logDir := os.Getenv("CFGMS_LOG_DIR")
	if logDir == "" {
		logDir = "/tmp/cfgms"
		log.Printf("WARNING: Using /tmp/cfgms for logs — set CFGMS_LOG_DIR for production deployments")
	}
	loggingConfig := &logging.LoggingConfig{
		Provider:          "file",
		Level:             logLevelFromEnv(),
		ServiceName:       "steward",
		Component:         "main",
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
		AsyncWrites:       true,
		BatchSize:         100,
		FlushInterval:     5 * time.Second,
		RetentionDays:     30,
		Config: map[string]interface{}{
			"directory": logDir,
		},
	}

	if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
		return fmt.Errorf("failed to initialize global logging: %w", err)
	}
	// Flush and close the logger when runSteward returns so that buffered log
	// entries (AsyncWrites=true, FlushInterval=5s) reach disk before os.Exit
	// is called — critical for short-lived exit paths (e.g. ErrRefreshRejected).
	defer func() {
		if mgr := logging.GetGlobalLoggingManager(); mgr != nil {
			_ = mgr.Close()
		}
	}()
	(&logging.TelemetryBridge{}).Initialize()

	logging.InitializeGlobalLoggerFactory("steward", "main")
	logger := logging.ForComponent("steward")

	// gRPC transport registration flow.
	if regToken != "" {
		logger.Info("Using registration token for auto-registration (gRPC transport mode)",
			"operation", "registration_init",
			"token_prefix", logging.RedactedID(regToken))

		// Derive a cancellable context so a pushed binary upgrade can request a
		// graceful self-exit (the launcher then re-execs the staged binary).
		// Cancelling runCtx flows into <-runCtx.Done() below, driving the clean
		// Disconnect+return path — no hard os.Exit. The parent ctx (signal/SCM
		// stop) still cancels runCtx too. (Issue #2001)
		runCtx, runCancel := context.WithCancel(ctx)
		defer runCancel()

		// Initialise device identity key store before registration so the refresh
		// handshake path (Issue #2094) has a stable key available. Failure here is
		// non-fatal: initial registration still works; only the refresh path is disabled.
		ks, ksErr := identity.NewFileKeyStore(defaultCertStoreDir())
		if ksErr != nil {
			logger.Warn("Failed to create device identity key store; registration-refresh disabled", "error", ksErr)
		} else if _, _, loadErr := ks.GenerateOrLoad(runCtx); loadErr != nil {
			logger.Warn("Failed to load/generate device identity key; registration-refresh disabled", "error", loadErr)
			ks = nil
		}

		transportCl, err := registerAndConnect(runCtx, regToken, ks, logger)
		if err != nil {
			return fmt.Errorf("failed to register with controller: %w", err)
		}

		// Wire the graceful-shutdown trigger used after a successful
		// push_steward_binary swap. Pass runCtx so the upgrade grace-delay timer
		// watches the process lifecycle (cancelled only on SCM stop / signal /
		// runCancel) for early-exit, NOT a per-command context. (Issue #2001, #2003)
		transportCl.SetShutdownFunc(runCtx, runCancel)

		logger.Info("Steward registered and connected successfully via gRPC transport",
			"operation", "registration_complete",
			"steward_id", transportCl.GetStewardID(),
			"tenant_id", transportCl.GetTenantID())

		logger.Info("Running in gRPC controller-connected mode",
			"operation", "steward_mode",
			"mode", "grpc_transport")

		// Collect and publish DNA so the controller's steward record carries
		// `os`, `hostname`, `arch`, etc. — selectors like `os:windows` and
		// `cfg steward run-command --target …` depend on the controller
		// having received a non-empty DNA snapshot. Without this one-shot
		// publish, the controller's steward record stays at its registration-
		// time defaults (empty DNA) and every selector matches zero stewards.
		// Failures are non-fatal — the steward stays usable for config
		// convergence even if DNA publication is briefly unavailable; the
		// controller will pick up DNA on the next convergence-driven publish
		// in publishConfigStatus.
		if currentDNA, dnaErr := dna.NewCollector(logger).Collect(runCtx); dnaErr == nil && currentDNA != nil {
			if pubErr := transportCl.PublishDNAUpdate(runCtx, currentDNA.Attributes, "", ""); pubErr != nil {
				logger.Warn("Initial DNA publish failed; controller selectors may not find this steward until next config apply",
					"error", pubErr)
			} else {
				logger.Info("Initial DNA snapshot published",
					"attribute_count", len(currentDNA.Attributes))
			}
		} else if dnaErr != nil {
			logger.Warn("DNA collection failed at startup; controller selectors may match no stewards until DNA is collected later",
				"error", dnaErr)
		}

		// Check for launcher-written upgrade flag files and emit lifecycle events.
		// Must run before the heartbeat loop so the controller learns commit/rollback
		// status on the first heartbeat after a restart. (Issue #1943)
		checkUpgradeFlagFiles(runCtx, defaultCertStoreDir(), transportCl, logger)

		// Start scheduled convergence loop. The initial interval defaults to
		// 30 minutes. When the controller delivers a cfg, the loop reads
		// converge_interval from it and resets the ticker accordingly.
		// sync_config commands from the controller also trigger immediate
		// convergence as an out-of-band optimization on top of the schedule.
		transportCl.StartConvergenceLoop(runCtx)

		// Start periodic DNA refresh loop. Re-collects system attributes on
		// the configured interval and publishes delta updates so the controller
		// fleet view stays current without requiring a full reconnect. (Issue #1915)
		transportCl.StartDNARefreshLoop(runCtx)

		// Wait for context cancellation (signal, SCM stop, or a pushed-upgrade
		// graceful self-exit request via SetShutdownFunc → runCancel).
		<-runCtx.Done()
		logger.Info("Shutdown signal received, disconnecting...",
			"operation", "steward_shutdown")

		disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer disconnectCancel()
		if err := transportCl.Disconnect(disconnectCtx); err != nil {
			logger.Error("Error during transport disconnect",
				"operation", "transport_disconnect",
				"error", err.Error())
		}

		logger.Info("Steward shutdown completed", "operation", "steward_shutdown", "status", "completed")
		return nil
	}

	// Standalone mode: --config was provided.
	useStandalone := configPath != ""
	if useStandalone {
		legacyLogger := logging.GetLogger()
		s, err := steward.NewStandalone(configPath, legacyLogger)
		if err != nil {
			return fmt.Errorf("failed to create standalone steward: %w", err)
		}
		logger.Info("Starting steward in standalone mode",
			"operation", "steward_start", "mode", "standalone", "config_path", configPath)

		errCh := make(chan error, 1)
		go func() {
			errCh <- s.Start(ctx)
		}()

		<-ctx.Done()
		logger.Info("Shutdown signal received", "operation", "steward_shutdown")

		stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer stopCancel()
		if stopErr := s.Stop(stopCtx); stopErr != nil {
			logger.Error("Error during shutdown", "operation", "steward_shutdown", "error", stopErr.Error())
		}

		if startErr := <-errCh; startErr != nil && startErr != context.Canceled {
			logger.Error("Steward start failed", "operation", "steward_run", "error", startErr.Error())
			return fmt.Errorf("steward start failed: %w", startErr)
		}

		logger.Info("Steward shutdown completed", "operation", "steward_shutdown", "status", "completed")
		return nil
	}

	// Structurally unreachable: runRootCommand's noFlags guard prevents calling
	// runSteward with both regToken and configPath empty.
	return nil
}

// buildInstallCommand builds the `cfgms-steward install` subcommand.
func buildInstallCommand() *cobra.Command {
	var regToken, caCertPath, fingerprint string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Copy binary to platform path and register as OS service",
		Long: `Install copies the cfgms-steward binary to the platform-standard location
and registers it as a persistent OS service that starts automatically on boot.

Platforms:
  Windows  C:\Program Files\CFGMS\cfgms-steward.exe  (Windows Service)
  Linux    /usr/local/bin/cfgms-steward               (systemd)
  macOS    /usr/local/bin/cfgms-steward               (launchd)

Requires elevated privileges (Administrator on Windows, root on Linux/macOS).
Install is idempotent: running it again updates the binary and restarts the service.

Standard form (controller certificate issued by a public CA):

  cfgms-steward install --regtoken TOKEN

Private-CA deployments (Tier 1, internal CA, lab environments):
  Pass --ca-cert and --fingerprint for fingerprint-verified trust-on-first-use
  (TOFU) of the controller CA certificate. The fingerprint is printed by the
  controller during --init and can also be retrieved with:

    cfg admin ca fingerprint`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(regToken, caCertPath, fingerprint)
		},
	}

	cmd.Flags().StringVar(&regToken, "regtoken", "", "Registration token (required)")
	_ = cmd.MarkFlagRequired("regtoken")
	cmd.Flags().StringVar(&caCertPath, "ca-cert", "", "Path to controller CA certificate PEM file (private-CA deployments only)")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "Expected SHA-256 fingerprint of the CA certificate (hex, from controller --init output)")

	return cmd
}

// buildUninstallCommand builds the `cfgms-steward uninstall` subcommand.
func buildUninstallCommand() *cobra.Command {
	var purge bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the OS service",
		Long: `Uninstall stops the running cfgms-steward service and removes the service
definition from the OS service manager. With --purge the installed binary is
also deleted.

Requires elevated privileges (Administrator on Windows, root on Linux/macOS).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(purge)
		},
	}

	cmd.Flags().BoolVar(&purge, "purge", false, "Also remove the installed binary")

	return cmd
}

// buildStatusCommand builds the `cfgms-steward status` subcommand.
func buildStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show service state, install path, and controller URL",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus()
		},
	}
}

// runInstall performs the install operation for the current platform.
func runInstall(regToken, caCertPath, fingerprint string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}

	var caCertPEM string
	if caCertPath != "" {
		data, readErr := os.ReadFile(caCertPath)
		if readErr != nil {
			return fmt.Errorf("failed to read CA cert file %s: %w", caCertPath, readErr)
		}
		caCertPEM = string(data)
	}

	mgr := service.New(exe)

	if !mgr.IsElevated() {
		return fmt.Errorf("install requires elevated privileges\n" +
			"  Windows: right-click the binary and select 'Run as administrator'\n" +
			"  Linux/macOS: re-run with sudo")
	}

	return mgr.Install(regToken, caCertPEM, fingerprint)
}

// runUninstall performs the uninstall operation for the current platform.
func runUninstall(purge bool) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}

	mgr := service.New(exe)

	if !mgr.IsElevated() {
		return fmt.Errorf("uninstall requires elevated privileges\n" +
			"  Windows: right-click the binary and select 'Run as administrator'\n" +
			"  Linux/macOS: re-run with sudo")
	}

	return mgr.Uninstall(purge)
}

// runStatus prints the current service state without requiring elevated privileges.
func runStatus() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}

	mgr := service.New(exe)
	status, err := mgr.Status()
	if err != nil {
		return fmt.Errorf("failed to query service status: %w", err)
	}

	fmt.Printf("CFGMS Steward %s\n\n", version.Short())
	fmt.Printf("  Service name:  %s\n", status.ServiceName)
	fmt.Printf("  Install path:  %s\n", status.InstallPath)
	fmt.Printf("  Controller:    %s\n", controllerURLOrUnknown())

	if !status.Installed {
		fmt.Printf("  Status:        not installed\n")
		fmt.Printf("\n  To install: cfgms-steward install --regtoken TOKEN\n")
		return nil
	}

	state := "stopped"
	if status.Running {
		state = "running"
	}
	fmt.Printf("  Status:        %s\n", state)
	return nil
}

// controllerURLOrUnknown returns the compile-time controller URL or a
// human-friendly placeholder when the binary was built without one.
func controllerURLOrUnknown() string {
	if ControllerURL == "" {
		return "(not set — binary built without -ldflags \"-X main.ControllerURL=...\")"
	}
	return ControllerURL
}

// runInteractive enters the interactive terminal UI shown when the binary is
// launched with no arguments (including Windows double-click).
//
// Flow:
//  1. Print header with version
//  2. Prompt for registration token
//  3. Offer: [1] Install as service  [2] Run once  [3] Exit
//  4. Execute chosen action
func runInteractive() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("CFGMS Steward %s\n\n", version.Short())
	fmt.Printf("Controller: %s\n\n", controllerURLOrUnknown())

	fmt.Print("Registration token: ")
	token, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read registration token: %w", err)
	}
	token = strings.TrimSpace(token)

	if token == "" {
		return fmt.Errorf("registration token cannot be empty")
	}

	fmt.Println()
	fmt.Println("  [1] Install as service (recommended)")
	fmt.Println("  [2] Run once (foreground)")
	fmt.Println("  [3] Exit")
	fmt.Println()
	fmt.Print("Choice: ")

	choice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read choice: %w", err)
	}
	choice = strings.TrimSpace(choice)

	fmt.Println()

	switch choice {
	case "1":
		return runInstall(token, "", "")
	case "2":
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigChan
			cancel()
		}()

		fmt.Println("Running in foreground. Press Ctrl+C to stop.")
		return runSteward(ctx, token, "")
	case "3", "":
		fmt.Println("Exiting.")
		return nil
	default:
		return fmt.Errorf("invalid choice %q — enter 1, 2, or 3", choice)
	}
}

// logLevelFromEnv reads CFGMS_LOG_LEVEL and returns the uppercased level string.
// Accepts debug, info, warn, error (case-insensitive). Returns "INFO" for empty
// or unrecognised values.
func logLevelFromEnv() string {
	switch strings.ToLower(os.Getenv("CFGMS_LOG_LEVEL")) {
	case "debug", "info", "warn", "error":
		return strings.ToUpper(os.Getenv("CFGMS_LOG_LEVEL"))
	default:
		return "INFO"
	}
}

// buildHTTPConfig constructs an HTTPConfig from environment variables and the provided arguments.
func buildHTTPConfig(controllerURL string, timeout time.Duration, logger logging.Logger) *registration.HTTPConfig {
	return &registration.HTTPConfig{
		ControllerURL: controllerURL,
		Timeout:       timeout,
		CACertPath:    resolveRegistrationCACertPath(logger),
		Logger:        logger,
	}
}

// resolveRegistrationCACertPath returns the first CA cert path that exists on disk,
// checking in priority order: env var override, platform-standard installer path,
// then empty string (system trust store). See doResolveRegistrationCACertPath for logic.
func resolveRegistrationCACertPath(logger logging.Logger) string {
	return doResolveRegistrationCACertPath(logger, defaultPlatformCACertPath())
}

// doResolveRegistrationCACertPath is the testable core of resolveRegistrationCACertPath.
// platformPath is injected so tests can exercise all priority levels without root access.
func doResolveRegistrationCACertPath(logger logging.Logger, platformPath string) string {
	// Priority 1: explicit env var override.
	if envPath := os.Getenv("CFGMS_HTTP_CA_CERT_PATH"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath
		}
		logger.Warn("CFGMS_HTTP_CA_CERT_PATH set but file not found, falling through", "path", envPath)
	}

	// Priority 2: platform-standard path written by the installer.
	if _, err := os.Stat(platformPath); err == nil {
		logger.Info("Using platform-standard CA cert path", "path", platformPath)
		return platformPath
	}

	// Priority 3: no cert found; caller uses system trust store.
	logger.Info("No CA cert found; using system trust store")
	return ""
}

// defaultPlatformCACertPath returns the OS-specific path where the installer writes
// the controller CA cert, mirroring the path convention used by the install package.
func defaultPlatformCACertPath() string {
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "cfgms", "controller-ca.crt")
	default: // linux and darwin
		return "/etc/cfgms/controller-ca.crt"
	}
}

// approvedRegistration holds the fields returned by the controller after a successful
// registration — either an immediate HTTP 200 or a manual-review poll approval.
// This allows connectWithApprovedRegistration to serve both paths without duplication.
type approvedRegistration struct {
	StewardID        string
	TenantID         string
	Group            string
	TransportAddress string
	ClientCert       string
	ClientKey        string
	CACert           string
	ServerCert       string
	SigningCert      string
	DeviceID         string // stable device identity ID (Issue #2094)
	IdentityKeyPub   string // base64-encoded Ed25519 public key (Issue #2094)
}

// registerAndConnect registers the steward using HTTP REST API
// and then establishes gRPC-over-QUIC connections for ongoing communication.
// Both control plane and data plane use the transport_address from the registration response.
//
// On restart with a valid stored cert and identity, HTTP registration is skipped
// and the steward reconnects directly using the persisted credentials (Issue #1719).
//
// When the steward's mTLS cert is expired but a stored identity and device identity key
// exist, registerAndConnect tries the registration-refresh handshake (Issue #2094) before
// falling through to full HTTP re-registration.
//
// When the controller uses registration.workflow: manual (Issue #1899), the steward
// persists the pending_id locally and polls GET /api/v1/registration/status/{pending_id}
// with exponential backoff (5s → 60s max) until approved, denied, or timed out.
// On restart, the persisted pending_id is resumed rather than creating a new pending record.
func registerAndConnect(ctx context.Context, token string, ks *identity.FileKeyStore, logger logging.Logger) (*client.TransportClient, error) {
	logger.Info("Starting steward connect sequence")

	certStoreDir := defaultCertStoreDir()

	// Attempt cert-reuse reconnect (skips HTTP registration on restart).
	if tc, reconnErr := tryReconnectWithStoredIdentity(ctx, certStoreDir, token, logger); tc != nil {
		return tc, nil
	} else if reconnErr != nil {
		logger.Warn("Stored-identity reconnect failed; checking for expired-cert refresh path", "error", reconnErr)
	}

	// Expired-cert refresh path (Issue #2094): when a stored identity exists and all
	// client certs are expired, attempt the registration-refresh handshake before
	// falling through to full HTTP re-registration.
	if ks != nil && ks.DeviceID() != "" {
		if storedID, loadErr := loadIdentity(certStoreDir); loadErr == nil && storedID != nil {
			certMgr, certMgrErr := cert.NewManager(&cert.ManagerConfig{
				StoragePath:    certStoreDir,
				LoadExistingCA: true,
			})
			if certMgrErr == nil {
				if certs, listErr := certMgr.ListCertificates(); listErr == nil && hasExpiredClientCert(certs) {
					tc, refreshErr := refreshAndConnect(ctx, storedID, ks, certStoreDir, token, logger)
					if refreshErr == nil {
						return tc, nil
					}
					if errors.Is(refreshErr, registration.ErrRefreshPending) {
						logger.Warn("Registration refresh pending operator approval; retry later",
							"device_id", logging.SanitizeLogValue(ks.DeviceID()))
						return nil, refreshErr
					}
					if errors.Is(refreshErr, registration.ErrRefreshRejected) {
						logger.Error("Registration refresh rejected; steward must be manually re-admitted",
							"device_id", logging.SanitizeLogValue(ks.DeviceID()))
						return nil, refreshErr
					}
					logger.Warn("Registration refresh failed; falling back to HTTP re-registration", "error", refreshErr)
				}
			}
		}
	}

	logger.Info("Registering steward via HTTP API")

	controllerURL := ControllerURL
	if controllerURL == "" {
		return nil, fmt.Errorf("controller URL not set: binary must be built with " +
			"-ldflags \"-X main.ControllerURL=https://your-controller.example.com\". " +
			"See docs/deployment/ for build instructions")
	}

	httpClient, err := registration.NewHTTPClient(buildHTTPConfig(controllerURL, 30*time.Second, logger))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP registration client: %w", err)
	}

	// Load the approval poll timeout from optional local config (default: 24h).
	pollTimeout := 24 * time.Hour
	if cfg, cfgErr := stewardconfig.LoadConfiguration(""); cfgErr == nil && cfg.Steward.RegistrationPollTimeout > 0 {
		pollTimeout = cfg.Steward.RegistrationPollTimeout
	}

	// Resume a pending registration from a previous run if one exists.
	// This avoids creating a duplicate pending record on every steward restart (Issue #1899).
	if pendingState, loadErr := loadPendingState(certStoreDir); loadErr != nil {
		logger.Warn("Failed to load pending registration state; re-registering", "error", loadErr)
	} else if pendingState != nil {
		logger.Info("Resuming pending registration from previous run",
			"pending_id", logging.SanitizeLogValue(pendingState.PendingID))
		approved, pollErr := pollForApproval(ctx, httpClient, pendingState.PendingID, token,
			pollTimeout, 5*time.Second, 60*time.Second, logger)
		if pollErr != nil {
			_ = clearPendingState(certStoreDir)
			return nil, pollErr
		}
		if approved != nil {
			enrichApprovedWithDeviceIdentity(approved, ks)
			_ = clearPendingState(certStoreDir)
			return connectWithApprovedRegistration(ctx, *approved, certStoreDir, token, logger)
		}
		// approved == nil: pending record expired (HTTP 410); fall through to fresh registration.
		logger.Info("Persisted pending record expired on controller; performing fresh registration")
		if clearErr := clearPendingState(certStoreDir); clearErr != nil {
			logger.Warn("Failed to clear stale pending state file", "error", clearErr)
		}
	}

	regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
	defer regCancel()

	regReq := registration.RegistrationRequest{Token: token}
	if ks != nil && ks.DeviceID() != "" {
		regReq.DeviceID = ks.DeviceID()
		if pub := ks.PublicKey(); pub != nil {
			regReq.IdentityKeyPub = base64.StdEncoding.EncodeToString([]byte(pub))
		}
	}

	regResp, pendingResp, err := httpClient.Register(regCtx, regReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP registration failed: %w", err)
	}

	if pendingResp != nil {
		// Controller returned HTTP 202: registration is pending operator approval.
		// Persist the pending_id so restarts resume this record rather than creating
		// a duplicate (Issue #1899).
		logger.Info("Registration is pending operator approval — polling for approval",
			"pending_id", logging.SanitizeLogValue(pendingResp.PendingID),
			"steward_id", logging.SanitizeLogValue(pendingResp.StewardID),
			"tenant_id", logging.SanitizeLogValue(pendingResp.TenantID))
		if saveErr := savePendingState(certStoreDir, PendingState{PendingID: pendingResp.PendingID}); saveErr != nil {
			logger.Warn("Failed to persist pending registration ID; restart will re-register", "error", saveErr)
		}
		approved, pollErr := pollForApproval(ctx, httpClient, pendingResp.PendingID, token,
			pollTimeout, 5*time.Second, 60*time.Second, logger)
		if pollErr != nil {
			_ = clearPendingState(certStoreDir)
			return nil, pollErr
		}
		if approved == nil {
			// 410 immediately after registration — controller record vanished unexpectedly.
			_ = clearPendingState(certStoreDir)
			return nil, fmt.Errorf("registration approval timed out after %s; re-run with a fresh token if needed", pollTimeout)
		}
		enrichApprovedWithDeviceIdentity(approved, ks)
		_ = clearPendingState(certStoreDir)
		return connectWithApprovedRegistration(ctx, *approved, certStoreDir, token, logger)
	}

	// Immediate approval (HTTP 200): proceed directly to transport setup.
	logger.Info("Registration successful via HTTP",
		"steward_id", regResp.StewardID,
		"tenant_id", regResp.TenantID,
		"group", regResp.Group,
		"transport_address", regResp.TransportAddress)

	bundle := approvedRegistration{
		StewardID:        regResp.StewardID,
		TenantID:         regResp.TenantID,
		Group:            regResp.Group,
		TransportAddress: regResp.TransportAddress,
		ClientCert:       regResp.ClientCert,
		ClientKey:        regResp.ClientKey,
		CACert:           regResp.CACert,
		ServerCert:       regResp.ServerCert,
		SigningCert:      regResp.SigningCert,
	}
	enrichApprovedWithDeviceIdentity(&bundle, ks)
	return connectWithApprovedRegistration(ctx, bundle, certStoreDir, token, logger)
}

// pollForApproval polls GET /api/v1/registration/status/{pendingID} with exponential
// backoff until the controller approves, denies, or the timeout is reached.
//
// Intervals grow from initialInterval up to maxInterval. Pass initialInterval=0 to
// skip all sleeps (useful in tests via the PollStatus(0,0) pass-through).
//
// Returns:
//   - (*approvedRegistration, nil) when approved (status "claimed" with cert fields)
//   - (nil, nil) when the pending record expired (HTTP 410) — caller should re-register
//   - (nil, error) on denial, timeout, or context cancellation
func pollForApproval(
	ctx context.Context,
	httpClient *registration.HTTPClient,
	pendingID, regToken string,
	pollTimeout, initialInterval, maxInterval time.Duration,
	logger logging.Logger,
) (*approvedRegistration, error) {
	pollCtx, pollCancel := context.WithTimeout(ctx, pollTimeout)
	defer pollCancel()

	const pollJitter = 2 * time.Second
	currentInterval := initialInterval

	for {
		jitter := pollJitter
		if currentInterval == 0 {
			jitter = 0
		}

		resp, err := httpClient.PollStatus(pollCtx, pendingID, regToken, currentInterval, jitter)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return nil, fmt.Errorf("registration approval timed out after %s; re-run with a fresh token if needed", pollTimeout)
			}
			// Transient network error — log and retry with unchanged interval.
			logger.Warn("Transient error polling registration status; will retry", "error", err)
			continue
		}

		switch resp.Status {
		case "claimed":
			if resp.ClientCert == "" {
				// HTTP 410: pending record expired or already claimed by another process.
				logger.Info("Pending registration record expired or already claimed; will re-register")
				return nil, nil
			}
			logger.Info("Registration approved by operator",
				"steward_id", logging.SanitizeLogValue(resp.StewardID),
				"tenant_id", logging.SanitizeLogValue(resp.TenantID))
			return &approvedRegistration{
				StewardID:        resp.StewardID,
				TenantID:         resp.TenantID,
				Group:            resp.Group,
				TransportAddress: resp.TransportAddress,
				ClientCert:       resp.ClientCert,
				ClientKey:        resp.ClientKey,
				CACert:           resp.CACert,
				ServerCert:       resp.ServerCert,
				SigningCert:      resp.SigningCert,
			}, nil

		case "denied":
			return nil, fmt.Errorf("registration denied by operator")

		default:
			// "pending" or any other status — keep polling with backoff.
			logger.Info("Registration still pending operator approval; polling",
				"pending_id", logging.SanitizeLogValue(pendingID),
				"status", logging.SanitizeLogValue(resp.Status))
			if currentInterval > 0 && maxInterval > 0 {
				currentInterval = min(currentInterval*2, maxInterval)
			}
		}
	}
}

// connectWithApprovedRegistration persists the steward identity from an approved
// registration (immediate or manual-review poll), then builds and connects the
// transport client. Shared by the immediate-approval and poll-approval paths to
// avoid duplication.
func connectWithApprovedRegistration(
	ctx context.Context,
	reg approvedRegistration,
	certStoreDir, token string,
	logger logging.Logger,
) (*client.TransportClient, error) {
	// Persist the identity record so that a subsequent restart can reconnect
	// without HTTP re-registration (Issue #1719).
	persistedID := StewardIdentity{
		StewardID:        reg.StewardID,
		TenantID:         reg.TenantID,
		TransportAddress: reg.TransportAddress,
		CACertPEM:        reg.CACert,
		ServerCertPEM:    reg.ServerCert,
		SigningCertPEM:   reg.SigningCert,
		DeviceID:         reg.DeviceID,
		IdentityKeyPub:   reg.IdentityKeyPub,
	}
	if saveErr := saveIdentity(certStoreDir, persistedID); saveErr != nil {
		logger.Warn("Failed to persist steward identity; next restart will re-register", "error", saveErr)
	} else {
		logger.Info("Steward identity persisted for restart reuse", "steward_id", persistedID.StewardID)
	}

	// Optionally load the local steward config to apply custom replay window,
	// params-size limits, upgrade policy, and DNA refresh interval.
	// If no config file is found (the common case when the steward is purely
	// controller-managed), defaults apply.
	var commandReplayWindow time.Duration
	var commandMaxParamsBytes int
	var scriptSigning stewardconfig.ScriptSigningConfig
	var upgradeAllowDowngrade bool
	var dnaRefreshInterval time.Duration
	if cfg, cfgErr := stewardconfig.LoadConfiguration(""); cfgErr == nil {
		commandReplayWindow = cfg.Steward.SignedCommandReplayWindow
		commandMaxParamsBytes = cfg.Steward.SignedCommandMaxParamsBytes
		scriptSigning = cfg.Steward.ScriptSigning
		upgradeAllowDowngrade = cfg.Steward.Upgrade.AllowDowngrade
		dnaRefreshInterval = stewardconfig.GetDNARefreshInterval(cfg)
	}

	// Build cert.Manager and SecretStore for on-demand TLS cert loading and
	// offline queue encryption (Issue #920).
	certMgr, secretStore := buildCertManagerAndSecretStore(reg.ClientCert, reg.ClientKey, logger)

	transportClient, err := client.NewTransportClient(&client.TransportConfig{
		ControllerURL:               reg.TransportAddress,
		RegistrationToken:           token,
		CACertPEM:                   reg.CACert,
		ClientCertPEM:               reg.ClientCert,
		ServerCertPEM:               reg.ServerCert,
		CertManager:                 certMgr,
		SecretStore:                 secretStore,
		SignedCommandReplayWindow:   commandReplayWindow,
		SignedCommandMaxParamsBytes: commandMaxParamsBytes,
		ScriptSigning:               scriptSigning,
		CertStoreDir:                certStoreDir,
		UpgradeAllowDowngrade:       upgradeAllowDowngrade,
		UpgradePublisherTrustStore:  buildTestPublisherTrustStore(logger),
		DNARefreshInterval:          dnaRefreshInterval,
		DNACollector:                newDNACollectorAdapter(logger),
		Logger:                      logger,
		IdentityPersistFunc: func(pems []string, at *time.Time) error {
			cur, loadErr := loadIdentity(certStoreDir)
			if loadErr != nil {
				return fmt.Errorf("persist signing cert: load identity: %w", loadErr)
			}
			if cur == nil {
				return fmt.Errorf("persist signing cert: identity not found")
			}
			cur.SigningCertPEMs = pems
			cur.OverlapExpiresAt = at
			return saveIdentity(certStoreDir, *cur)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create transport client: %w", err)
	}

	transportClient.SetStewardID(reg.StewardID)
	transportClient.SetTenantID(reg.TenantID)

	if err := transportClient.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to controller: %w", err)
	}

	logger.Info("Connected to controller via gRPC transport",
		"transport_address", reg.TransportAddress)

	if err := transportClient.SendHeartbeat(ctx, "healthy", nil); err != nil {
		logger.Warn("Failed to send initial heartbeat", "error", err)
	}

	if err := transportClient.InitializeConfigExecutor(reg.TenantID); err != nil {
		return nil, fmt.Errorf("failed to initialize config executor: %w", err)
	}

	logger.Info("Configuration executor initialized", "tenant_id", reg.TenantID)

	return transportClient, nil
}

// tryReconnectWithStoredIdentity attempts to reconnect using the steward's
// persisted identity record and the client cert already in the cert store,
// skipping HTTP re-registration entirely.
//
// Returns (nil, nil) when no stored identity exists — caller falls through to
// HTTP registration (first run or manually cleared identity).
// Returns (nil, err) when a stored identity exists but reconnect fails — caller
// should log the error and fall back to HTTP registration.
func tryReconnectWithStoredIdentity(ctx context.Context, certStoreDir, token string, logger logging.Logger) (*client.TransportClient, error) {
	id, err := loadIdentity(certStoreDir)
	if err != nil {
		// corrupt/unreadable identity: log and treat as absent so the caller falls through
		logger.Warn("Could not load stored identity; falling back to HTTP registration", "error", err)
		return nil, nil
	}
	if id == nil {
		return nil, nil // first run; no stored identity
	}

	// The reconnect path must be able to verify signed sync_config commands.
	// Without a controller server/signing cert the steward would reconnect but
	// silently reject every signed command, so treat an identity record that
	// lacks both as unusable and fall back to HTTP re-registration.
	if id.ServerCertPEM == "" && id.SigningCertPEM == "" && len(id.SigningCertPEMs) == 0 {
		return nil, fmt.Errorf("stored identity missing controller server/signing certificate; cannot verify signed commands")
	}

	// Load the cert manager from the existing cert store.
	certMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    certStoreDir,
		LoadExistingCA: true,
	})
	if err != nil {
		return nil, fmt.Errorf("cert store not loadable: %w", err)
	}

	// Require at least one valid (non-expired) client cert in the store.
	certs, err := certMgr.ListCertificates()
	if err != nil {
		return nil, fmt.Errorf("cert list unavailable: %w", err)
	}
	if !hasValidClientCert(certs) {
		return nil, fmt.Errorf("no valid client certificate found in cert store")
	}

	logger.Info("Stored identity and cert found; reconnecting without HTTP registration",
		"steward_id", logging.SanitizeLogValue(id.StewardID),
		"tenant_id", logging.SanitizeLogValue(id.TenantID),
		"transport_address", logging.SanitizeLogValue(id.TransportAddress))

	// Best-effort secret store for offline queue encryption.
	var secretStore secretsif.SecretStore
	if sp, spErr := secretsif.GetSecretProvider("steward"); spErr == nil {
		if store, storeErr := sp.CreateSecretStore(map[string]interface{}{}); storeErr == nil {
			secretStore = store
		}
	}

	var commandReplayWindow time.Duration
	var commandMaxParamsBytes int
	var upgradeAllowDowngradeReconnect bool
	var dnaRefreshIntervalReconnect time.Duration
	if cfg, cfgErr := stewardconfig.LoadConfiguration(""); cfgErr == nil {
		commandReplayWindow = cfg.Steward.SignedCommandReplayWindow
		commandMaxParamsBytes = cfg.Steward.SignedCommandMaxParamsBytes
		upgradeAllowDowngradeReconnect = cfg.Steward.Upgrade.AllowDowngrade
		dnaRefreshIntervalReconnect = stewardconfig.GetDNARefreshInterval(cfg)
	}

	transportClient, err := client.NewTransportClient(&client.TransportConfig{
		ControllerURL:               id.TransportAddress,
		RegistrationToken:           token,
		CACertPEM:                   id.CACertPEM,
		ServerCertPEM:               id.ServerCertPEM,
		SigningCertPEM:              id.SigningCertPEM,  // backward compat seed; seeded into SigningCertPEMs in NewTransportClient when SigningCertPEMs is empty
		SigningCertPEMs:             id.SigningCertPEMs, // Issue #1816: mutable rotation set
		CertManager:                 certMgr,
		SecretStore:                 secretStore,
		SignedCommandReplayWindow:   commandReplayWindow,
		SignedCommandMaxParamsBytes: commandMaxParamsBytes,
		CertStoreDir:                certStoreDir,
		UpgradeAllowDowngrade:       upgradeAllowDowngradeReconnect,
		UpgradePublisherTrustStore:  buildTestPublisherTrustStore(logger),
		DNARefreshInterval:          dnaRefreshIntervalReconnect,
		DNACollector:                newDNACollectorAdapter(logger),
		Logger:                      logger,
		IdentityPersistFunc: func(pems []string, at *time.Time) error {
			cur, loadErr := loadIdentity(certStoreDir)
			if loadErr != nil {
				return fmt.Errorf("persist signing cert: load identity: %w", loadErr)
			}
			if cur == nil {
				return fmt.Errorf("persist signing cert: identity not found")
			}
			cur.SigningCertPEMs = pems
			cur.OverlapExpiresAt = at
			return saveIdentity(certStoreDir, *cur)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create transport client: %w", err)
	}

	transportClient.SetStewardID(id.StewardID)
	transportClient.SetTenantID(id.TenantID)

	if err := transportClient.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to controller with stored identity: %w", err)
	}

	logger.Info("Reconnected to controller via stored identity",
		"steward_id", logging.SanitizeLogValue(id.StewardID),
		"transport_address", logging.SanitizeLogValue(id.TransportAddress))

	if err := transportClient.SendHeartbeat(ctx, "healthy", nil); err != nil {
		logger.Warn("Failed to send initial heartbeat after reconnect", "error", err)
	}

	if err := transportClient.InitializeConfigExecutor(id.TenantID); err != nil {
		return nil, fmt.Errorf("failed to initialize config executor: %w", err)
	}

	logger.Info("Configuration executor initialized after reconnect", "tenant_id", logging.SanitizeLogValue(id.TenantID))

	return transportClient, nil
}

// buildTestPublisherTrustStore reads CFGMS_TEST_STEWARD_PUBLISHER_KEY from the
// environment. When set, it returns a trust.TrustStore seeded with the
// base64-encoded Ed25519 public key so E2E upgrade tests can sign binaries with
// the corresponding known private key. Returns nil when the env var is absent or
// the key is malformed — the caller falls back to CFGMSPublisherIdentity().
// This path is never reachable in production because CFGMS_TEST_STEWARD_PUBLISHER_KEY
// is only set in ephemeral test environments.
func buildTestPublisherTrustStore(logger logging.Logger) trust.TrustStore {
	pubKeyBase64 := os.Getenv("CFGMS_TEST_STEWARD_PUBLISHER_KEY")
	if pubKeyBase64 == "" {
		return nil
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		if logger != nil {
			logger.Warn("CFGMS_TEST_STEWARD_PUBLISHER_KEY is set but malformed; ignoring")
		}
		return nil
	}
	ts := trust.NewInMemoryTrustStore()
	_ = ts.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: pubKeyBytes,
		Algorithm: "ed25519",
	})
	if logger != nil {
		logger.Info("Test mode: overriding steward binary publisher trust store (Issue #1948)")
	}
	return ts
}

// hasValidClientCert reports whether certs contains at least one non-expired client certificate.
func hasValidClientCert(certs []*cert.CertificateInfo) bool {
	for _, c := range certs {
		if c.Type == cert.CertificateTypeClient && c.IsValid {
			return true
		}
	}
	return false
}

// hasExpiredClientCert reports true only when certs contains at least one client certificate
// AND every client certificate in the list is expired (IsValid == false).
// Returns false when certs contains no client certificates at all.
func hasExpiredClientCert(certs []*cert.CertificateInfo) bool {
	found := false
	for _, c := range certs {
		if c.Type == cert.CertificateTypeClient {
			found = true
			if c.IsValid {
				return false
			}
		}
	}
	return found
}

// enrichApprovedWithDeviceIdentity sets DeviceID and IdentityKeyPub on reg from ks when available,
// so the identity file persists the device identity across restarts (Issue #2094).
func enrichApprovedWithDeviceIdentity(reg *approvedRegistration, ks *identity.FileKeyStore) {
	if ks == nil || ks.DeviceID() == "" {
		return
	}
	reg.DeviceID = ks.DeviceID()
	if pub := ks.PublicKey(); pub != nil {
		reg.IdentityKeyPub = base64.StdEncoding.EncodeToString([]byte(pub))
	}
}

// refreshAndConnect performs the registration-refresh handshake (ADR-011, Issue #2094)
// for a steward whose mTLS cert has expired. The handshake proves device identity via
// an Ed25519 proof-of-possession signature over a server-issued nonce.
//
// Returns ErrRefreshPending when the controller queues the request for manual approval.
// Returns ErrRefreshRejected when the controller refuses (revoked or dormant device).
// On success, persists the new cert via saveIdentity and reconnects.
func refreshAndConnect(
	ctx context.Context,
	id *StewardIdentity,
	ks *identity.FileKeyStore,
	certStoreDir, token string,
	logger logging.Logger,
) (*client.TransportClient, error) {
	controllerURL := ControllerURL
	if controllerURL == "" {
		return nil, fmt.Errorf("controller URL not set; cannot perform registration refresh")
	}

	httpClient, err := registration.NewHTTPClient(buildHTTPConfig(controllerURL, 30*time.Second, logger))
	if err != nil {
		return nil, fmt.Errorf("create HTTP client for refresh: %w", err)
	}

	logger.Info("Attempting registration-refresh handshake",
		"device_id", logging.SanitizeLogValue(ks.DeviceID()),
		"steward_id", logging.SanitizeLogValue(id.StewardID))

	challengeCtx, challengeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer challengeCancel()

	challenge, err := httpClient.RefreshChallenge(challengeCtx, ks.DeviceID())
	if err != nil {
		return nil, fmt.Errorf("refresh challenge: %w", err)
	}

	// Decode the nonce from base64url.
	nonceBytes, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode refresh nonce: %w", err)
	}

	// Compute the PoP digest: sha256(nonce_bytes || device_id_utf8 || server_ts_big_endian_uint64)
	// per ADR-011 §4. This formula must match the controller's implementation exactly.
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], challenge.ServerTS)

	digestInput := make([]byte, 0, len(nonceBytes)+len(ks.DeviceID())+8)
	digestInput = append(digestInput, nonceBytes...)
	digestInput = append(digestInput, []byte(ks.DeviceID())...)
	digestInput = append(digestInput, tsBuf[:]...)
	digest := sha256.Sum256(digestInput)

	pop, err := ks.Sign(digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign refresh digest: %w", err)
	}

	completeCtx, completeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer completeCancel()

	completeResp, err := httpClient.RefreshComplete(completeCtx, ks.DeviceID(), challenge.Nonce, pop)
	if err != nil {
		return nil, err // ErrRefreshPending or ErrRefreshRejected propagated to caller
	}

	logger.Info("Registration refresh approved; storing new certificate",
		"steward_id", logging.SanitizeLogValue(id.StewardID))

	// Persist the refreshed identity with updated certs.
	// The controller's refresh response does not include TransportAddress or ServerCert
	// (the connection endpoint and signing cert do not change during cert refresh).
	// Preserve the stored values as authoritative fallbacks so the reconnect succeeds
	// even when the controller omits those optional fields.
	updatedID := *id
	updatedID.CACertPEM = completeResp.CACert
	if completeResp.ServerCert != "" {
		updatedID.ServerCertPEM = completeResp.ServerCert
	}
	if completeResp.TransportAddress != "" {
		updatedID.TransportAddress = completeResp.TransportAddress
	}
	if saveErr := saveIdentity(certStoreDir, updatedID); saveErr != nil {
		logger.Warn("Failed to persist refreshed identity; next restart may re-register", "error", saveErr)
	}

	bundle := approvedRegistration{
		StewardID:        id.StewardID,
		TenantID:         id.TenantID,
		TransportAddress: updatedID.TransportAddress,
		ClientCert:       completeResp.ClientCert,
		ClientKey:        completeResp.ClientKey,
		CACert:           completeResp.CACert,
		ServerCert:       updatedID.ServerCertPEM,
	}
	enrichApprovedWithDeviceIdentity(&bundle, ks)
	return connectWithApprovedRegistration(ctx, bundle, certStoreDir, token, logger)
}

// buildCertManagerAndSecretStore initialises a cert.Manager (holding the
// steward's client certificate for on-demand TLS loading) and a SecretStore
// (for offline queue encryption key persistence). Both are best-effort — a nil
// return from either does not prevent the steward from connecting, it just
// disables the respective feature.
func buildCertManagerAndSecretStore(clientCertPEM, clientKeyPEM string, logger logging.Logger) (*cert.Manager, secretsif.SecretStore) {
	// ── SecretStore ──────────────────────────────────────────────────────────
	var secretStore secretsif.SecretStore
	secretsProvider, err := secretsif.GetSecretProvider("steward")
	if err == nil {
		if store, storeErr := secretsProvider.CreateSecretStore(map[string]interface{}{}); storeErr == nil {
			secretStore = store
		} else {
			logger.Warn("Failed to create steward secret store; offline-queue key will not persist", "error", storeErr)
		}
	} else {
		logger.Warn("Steward secrets provider unavailable; offline-queue key will not persist", "error", err)
	}

	// ── cert.Manager ─────────────────────────────────────────────────────────
	if clientCertPEM == "" || clientKeyPEM == "" {
		return nil, secretStore
	}

	certStorePath := defaultCertStoreDir()

	// Try to load an existing local CA (created on a previous run).
	certMgr, mgrErr := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    certStorePath,
		LoadExistingCA: true,
	})
	if mgrErr != nil {
		// First run — create a local CA used only as a cert store.
		certMgr, mgrErr = cert.NewManager(&cert.ManagerConfig{
			StoragePath:    certStorePath,
			LoadExistingCA: false,
			CAConfig: &cert.CAConfig{
				Organization: "CFGMS Steward",
				Country:      "US",
				ValidityDays: 3650,
			},
		})
		if mgrErr != nil {
			logger.Warn("Failed to create cert.Manager; on-demand TLS cert loading disabled", "error", mgrErr)
			return nil, secretStore
		}
	}

	// Import the client cert+key from the registration response.
	if _, impErr := certMgr.ImportCertificate(
		[]byte(clientCertPEM), []byte(clientKeyPEM), cert.CertificateTypeClient,
	); impErr != nil {
		logger.Warn("Failed to import client certificate into cert.Manager", "error", impErr)
		return nil, secretStore
	}

	return certMgr, secretStore
}

// defaultCertStoreDir returns the platform-specific stable directory for the
// steward's on-demand client certificate store. Uses the same path convention
// as the StewardProvider's defaultSecretsDir so operators find both under the
// same platform root (e.g. /var/lib/cfgms/ on Linux).
func defaultCertStoreDir() string {
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "cfgms", "steward", "certs")
	case "darwin":
		home, _ := os.UserHomeDir()
		if home == "" {
			home = "/tmp"
		}
		return filepath.Join(home, "Library", "Application Support", "cfgms", "steward", "certs")
	default:
		return "/var/lib/cfgms/steward/certs"
	}
}

// upgradeEventPublisher is the minimal interface required by checkUpgradeFlagFiles
// to emit upgrade lifecycle events. Satisfied by *client.TransportClient.
type upgradeEventPublisher interface {
	GetStewardID() string
	GetTenantID() string
}

// checkUpgradeFlagFiles reads launcher-written flag files in certStoreDir and
// emits the corresponding upgrade lifecycle events, then deletes each file.
//
// Flag files written by the launcher after a supervised restart:
//   - certStoreDir/upgrade-committed: new version passed its startup window.
//   - certStoreDir/upgrade-rolled-back: launcher auto-rolled-back to previous version.
//
// Each file's content is the version string (e.g. "v1.2.3\n") so the event
// carries the version. Missing or unreadable files are silently ignored.
// (Issue #1943)
func checkUpgradeFlagFiles(ctx context.Context, certStoreDir string, tc upgradeEventPublisher, logger logging.Logger) {
	files := []struct {
		name      string
		eventType string
	}{
		{"upgrade-committed", string(cpTypes.EventStewardUpgradeCommitted)},
		{"upgrade-rolled-back", string(cpTypes.EventStewardUpgradeRolledBack)},
	}

	for _, f := range files {
		flagPath := filepath.Join(certStoreDir, f.name)
		raw, err := os.ReadFile(flagPath) //#nosec G304 -- certStoreDir is from defaultCertStoreDir()
		if err != nil {
			if !os.IsNotExist(err) {
				logger.Warn("Could not read upgrade flag file",
					"path", flagPath, "error", err.Error())
			}
			continue
		}
		version := strings.TrimSpace(string(raw))
		logger.Info("Upgrade flag file detected",
			"flag", f.name, "version", version)

		// Emit the event before deleting the flag so a crash between the two
		// results in re-emitting on the next start (idempotent from the
		// controller's perspective) rather than silently losing the event.
		if pubErr := publishUpgradeLifecycleEvent(ctx, tc, f.eventType, version, logger); pubErr != nil {
			logger.Warn("Failed to publish upgrade lifecycle event",
				"event_type", f.eventType, "error", pubErr.Error())
		}

		if delErr := os.Remove(flagPath); delErr != nil && !os.IsNotExist(delErr) {
			logger.Warn("Failed to delete upgrade flag file",
				"path", flagPath, "error", delErr.Error())
		}
	}
}

// publishUpgradeLifecycleEvent emits a single upgrade lifecycle event via the
// transport client's control plane. Returns an error if the publish fails.
func publishUpgradeLifecycleEvent(ctx context.Context, tc upgradeEventPublisher, eventType, version string, logger logging.Logger) error {
	// TransportClient embeds publishEventWithQueue but that method is unexported.
	// Cast to the concrete type — main.go is in the same binary and this cast
	// is safe because main always creates a *client.TransportClient.
	type eventPublisher interface {
		upgradeEventPublisher
		PublishUpgradeLifecycleEvent(ctx context.Context, eventType, version string) error
	}
	if ep, ok := tc.(eventPublisher); ok {
		return ep.PublishUpgradeLifecycleEvent(ctx, eventType, version)
	}
	// Fallback: log the event locally when the interface is not satisfied.
	logger.Info("Upgrade lifecycle event (no control plane publish)",
		"event_type", eventType, "version", version)
	return nil
}

// dnaCollectorAdapter adapts dna.Collector to the client.DNACollector interface
// by extracting the Attributes map from the proto DNA result. (Issue #1915)
type dnaCollectorAdapter struct {
	collector *dna.Collector
}

func newDNACollectorAdapter(logger logging.Logger) *dnaCollectorAdapter {
	return &dnaCollectorAdapter{collector: dna.NewCollector(logger)}
}

func (a *dnaCollectorAdapter) CollectAttributes(ctx context.Context) (map[string]string, error) {
	result, err := a.collector.Collect(ctx)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.Attributes, nil
}
