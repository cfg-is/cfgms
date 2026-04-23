// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/logging"
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
		opMode     string
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
			return runRootCommand(cmd, regToken, configPath, opMode)
		},
	}

	// Flags used by the root command (foreground run mode).
	root.Flags().StringVar(&configPath, "config", "", "Path to configuration file (enables standalone mode)")
	root.Flags().StringVar(&opMode, "mode", "", "Operation mode: 'standalone' or 'controller'")
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
func runRootCommand(cmd *cobra.Command, regToken, configPath, opMode string) error {
	// Interactive mode: no flags set and no subcommand selected.
	noFlags := regToken == "" && configPath == "" && opMode == ""
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

	return runSteward(ctx, regToken, configPath, opMode)
}

// runSteward starts the steward with the given configuration and blocks until
// ctx is cancelled. It is called from both the root cobra command and the
// Windows service handler.
func runSteward(ctx context.Context, regToken, configPath, opMode string) error {
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

	logging.InitializeGlobalLoggerFactory("steward", "main")
	logger := logging.ForComponent("steward")

	// gRPC transport registration flow.
	if regToken != "" {
		tokenPrefix := regToken
		if len(regToken) > 15 {
			tokenPrefix = regToken[:15] + "..."
		}
		logger.Info("Using registration token for auto-registration (gRPC transport mode)",
			"operation", "registration_init",
			"token_prefix", tokenPrefix)

		transportCl, err := registerAndConnect(ctx, regToken, logger)
		if err != nil {
			return fmt.Errorf("failed to register with controller: %w", err)
		}

		logger.Info("Steward registered and connected successfully via gRPC transport",
			"operation", "registration_complete",
			"steward_id", transportCl.GetStewardID(),
			"tenant_id", transportCl.GetTenantID())

		logger.Info("Running in gRPC controller-connected mode",
			"operation", "steward_mode",
			"mode", "grpc_transport")

		// Start scheduled convergence loop. The initial interval defaults to
		// 30 minutes. When the controller delivers a cfg, the loop reads
		// converge_interval from it and resets the ticker accordingly.
		// sync_config commands from the controller also trigger immediate
		// convergence as an out-of-band optimization on top of the schedule.
		transportCl.StartConvergenceLoop(ctx)

		// Wait for context cancellation (signal or SCM stop).
		<-ctx.Done()
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

	// Standalone or legacy controller mode.
	useStandalone := configPath != "" || opMode == "standalone"

	var s *steward.Steward
	var err error

	legacyLogger := logging.GetLogger()
	if useStandalone {
		s, err = steward.NewStandalone(configPath, legacyLogger)
		if err != nil {
			return fmt.Errorf("failed to create standalone steward: %w", err)
		}
		logger.Info("Starting steward in standalone mode",
			"operation", "steward_start", "mode", "standalone", "config_path", configPath)
	} else {
		// Legacy controller mode was removed in Story #198.
		// Controller-connected stewards use --regtoken (gRPC transport) handled above.
		return fmt.Errorf("standalone mode requires --config flag; for controller mode use --regtoken")
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	<-ctx.Done()
	logger.Info("Shutdown signal received", "operation", "steward_shutdown")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer stopCancel()
	if err := s.Stop(stopCtx); err != nil {
		logger.Error("Error during shutdown", "operation", "steward_shutdown", "error", err.Error())
	}

	if startErr := <-errCh; startErr != nil && startErr != context.Canceled {
		logger.Error("Steward start failed", "operation", "steward_run", "error", startErr.Error())
		return fmt.Errorf("steward start failed: %w", startErr)
	}

	logger.Info("Steward shutdown completed", "operation", "steward_shutdown", "status", "completed")
	return nil
}

// buildInstallCommand builds the `cfgms-steward install` subcommand.
func buildInstallCommand() *cobra.Command {
	var regToken string

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
Install is idempotent: running it again updates the binary and restarts the service.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(regToken)
		},
	}

	cmd.Flags().StringVar(&regToken, "regtoken", "", "Registration token (required)")
	_ = cmd.MarkFlagRequired("regtoken")

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
func runInstall(regToken string) error {
	if regToken == "" {
		return fmt.Errorf("--regtoken is required for install")
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}

	mgr := service.New(exe)

	if !mgr.IsElevated() {
		return fmt.Errorf("install requires elevated privileges\n" +
			"  Windows: right-click the binary and select 'Run as administrator'\n" +
			"  Linux/macOS: re-run with sudo")
	}

	return mgr.Install(regToken)
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
		return runInstall(token)
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
		return runSteward(ctx, token, "", "")
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
// CFGMS_HTTP_CA_CERT_PATH, when set, is used to verify the controller's TLS certificate during registration.
func buildHTTPConfig(controllerURL string, timeout time.Duration, logger logging.Logger) *registration.HTTPConfig {
	return &registration.HTTPConfig{
		ControllerURL: controllerURL,
		Timeout:       timeout,
		CACertPath:    os.Getenv("CFGMS_HTTP_CA_CERT_PATH"),
		Logger:        logger,
	}
}

// registerAndConnect registers the steward using HTTP REST API
// and then establishes gRPC-over-QUIC connections for ongoing communication.
// Both control plane and data plane use the transport_address from the registration response.
func registerAndConnect(ctx context.Context, token string, logger logging.Logger) (*client.TransportClient, error) {
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

	regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
	defer regCancel()

	regResp, err := httpClient.Register(regCtx, token)
	if err != nil {
		return nil, fmt.Errorf("HTTP registration failed: %w", err)
	}

	logger.Info("Registration successful via HTTP",
		"steward_id", regResp.StewardID,
		"tenant_id", regResp.TenantID,
		"group", regResp.Group,
		"transport_address", regResp.TransportAddress)

	transportClient, err := client.NewTransportClient(&client.TransportConfig{
		ControllerURL:     regResp.TransportAddress,
		RegistrationToken: token,
		CACertPEM:         regResp.CACert,
		ClientCertPEM:     regResp.ClientCert,
		ClientKeyPEM:      regResp.ClientKey,
		ServerCertPEM:     regResp.ServerCert,
		Logger:            logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create transport client: %w", err)
	}

	transportClient.SetStewardID(regResp.StewardID)
	transportClient.SetTenantID(regResp.TenantID)

	if err := transportClient.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to controller: %w", err)
	}

	logger.Info("Connected to controller via gRPC transport",
		"transport_address", regResp.TransportAddress)

	if err := transportClient.SendHeartbeat(ctx, "healthy", nil); err != nil {
		logger.Warn("Failed to send initial heartbeat", "error", err)
	}

	if err := transportClient.InitializeConfigExecutor(regResp.TenantID); err != nil {
		return nil, fmt.Errorf("failed to initialize config executor: %w", err)
	}

	logger.Info("Configuration executor initialized", "tenant_id", regResp.TenantID)

	return transportClient, nil
}
