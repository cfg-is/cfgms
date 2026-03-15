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
	_ "github.com/cfgis/cfgms/pkg/logging/providers/timescale"

	// Import storage providers to register them
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"

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
		configPath  string
		opMode      string
		logLevel    string
		logProvider string
		regToken    string
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
			return runRootCommand(cmd, regToken, configPath, opMode, logLevel, logProvider)
		},
	}

	// Flags used by the root command (foreground run mode).
	root.Flags().StringVar(&configPath, "config", "", "Path to configuration file (enables standalone mode)")
	root.Flags().StringVar(&opMode, "mode", "", "Operation mode: 'standalone' or 'controller'")
	root.Flags().StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn, error")
	root.Flags().StringVar(&logProvider, "log-provider", "file", "Logging provider: file, timescale")
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
func runRootCommand(cmd *cobra.Command, regToken, configPath, opMode, logLevel, logProvider string) error {
	// Interactive mode: no flags set and no subcommand selected.
	noFlags := regToken == "" && configPath == "" && opMode == ""
	if noFlags && !cmd.Flags().Changed("log-level") && !cmd.Flags().Changed("log-provider") {
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

	return runSteward(ctx, regToken, configPath, opMode, logLevel, logProvider)
}

// runSteward starts the steward with the given configuration and blocks until
// ctx is cancelled. It is called from both the root cobra command and the
// Windows service handler.
func runSteward(ctx context.Context, regToken, configPath, opMode, logLevel, logProvider string) error {
	// Initialize global logging provider
	loggingConfig := &logging.LoggingConfig{
		Provider:          logProvider,
		Level:             strings.ToUpper(logLevel),
		ServiceName:       "steward",
		Component:         "main",
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
		AsyncWrites:       true,
		BatchSize:         100,
		FlushInterval:     5 * time.Second,
		RetentionDays:     30,
		Config:            make(map[string]interface{}),
	}

	if logProvider == "file" {
		logDir := os.Getenv("CFGMS_LOG_DIR")
		if logDir == "" {
			logDir = "/tmp/cfgms"
			log.Printf("WARNING: Using /tmp/cfgms for logs — set CFGMS_LOG_DIR for production deployments")
		}
		loggingConfig.Config["directory"] = logDir
	}

	if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
		return fmt.Errorf("failed to initialize global logging: %w", err)
	}

	logging.InitializeGlobalLoggerFactory("steward", "main")
	logger := logging.ForComponent("steward")

	// MQTT+QUIC registration flow.
	if regToken != "" {
		tokenPrefix := regToken
		if len(regToken) > 15 {
			tokenPrefix = regToken[:15] + "..."
		}
		logger.Info("Using registration token for auto-registration (MQTT+QUIC mode)",
			"operation", "registration_init",
			"token_prefix", tokenPrefix)

		mqttCl, err := registerAndConnectMQTT(ctx, regToken, logger)
		if err != nil {
			return fmt.Errorf("failed to register with MQTT: %w", err)
		}

		logger.Info("Steward registered and connected successfully via MQTT",
			"operation", "registration_complete",
			"steward_id", mqttCl.GetStewardID(),
			"tenant_id", mqttCl.GetTenantID())

		logger.Info("Running in MQTT+QUIC controller-connected mode",
			"operation", "steward_mode",
			"mode", "mqtt_quic")

		// Wait for context cancellation (signal or SCM stop).
		<-ctx.Done()
		logger.Info("Shutdown signal received, disconnecting...",
			"operation", "steward_shutdown")

		if err := mqttCl.Disconnect(context.Background()); err != nil {
			logger.Error("Error during MQTT disconnect",
				"operation", "mqtt_disconnect",
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
		cfg := steward.DefaultConfig()
		cfg.LogLevel = logLevel
		s, err = steward.New(cfg, legacyLogger)
		if err != nil {
			return fmt.Errorf("failed to create steward: %w", err)
		}
		logger.Info("Starting steward in controller mode",
			"operation", "steward_start", "mode", "controller")
	}

	go func() {
		if err := s.Start(ctx); err != nil {
			logger.Fatal("Steward failed", "operation", "steward_run", "error", err.Error())
		}
	}()

	<-ctx.Done()
	logger.Info("Shutdown signal received", "operation", "steward_shutdown")

	if err := s.Stop(context.Background()); err != nil {
		logger.Error("Error during shutdown", "operation", "steward_shutdown", "error", err.Error())
	}

	logger.Info("Steward shutdown completed", "operation", "steward_shutdown", "status", "completed")
	return nil
}

// buildInstallCommand builds the `cfgms-steward install` subcommand.
func buildInstallCommand() *cobra.Command {
	var (
		regToken    string
		logLevel    string
		logProvider string
	)

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
			return runInstall(regToken, logLevel, logProvider)
		},
	}

	cmd.Flags().StringVar(&regToken, "regtoken", "", "Registration token (required)")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn, error")
	cmd.Flags().StringVar(&logProvider, "log-provider", "file", "Logging provider: file, timescale")
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
func runInstall(regToken, logLevel, logProvider string) error {
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
		return runInstall(token, "info", "file")
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
		return runSteward(ctx, token, "", "", "info", "file")
	case "3", "":
		fmt.Println("Exiting.")
		return nil
	default:
		return fmt.Errorf("invalid choice %q — enter 1, 2, or 3", choice)
	}
}

// registerAndConnectMQTT registers the steward using HTTP REST API
// and then establishes MQTT+QUIC connections for ongoing communication.
func registerAndConnectMQTT(ctx context.Context, token string, logger logging.Logger) (*client.MQTTClient, error) {
	logger.Info("Registering steward via HTTP API")

	controllerURL := ControllerURL
	if controllerURL == "" {
		return nil, fmt.Errorf("controller URL not set: binary must be built with " +
			"-ldflags \"-X main.ControllerURL=https://your-controller.example.com\". " +
			"See docs/deployment/ for build instructions")
	}

	insecureSkipVerify := false
	if skipVerify := os.Getenv("CFGMS_HTTP_INSECURE_SKIP_VERIFY"); skipVerify == "true" {
		insecureSkipVerify = true
		logger.Warn("HTTP TLS verification disabled (test mode only)")
	}

	httpClient, err := registration.NewHTTPClient(&registration.HTTPConfig{
		ControllerURL:      controllerURL,
		Timeout:            30 * time.Second,
		InsecureSkipVerify: insecureSkipVerify,
		Logger:             logger,
	})
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
		"mqtt_broker", regResp.MQTTBroker)

	mqttBroker := regResp.MQTTBroker
	quicAddress := regResp.QUICAddress

	mqttClient, err := client.NewMQTTClient(&client.MQTTConfig{
		ControllerURL:     mqttBroker,
		QUICAddress:       quicAddress,
		RegistrationToken: token,
		CACertPEM:         regResp.CACert,
		ClientCertPEM:     regResp.ClientCert,
		ClientKeyPEM:      regResp.ClientKey,
		ServerCertPEM:     regResp.ServerCert,
		Logger:            logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MQTT client: %w", err)
	}

	mqttClient.SetStewardID(regResp.StewardID)
	mqttClient.SetTenantID(regResp.TenantID)

	if err := mqttClient.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to MQTT: %w", err)
	}

	logger.Info("Connected to controller via MQTT+QUIC",
		"mqtt_broker", mqttBroker,
		"quic_address", quicAddress)

	if err := mqttClient.SendHeartbeat(ctx, "healthy", nil); err != nil {
		logger.Warn("Failed to send initial heartbeat", "error", err)
	}

	if err := mqttClient.InitializeConfigExecutor(regResp.TenantID); err != nil {
		return nil, fmt.Errorf("failed to initialize config executor: %w", err)
	}

	logger.Info("Configuration executor initialized", "tenant_id", regResp.TenantID)

	return mqttClient, nil
}
