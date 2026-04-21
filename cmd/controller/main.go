// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cfgis/cfgms/cmd/controller/service"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/features/controller/server"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/version"
	"github.com/spf13/cobra"

	// Import logging providers to register them
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/timescale"

	// Import storage providers to register them
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func main() {
	rootCmd := buildRootCommand()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// buildRootCommand constructs the cobra command tree for cfgms-controller.
func buildRootCommand() *cobra.Command {
	var (
		configPath string
		initMode   bool
	)

	root := &cobra.Command{
		Use:   "cfgms-controller",
		Short: "CFGMS Controller — fleet configuration management controller",
		Long: fmt.Sprintf(`CFGMS Controller %s

Manages fleet-wide configuration distribution, CA issuance, and steward registration.

Entry paths:
  cfgms-controller --config /etc/cfgms/controller.cfg   Run in foreground
  cfgms-controller --init --config /path/to/config      First-run initialization
  cfgms-controller install --config /path/to/config     Install as OS service
  cfgms-controller status                               Show service status`, version.Short()),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runController(configPath, initMode)
		},
	}

	root.Flags().StringVar(&configPath, "config", "", "Path to configuration file (default: search /etc/cfgms/controller.cfg, then ./controller.cfg)")
	root.Flags().BoolVar(&initMode, "init", false, "Perform first-run initialization (creates CA, storage, RBAC defaults)")

	root.AddCommand(
		buildInstallCommand(),
		buildUninstallCommand(),
		buildStatusCommand(),
	)

	return root
}

// runController starts the controller server (or runs --init and exits).
func runController(configPath string, initMode bool) error {
	cfg, err := config.LoadWithPath(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Guard: reject deprecated git provider before any initialization
	if cfg.Storage != nil && cfg.Storage.Provider == "git" {
		return fmt.Errorf("the 'git' storage provider has been removed; " +
			"run 'cfg storage migrate --from git --to flatfile' to migrate your data, " +
			"then update your configuration to use 'flatfile' or 'database'")
	}

	loggingConfig := &logging.LoggingConfig{
		Provider:          getLogProvider(cfg),
		Level:             strings.ToUpper(cfg.LogLevel),
		ServiceName:       "controller",
		Component:         "main",
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
		AsyncWrites:       true,
		BatchSize:         100,
		FlushInterval:     5 * time.Second,
		RetentionDays:     90,
		Config:            getLogProviderConfig(cfg),
	}

	if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
		return fmt.Errorf("failed to initialize global logging: %w", err)
	}

	logging.InitializeGlobalLoggerFactory("controller", "main")
	logger := logging.ForComponent("controller")

	// Handle --init mode: perform first-run initialization and exit.
	if initMode {
		logger.Info("Starting controller first-run initialization...", "operation", "init")
		result, err := initialization.Run(cfg, logger)
		if err != nil {
			return fmt.Errorf("initialization failed: %w", err)
		}

		fmt.Println("Controller initialization complete:")
		fmt.Printf("  CA Fingerprint:    %s\n", result.CAFingerprint)
		fmt.Printf("  Storage Provider:  %s\n", result.StorageProvider)
		fmt.Printf("  Initialized At:    %s\n", result.InitializedAt.Format(time.RFC3339))
		fmt.Println("\nThe controller is now ready to start with: cfgms-controller --config <path>")
		return nil
	}

	legacyLogger := logging.GetLogger()
	srv, err := server.New(cfg, legacyLogger)
	if err != nil {
		return fmt.Errorf("failed to create controller server: %w", err)
	}

	logger.Info("Starting controller server",
		"operation", "server_start",
		"log_provider", loggingConfig.Provider,
		"service_name", "controller")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil {
			logger.Fatal("Controller server failed",
				"operation", "server_run",
				"error", err.Error())
		}
	}()

	sig := <-sigChan
	logger.Info("Received signal, shutting down controller...",
		"operation", "server_shutdown",
		"signal", sig.String())

	if err := srv.Stop(); err != nil {
		logger.Error("Error during controller shutdown",
			"operation", "server_shutdown",
			"error", err.Error())
	}

	logger.Info("Controller shutdown completed",
		"operation", "server_shutdown",
		"status", "completed")
	return nil
}

// buildInstallCommand builds the `cfgms-controller install` subcommand.
func buildInstallCommand() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Copy binary to platform path and register as OS service",
		Long: `Install copies the cfgms-controller binary to the platform-standard location
and registers it as a persistent OS service that starts automatically on boot.

Platforms:
  Windows  C:\Program Files\CFGMS\cfgms-controller.exe  (Windows Service)
  Linux    /usr/local/bin/cfgms-controller               (systemd)
  macOS    /usr/local/bin/cfgms-controller               (launchd)

Requires elevated privileges (Administrator on Windows, root on Linux/macOS).
Install is idempotent: running it again updates the binary and restarts the service.

If the controller has not been initialized yet (no CA present), --init is run
automatically before the service is started.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(configPath)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to configuration file (required)")
	if err := cmd.MarkFlagRequired("config"); err != nil {
		panic(err) // programming error: flag name mismatch
	}

	return cmd
}

// buildUninstallCommand builds the `cfgms-controller uninstall` subcommand.
func buildUninstallCommand() *cobra.Command {
	var purge bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the OS service",
		Long: `Uninstall stops the running cfgms-controller service and removes the service
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

// buildStatusCommand builds the `cfgms-controller status` subcommand.
func buildStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show service state, install path, config path, and CA fingerprint",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus()
		},
	}
}

// runInstall performs the install operation for the current platform.
// If the controller has not been initialized, it runs --init before registering
// the OS service.
func runInstall(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("--config is required for install")
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

	// Check whether the controller needs first-run initialization.
	cfg, err := config.LoadWithPath(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration from %s: %w", configPath, err)
	}

	caPath := ""
	if cfg.Certificate != nil {
		caPath = cfg.Certificate.CAPath
	}

	if caPath != "" && !initialization.IsInitialized(caPath) {
		fmt.Println("Controller not yet initialized — running --init...")
		loggingConfig := &logging.LoggingConfig{
			Provider:    getLogProvider(cfg),
			Level:       "INFO",
			ServiceName: "controller",
			Component:   "install",
			Config:      getLogProviderConfig(cfg),
		}
		if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
			return fmt.Errorf("failed to initialize logging: %w", err)
		}
		logging.InitializeGlobalLoggerFactory("controller", "install")
		logger := logging.ForComponent("controller")

		result, err := initialization.Run(cfg, logger)
		if err != nil {
			return fmt.Errorf("controller initialization failed: %w", err)
		}
		fmt.Printf("  CA Fingerprint:    %s\n", result.CAFingerprint)
		fmt.Printf("  Storage Provider:  %s\n", result.StorageProvider)
		fmt.Println()
	}

	return mgr.Install(configPath)
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

	fmt.Printf("CFGMS Controller %s\n\n", version.Short())
	fmt.Printf("  Service name:  %s\n", status.ServiceName)
	fmt.Printf("  Install path:  %s\n", status.InstallPath)

	configPath := status.ConfigPath
	if configPath == "" {
		configPath = "(not installed)"
	}
	fmt.Printf("  Config path:   %s\n", configPath)

	// Try to read CA fingerprint from the initialization marker.
	caFingerprint := caFingerprintFromConfig(configPath)
	fmt.Printf("  CA fingerprint: %s\n", caFingerprint)

	if !status.Installed {
		fmt.Printf("  Status:        not installed\n")
		fmt.Printf("\n  To install: cfgms-controller install --config /etc/cfgms/controller.cfg\n")
		return nil
	}

	state := "stopped"
	if status.Running {
		state = "running"
	}
	fmt.Printf("  Status:        %s\n", state)
	return nil
}

// caFingerprintFromConfig loads the controller config and reads the CA fingerprint
// from the initialization marker. Returns a human-friendly string in all cases.
func caFingerprintFromConfig(configPath string) string {
	if configPath == "" || configPath == "(not installed)" {
		return "(unknown — service not installed)"
	}

	cfg, err := config.LoadWithPath(configPath)
	if err != nil {
		return fmt.Sprintf("(unavailable — cannot load config: %v)", err)
	}

	if cfg.Certificate == nil || cfg.Certificate.CAPath == "" {
		return "(unavailable — CA path not configured)"
	}

	marker, err := initialization.ReadInitMarker(cfg.Certificate.CAPath)
	if err != nil {
		return "(unavailable — controller not yet initialized)"
	}

	return marker.CAFingerprint
}

// getLogProvider determines the logging provider from configuration.
func getLogProvider(cfg *config.Config) string {
	if cfg.Logging != nil && cfg.Logging.Provider != "" {
		return cfg.Logging.Provider
	}
	return "file"
}

// getLogProviderConfig creates provider-specific configuration.
func getLogProviderConfig(cfg *config.Config) map[string]interface{} {
	if cfg.Logging != nil && cfg.Logging.Config != nil && len(cfg.Logging.Config) > 0 {
		return cfg.Logging.Config
	}

	provider := getLogProvider(cfg)

	switch provider {
	case "timescale":
		password := os.Getenv("CFGMS_TIMESCALE_PASSWORD")
		if password == "" {
			log.Fatal("FATAL: CFGMS_TIMESCALE_PASSWORD environment variable is required when using " +
				"timescale logging provider. Set this variable or configure logging.config.password " +
				"in the config file. See QUICK_START.md for configuration examples.")
		}
		host := os.Getenv("CFGMS_TIMESCALE_HOST")
		if host == "" {
			host = "localhost"
		}
		port := os.Getenv("CFGMS_TIMESCALE_PORT")
		if port == "" {
			port = "5432"
		}
		database := os.Getenv("CFGMS_TIMESCALE_DATABASE")
		if database == "" {
			database = "cfgms"
		}
		username := os.Getenv("CFGMS_TIMESCALE_USER")
		if username == "" {
			username = "cfgms"
		}
		sslMode := os.Getenv("CFGMS_TIMESCALE_SSLMODE")
		if sslMode == "" {
			sslMode = "require"
		}
		return map[string]interface{}{
			"host":     host,
			"port":     port,
			"database": database,
			"username": username,
			"password": password,
			"ssl_mode": sslMode,
		}

	default:
		return map[string]interface{}{
			"directory":        "/var/log/cfgms",
			"max_file_size":    int64(100 * 1024 * 1024),
			"max_files":        10,
			"compress_rotated": true,
		}
	}
}
