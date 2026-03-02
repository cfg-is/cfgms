// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/server"
	"github.com/cfgis/cfgms/pkg/logging"

	// Import logging providers to register them
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/timescale"

	// Import storage providers to register them
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

func main() {
	// Parse CLI flags
	configPath := flag.String("config", "", "Path to configuration file (default: search /etc/cfgms/controller.cfg, then ./controller.cfg)")
	flag.Parse()

	fmt.Printf("[DEBUG] main.go: Controller main() function started\n")
	cfg, err := config.LoadWithPath(*configPath)
	if err != nil {
		fmt.Printf("[DEBUG] main.go: Failed to load config: %v\n", err)
		log.Fatalf("Failed to load configuration: %v", err)
	}
	fmt.Printf("[DEBUG] main.go: Configuration loaded successfully\n")

	// Initialize global logging provider for central hub
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
		RetentionDays:     90, // Longer retention for central hub
		Config:            getLogProviderConfig(cfg),
	}

	if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
		log.Fatalf("Failed to initialize global logging: %v", err)
	}

	// Initialize global logger factory
	logging.InitializeGlobalLoggerFactory("controller", "main")

	// Use global logging provider
	logger := logging.ForComponent("controller")

	// For backward compatibility, create legacy logger for server
	legacyLogger := logging.GetLogger()
	srv, err := server.New(cfg, legacyLogger)
	if err != nil {
		log.Fatalf("FATAL: Failed to create controller server: %v", err)
	}

	fmt.Printf("[DEBUG] main.go: Server created successfully, about to start\n")
	logger.Info("Starting controller server",
		"operation", "server_start",
		"log_provider", loggingConfig.Provider,
		"service_name", "controller")

	fmt.Printf("[DEBUG] main.go: Setting up signal handling\n")
	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("[DEBUG] main.go: Launching Start() goroutine\n")
	// Start server in a goroutine
	go func() {
		fmt.Printf("[DEBUG] main.go: Inside goroutine, about to call srv.Start()\n")
		if err := srv.Start(); err != nil {
			fmt.Printf("[DEBUG] main.go: srv.Start() returned error: %v\n", err)
			logger.Fatal("Controller server failed",
				"operation", "server_run",
				"error", err.Error())
		}
		fmt.Printf("[DEBUG] main.go: srv.Start() completed successfully\n")
	}()

	// Wait for termination signal
	sig := <-sigChan
	logger.Info("Received signal, shutting down controller...",
		"operation", "server_shutdown",
		"signal", sig.String())

	// Graceful shutdown
	if err := srv.Stop(); err != nil {
		logger.Error("Error during controller shutdown",
			"operation", "server_shutdown",
			"error", err.Error())
	}

	logger.Info("Controller shutdown completed",
		"operation", "server_shutdown",
		"status", "completed")
}

// getLogProvider determines the logging provider from configuration
// Note: To customize, use config file with provider: ${CFGMS_LOG_PROVIDER:-file} syntax
func getLogProvider(cfg *config.Config) string {
	// Use config value if available, otherwise default to file
	if cfg.Logging != nil && cfg.Logging.Provider != "" {
		return cfg.Logging.Provider
	}
	return "file"
}

// getLogProviderConfig creates provider-specific configuration
// Note: To customize, use config file with logging.config section and ${ENV_VAR:-default} syntax
func getLogProviderConfig(cfg *config.Config) map[string]interface{} {
	// Use config values if available
	if cfg.Logging != nil && cfg.Logging.Config != nil && len(cfg.Logging.Config) > 0 {
		return cfg.Logging.Config
	}

	// Return sensible defaults if no config provided
	provider := getLogProvider(cfg)

	switch provider {
	case "timescale":
		// TimescaleDB configuration from environment variables
		// CFGMS_TIMESCALE_PASSWORD is REQUIRED — no hardcoded defaults
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
		// File provider defaults
		return map[string]interface{}{
			"directory":        "/var/log/cfgms",
			"max_file_size":    int64(100 * 1024 * 1024), // 100MB
			"max_files":        10,
			"compress_rotated": true,
		}
	}
}
