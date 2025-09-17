package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/server"
	"github.com/cfgis/cfgms/pkg/logging"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

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
		logger.Fatal("Failed to create controller server",
			"operation", "server_init",
			"error", err.Error())
	}

	logger.Info("Starting controller server",
		"operation", "server_start",
		"log_provider", loggingConfig.Provider,
		"service_name", "controller")

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		if err := srv.Start(); err != nil {
			logger.Fatal("Controller server failed",
				"operation", "server_run",
				"error", err.Error())
		}
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
func getLogProvider(cfg *config.Config) string {
	// Check environment variable for provider
	if provider := os.Getenv("CFGMS_LOG_PROVIDER"); provider != "" {
		return provider
	}

	// Default to file provider for controller (central hub)
	return "file"
}

// getLogProviderConfig creates provider-specific configuration
func getLogProviderConfig(cfg *config.Config) map[string]interface{} {
	providerConfig := make(map[string]interface{})

	// Get configuration from environment variables with defaults
	logDir := os.Getenv("CFGMS_LOG_DIR")
	if logDir == "" {
		logDir = "/var/log/cfgms"
	}

	maxFileSizeStr := os.Getenv("CFGMS_LOG_MAX_FILE_SIZE")
	maxFileSize := int64(100 * 1024 * 1024) // 100MB default
	if maxFileSizeStr != "" {
		if parsed, err := strconv.ParseInt(maxFileSizeStr, 10, 64); err == nil {
			maxFileSize = parsed
		}
	}

	maxFilesStr := os.Getenv("CFGMS_LOG_MAX_FILES")
	maxFiles := 10 // default
	if maxFilesStr != "" {
		if parsed, err := strconv.Atoi(maxFilesStr); err == nil {
			maxFiles = parsed
		}
	}

	// Default file provider configuration for controller
	providerConfig["directory"] = logDir
	providerConfig["max_file_size"] = maxFileSize
	providerConfig["max_files"] = maxFiles
	providerConfig["compress_rotated"] = true

	return providerConfig
}
