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

	// Import logging providers to register them
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/timescale"

	// Import storage providers to register them
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
)

func main() {
	log.Println("DEBUG: Starting controller main()")

	// Log all HA-related environment variables at startup
	log.Printf("DEBUG: Environment Variables at startup:")
	log.Printf("  CFGMS_NODE_ID=%s", os.Getenv("CFGMS_NODE_ID"))
	log.Printf("  CFGMS_NODE_REGION=%s", os.Getenv("CFGMS_NODE_REGION"))
	log.Printf("  CFGMS_HA_ENABLED=%s", os.Getenv("CFGMS_HA_ENABLED"))
	log.Printf("  CFGMS_HA_MODE=%s", os.Getenv("CFGMS_HA_MODE"))
	log.Printf("  CFGMS_HA_NODE_NAME=%s", os.Getenv("CFGMS_HA_NODE_NAME"))
	log.Printf("  CFGMS_HA_CLUSTER_NODES=%s", os.Getenv("CFGMS_HA_CLUSTER_NODES"))

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	log.Println("DEBUG: Configuration loaded successfully")

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

	log.Println("DEBUG: About to initialize global logging")
	if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
		log.Fatalf("Failed to initialize global logging: %v", err)
	}
	log.Println("DEBUG: Global logging initialized")

	// Initialize global logger factory
	log.Println("DEBUG: About to initialize global logger factory")
	logging.InitializeGlobalLoggerFactory("controller", "main")
	log.Println("DEBUG: Global logger factory initialized")

	// Use global logging provider
	log.Println("DEBUG: About to get logger for component")
	logger := logging.ForComponent("controller")
	log.Println("DEBUG: Logger obtained")

	// For backward compatibility, create legacy logger for server
	log.Println("DEBUG: About to get legacy logger")
	legacyLogger := logging.GetLogger()
	log.Println("DEBUG: Legacy logger obtained, about to create server")
	srv, err := server.New(cfg, legacyLogger)
	if err != nil {
		logger.Fatal("Failed to create controller server",
			"operation", "server_init",
			"error", err.Error())
	}
	log.Println("DEBUG: Server created successfully")

	logger.Info("Starting controller server",
		"operation", "server_start",
		"log_provider", loggingConfig.Provider,
		"service_name", "controller")

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		log.Println("DEBUG: About to call srv.Start()")
		log.Println("DEBUG: Calling srv.Start() now...")
		if err := srv.Start(); err != nil {
			log.Println("DEBUG: srv.Start() failed with error:", err)
			logger.Fatal("Controller server failed",
				"operation", "server_run",
				"error", err.Error())
		}
		log.Println("DEBUG: srv.Start() completed successfully")
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

	// Determine the provider type
	provider := getLogProvider(cfg)

	switch provider {
	case "timescale":
		// TimescaleDB configuration
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

		user := os.Getenv("CFGMS_TIMESCALE_USER")
		if user == "" {
			user = "cfgms"
		}

		password := os.Getenv("CFGMS_TIMESCALE_PASSWORD")
		if password == "" {
			password = "cfgms"
		}

		providerConfig["host"] = host
		providerConfig["port"] = port
		providerConfig["database"] = database
		providerConfig["username"] = user
		providerConfig["password"] = password
		providerConfig["ssl_mode"] = "disable" // For Docker environments

	default:
		// File provider configuration (default)
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

		providerConfig["directory"] = logDir
		providerConfig["max_file_size"] = maxFileSize
		providerConfig["max_files"] = maxFiles
		providerConfig["compress_rotated"] = true
	}

	return providerConfig
}
