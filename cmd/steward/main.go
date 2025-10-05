package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/pkg/logging"

	// Import logging providers to register them
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/timescale"

	// Import storage providers to register them
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
)

// RegistrationCode represents the decoded registration code structure.
type RegistrationCode struct {
	TenantID      string `json:"tenant_id"`
	ControllerURL string `json:"controller_url"`
	Group         string `json:"group,omitempty"`
	Version       int    `json:"version"`
}

func main() {
	// Parse command line arguments
	var (
		configPath = flag.String("config", "", "Path to configuration file (enables standalone mode)")
		mode       = flag.String("mode", "", "Operation mode: 'standalone' or 'controller' (optional if config provided)")
		logLevel   = flag.String("log-level", "info", "Log level: debug, info, warn, error")
		provider   = flag.String("log-provider", "file", "Logging provider: file, timescale")
		regCode    = flag.String("regcode", "", "Registration code for automatic tenant registration")
	)
	flag.Parse()

	// Initialize global logging provider
	loggingConfig := &logging.LoggingConfig{
		Provider:          *provider,
		Level:             strings.ToUpper(*logLevel),
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

	if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
		log.Fatalf("Failed to initialize global logging: %v", err)
	}

	// Initialize global logger factory
	logging.InitializeGlobalLoggerFactory("steward", "main")

	// Set up logging using global provider
	logger := logging.ForComponent("steward")

	// Decode registration code if provided
	var registration *RegistrationCode
	if *regCode != "" {
		var err error
		registration, err = decodeRegistrationCode(*regCode)
		if err != nil {
			logger.Fatal("Failed to decode registration code",
				"operation", "registration_decode",
				"error", err.Error())
		}

		logger.Info("Registration code decoded successfully",
			"operation", "registration_decode",
			"tenant_id", registration.TenantID,
			"controller_url", registration.ControllerURL,
			"group", registration.Group)

		// TODO: Use registration to configure steward
		// - Set tenant_id for MQTT client credentials
		// - Set controller URL for MQTT broker connection
		// - Set group for optional organization
		// - Generate steward_id with tenant prefix: {tenant_id}-{uuid}
	}

	// Determine operation mode
	useStandalone := *configPath != "" || *mode == "standalone"
	
	var s *steward.Steward
	var err error
	
	if useStandalone {
		// Standalone mode - use hostname.cfg or provided config path
		configFile := *configPath
		if configFile == "" {
			// No config path provided, try to find hostname.cfg
			// This will be handled by the config loader's search logic
			configFile = "" // Default to empty - config loader will search for hostname.cfg
		}

		// For now, create legacy logger for steward constructor (TODO: update steward to use global provider)
		legacyLogger := logging.GetLogger()
		s, err = steward.NewStandalone(configFile, legacyLogger)
		if err != nil {
			logger.Fatal("Failed to create standalone steward",
				"operation", "steward_init",
				"mode", "standalone",
				"config_path", configFile,
				"error", err.Error())
		}

		logger.Info("Starting steward in standalone mode",
			"operation", "steward_start",
			"mode", "standalone",
			"config_path", configFile)
	} else {
		// Controller mode (legacy)
		cfg := steward.DefaultConfig()
		cfg.LogLevel = *logLevel

		// TODO: Load additional configuration from file and environment

		// For now, create legacy logger for steward constructor (TODO: update steward to use global provider)
		legacyLogger := logging.GetLogger()
		s, err = steward.New(cfg, legacyLogger)
		if err != nil {
			logger.Fatal("Failed to create steward",
				"operation", "steward_init",
				"mode", "controller",
				"error", err.Error())
		}

		logger.Info("Starting steward in controller mode",
			"operation", "steward_start",
			"mode", "controller")
	}
	
	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start steward in a goroutine
	go func() {
		if err := s.Start(ctx); err != nil {
			logger.Fatal("Steward failed",
				"operation", "steward_run",
				"error", err.Error())
		}
	}()

	// Wait for termination signal
	sig := <-sigChan
	logger.Info("Received signal, shutting down...",
		"operation", "steward_shutdown",
		"signal", sig.String())

	// Initiate graceful shutdown
	if err := s.Stop(ctx); err != nil {
		logger.Error("Error during shutdown",
			"operation", "steward_shutdown",
			"error", err.Error())
	}

	logger.Info("Steward shutdown completed",
		"operation", "steward_shutdown",
		"status", "completed")
}

// decodeRegistrationCode decodes a base64-encoded registration code.
func decodeRegistrationCode(encoded string) (*RegistrationCode, error) {
	// Decode from base64
	jsonData, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON
	var regCode RegistrationCode
	if err := json.Unmarshal(jsonData, &regCode); err != nil {
		return nil, err
	}

	return &regCode, nil
}
