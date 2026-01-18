// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/logging"

	// Import logging providers to register them
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/timescale"

	// Import storage providers to register them
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

func main() {
	// Parse command line arguments
	var (
		configPath = flag.String("config", "", "Path to configuration file (enables standalone mode)")
		mode       = flag.String("mode", "", "Operation mode: 'standalone' or 'controller' (optional if config provided)")
		logLevel   = flag.String("log-level", "info", "Log level: debug, info, warn, error")
		provider   = flag.String("log-provider", "file", "Logging provider: file, timescale")
		regCode    = flag.String("regcode", "", "Registration code for automatic tenant registration (deprecated, use --regtoken)")
		regToken   = flag.String("regtoken", "", "Registration token for automatic tenant registration")
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

	// Configure file provider if selected
	if *provider == "file" {
		logDir := os.Getenv("CFGMS_LOG_DIR")
		if logDir == "" {
			logDir = "/tmp/cfgms" // Default to /tmp for unprivileged containers
		}
		loggingConfig.Config["directory"] = logDir
	}

	if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
		log.Fatalf("Failed to initialize global logging: %v", err)
	}

	// Initialize global logger factory
	logging.InitializeGlobalLoggerFactory("steward", "main")

	// Set up logging using global provider
	logger := logging.ForComponent("steward")

	// Set up context with cancellation (BEFORE registration)
	// This context is used for long-lived MQTT operations
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Handle registration token
	var mqttClient *client.MQTTClient
	if *regToken != "" {
		// Registration token (new method - API key style - Story #198)
		tokenPrefix := *regToken
		if len(*regToken) > 15 {
			tokenPrefix = (*regToken)[:15] + "..."
		}
		logger.Info("Using registration token for auto-registration (MQTT+QUIC mode)",
			"operation", "registration_init",
			"token_prefix", tokenPrefix)

		// Use new MQTT+QUIC registration flow
		// Pass main application context for long-lived MQTT operations
		mqttCl, err := registerAndConnectMQTT(ctx, *regToken, logger)
		if err != nil {
			logger.Fatal("Failed to register with MQTT",
				"operation", "registration_mqtt",
				"error", err.Error())
		}

		mqttClient = mqttCl

		logger.Info("Steward registered and connected successfully via MQTT",
			"operation", "registration_complete",
			"steward_id", mqttClient.GetStewardID(),
			"tenant_id", mqttClient.GetTenantID())

		// Continue running with MQTT+QUIC mode (controller-connected steward)
		// The steward will maintain connection, receive commands, and send heartbeats

	} else if *regCode != "" {
		// Registration code support removed in Story #198
		// Use --regtoken for MQTT+QUIC registration
		logger.Fatal("Registration codes (--regcode) are no longer supported",
			"operation", "registration_error",
			"solution", "Use --regtoken with MQTT+QUIC registration tokens")
	}

	// If using MQTT+QUIC mode with registration token, run in controller-connected mode
	if mqttClient != nil {
		logger.Info("Running in MQTT+QUIC controller-connected mode",
			"operation", "steward_mode",
			"mode", "mqtt_quic")

		// The MQTT client is already connected and will:
		// - Send automatic heartbeats every 30 seconds
		// - Listen for commands from controller
		// - Handle DNA sync requests
		// - Handle config sync requests (via QUIC)

		logger.Info("Steward running and connected to controller",
			"operation", "steward_running",
			"steward_id", mqttClient.GetStewardID())

		// Wait for termination signal
		sig := <-sigChan
		logger.Info("Received signal, shutting down...",
			"operation", "steward_shutdown",
			"signal", sig.String())

		// Disconnect MQTT client
		if err := mqttClient.Disconnect(ctx); err != nil {
			logger.Error("Error during MQTT disconnect",
				"operation", "mqtt_disconnect",
				"error", err.Error())
		}

		logger.Info("Steward shutdown completed",
			"operation", "steward_shutdown",
			"status", "completed")
		return
	}

	// Determine operation mode (standalone vs legacy controller)
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

// registerAndConnectMQTT registers the steward using HTTP REST API
// and then establishes MQTT+QUIC connections for ongoing communication.
func registerAndConnectMQTT(ctx context.Context, token string, logger logging.Logger) (*client.MQTTClient, error) {
	logger.Info("Registering steward via HTTP API")

	// Get controller URL from environment (for Docker test mode)
	controllerURL := os.Getenv("CFGMS_CONTROLLER_URL")
	if controllerURL == "" {
		controllerURL = "http://controller-standalone:9080"
	}

	// Check if we should skip TLS verification (test mode only)
	insecureSkipVerify := false
	if skipVerify := os.Getenv("CFGMS_HTTP_INSECURE_SKIP_VERIFY"); skipVerify == "true" {
		insecureSkipVerify = true
		logger.Warn("HTTP TLS verification disabled (test mode only)")
	}

	// Create HTTP registration client
	httpClient, err := registration.NewHTTPClient(&registration.HTTPConfig{
		ControllerURL:      controllerURL,
		Timeout:            30 * time.Second,
		InsecureSkipVerify: insecureSkipVerify,
		Logger:             logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP registration client: %w", err)
	}

	// Register via HTTP with timeout (prevent hanging indefinitely)
	// Use child context for HTTP call, but keep parent ctx for MQTT operations
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

	// Now create MQTT+QUIC client with credentials from registration
	mqttBroker := regResp.MQTTBroker
	quicAddress := regResp.QUICAddress

	mqttClient, err := client.NewMQTTClient(&client.MQTTConfig{
		ControllerURL:     mqttBroker,
		QUICAddress:       quicAddress,
		RegistrationToken: token,
		CACertPEM:         regResp.CACert,
		ClientCertPEM:     regResp.ClientCert,
		ClientKeyPEM:      regResp.ClientKey,
		Logger:            logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MQTT client: %w", err)
	}

	// Set steward ID and tenant ID from registration response
	mqttClient.SetStewardID(regResp.StewardID)
	mqttClient.SetTenantID(regResp.TenantID)

	// Connect to MQTT
	if err := mqttClient.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to MQTT: %w", err)
	}

	logger.Info("Connected to controller via MQTT+QUIC",
		"mqtt_broker", mqttBroker,
		"quic_address", quicAddress)

	// Send initial heartbeat
	if err := mqttClient.SendHeartbeat(ctx, "healthy", nil); err != nil {
		logger.Warn("Failed to send initial heartbeat", "error", err)
	}

	// Return connected client (do NOT disconnect - maintain connection)
	return mqttClient, nil
}
