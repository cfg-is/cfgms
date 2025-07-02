package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	
	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/pkg/logging"
)

func main() {
	// Parse command line arguments
	var (
		configPath = flag.String("config", "", "Path to configuration file (enables standalone mode)")
		mode       = flag.String("mode", "", "Operation mode: 'standalone' or 'controller' (optional if config provided)")
		logLevel   = flag.String("log-level", "info", "Log level: debug, info, warn, error")
	)
	flag.Parse()

	// Determine operation mode
	useStandalone := *configPath != "" || *mode == "standalone"
	
	// Set up logging
	logger := logging.NewLogger(*logLevel)
	
	var s *steward.Steward
	var err error
	
	if useStandalone {
		// Standalone mode - use hostname.cfg or provided config path
		configFile := *configPath
		if configFile == "" {
			// No config path provided, try to find hostname.cfg
			// This will be handled by the config loader's search logic
		}
		
		s, err = steward.NewStandalone(configFile, logger)
		if err != nil {
			log.Fatalf("Failed to create standalone steward: %v", err)
		}
		
		logger.Info("Starting steward in standalone mode")
	} else {
		// Controller mode (legacy)
		cfg := steward.DefaultConfig()
		cfg.LogLevel = *logLevel
		
		// TODO: Load additional configuration from file and environment
		
		s, err = steward.New(cfg, logger)
		if err != nil {
			log.Fatalf("Failed to create steward: %v", err)
		}
		
		logger.Info("Starting steward in controller mode")
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
			logger.Fatal("Steward failed", "error", err)
		}
	}()

	// Wait for termination signal
	sig := <-sigChan
	logger.Info("Received signal, shutting down...", "signal", sig)
	
	// Initiate graceful shutdown
	if err := s.Stop(ctx); err != nil {
		logger.Error("Error during shutdown", "error", err)
	}
}
