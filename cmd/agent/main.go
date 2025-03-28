package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	
	"cfgms/features/steward"
	"cfgms/pkg/logging"
)

func main() {
	// Create default configuration
	cfg := steward.DefaultConfig()
	
	// TODO: Load configuration from file and environment
	
	// Set up logging
	logger := logging.NewLogger(cfg.LogLevel)
	
	// Create and initialize the steward
	s, err := steward.New(cfg, logger)
	if err != nil {
		log.Fatalf("Failed to create steward: %v", err)
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
