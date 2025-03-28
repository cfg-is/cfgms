package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"cfgms/features/controller/config"
	"cfgms/features/controller/server"
	"cfgms/pkg/logging"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	logger := logging.NewLogger(cfg.LogLevel)

	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to create server", "error", err)
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		if err := srv.Start(); err != nil {
			logger.Fatal("Server failed", "error", err)
		}
	}()

	// Wait for termination signal
	sig := <-sigChan
	logger.Info("Received signal, shutting down...", "signal", sig)

	// Graceful shutdown
	if err := srv.Stop(); err != nil {
		logger.Error("Error during shutdown", "error", err)
	}
}
