// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// cfgms-module-hostname is the out-of-process gRPC binary for the hostname stdlib module.
// It reads CFGMS_MODULE_SOCKET from the environment, registers the ModuleService
// gRPC server, and handles SIGTERM for graceful shutdown.
package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/modules/adapter"
	hostname "github.com/cfgis/cfgms/features/modules/stdlib/hostname"
	"google.golang.org/grpc"
)

func main() {
	socketPath := os.Getenv("CFGMS_MODULE_SOCKET")
	if socketPath == "" {
		log.Fatal("cfgms-module-hostname: CFGMS_MODULE_SOCKET environment variable is required")
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("cfgms-module-hostname: failed to listen on %s: %v", socketPath, err) // #nosec G706 - socketPath is system-set (CFGMS_MODULE_SOCKET), not user input
	}

	srv := grpc.NewServer()
	proto.RegisterModuleServiceServer(srv, adapter.New(hostname.New(), "hostname", srv))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("cfgms-module-hostname: gRPC server exited with error: %v", err)
	}
}
