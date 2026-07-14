// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// cfgms-module-cert_trust is the out-of-process gRPC binary for the cert_trust
// stdlib module. It reads CFGMS_MODULE_SOCKET from the environment, registers
// the ModuleService gRPC server, and handles SIGTERM for graceful shutdown.
package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/modules/adapter"
	cert_trust "github.com/cfgis/cfgms/features/modules/stdlib/cert_trust"
	"google.golang.org/grpc"
)

func main() {
	socketPath := os.Getenv("CFGMS_MODULE_SOCKET")
	if socketPath == "" {
		log.Fatal("cfgms-module-cert_trust: CFGMS_MODULE_SOCKET environment variable is required")
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("cfgms-module-cert_trust: failed to listen on %s: %v", socketPath, err)
	}

	srv := grpc.NewServer()
	proto.RegisterModuleServiceServer(srv, adapter.New(cert_trust.New(), "cert_trust", srv))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("cfgms-module-cert_trust: gRPC server exited with error: %v", err)
	}
}
