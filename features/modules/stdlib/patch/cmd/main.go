// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// cfgms-module-patch is the out-of-process gRPC binary for the patch stdlib module.
// The patch module has a real Windows Update implementation (windows_update.go) and
// a stub PatchManager for all other platforms. Both are retained.
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
	patchmodule "github.com/cfgis/cfgms/features/modules/stdlib/patch"
	"google.golang.org/grpc"
)

func main() {
	socketPath := os.Getenv("CFGMS_MODULE_SOCKET")
	if socketPath == "" {
		log.Fatal("cfgms-module-patch: CFGMS_MODULE_SOCKET environment variable is required")
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("cfgms-module-patch: failed to listen on %s: %v", socketPath, err)
	}

	srv := grpc.NewServer()
	proto.RegisterModuleServiceServer(srv, adapter.New(patchmodule.New(), "patch", srv))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("cfgms-module-patch: gRPC server exited with error: %v", err)
	}
}
