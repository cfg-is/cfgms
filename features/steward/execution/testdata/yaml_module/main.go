// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// yaml_module is a minimal out-of-process module binary used by the executor's
// required-module tests. Unlike the runtime package's echo_module, Get returns a
// YAML mapping equal to the desired state, so a resource converges as compliant:
//
//   - Handshake: acknowledges the session.
//   - Get: returns "key: value".
//   - Set: acknowledges with Applied = true.
//   - Test: returns InCompliance = true.
//   - Shutdown: stops the gRPC server.
//
// The socket path is supplied via the CFGMS_MODULE_SOCKET environment variable.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/pkg/modules/contract"
	"google.golang.org/grpc"
)

type server struct {
	proto.UnimplementedModuleServiceServer
	srv *grpc.Server
}

func (s *server) Handshake(_ context.Context, _ *proto.HandshakeRequest) (*proto.HandshakeResponse, error) {
	return &proto.HandshakeResponse{Capabilities: []string{"yaml"}}, nil
}

func (s *server) Get(_ context.Context, _ *proto.GetRequest) (*proto.GetResponse, error) {
	return &proto.GetResponse{ConfigData: "key: value\n"}, nil
}

func (s *server) Set(_ context.Context, _ *proto.SetRequest) (*proto.SetResponse, error) {
	return &proto.SetResponse{Applied: true}, nil
}

func (s *server) Test(_ context.Context, _ *proto.TestRequest) (*proto.TestResponse, error) {
	return &proto.TestResponse{InCompliance: true}, nil
}

func (s *server) Shutdown(_ context.Context, _ *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	go s.srv.GracefulStop()
	return &proto.ShutdownResponse{}, nil
}

func main() {
	socketPath := os.Getenv("CFGMS_MODULE_SOCKET")
	if socketPath == "" {
		log.Fatal("yaml_module: CFGMS_MODULE_SOCKET environment variable is required")
	}
	lis, err := contract.Listen(socketPath)
	if err != nil {
		log.Fatalf("yaml_module: failed to listen: %v", err)
	}
	srv := grpc.NewServer()
	proto.RegisterModuleServiceServer(srv, &server{srv: srv})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("yaml_module: gRPC server exited with error: %v", err)
	}
}
