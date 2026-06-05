// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// echo_module is a minimal out-of-process module binary used exclusively by
// runtime tests. It implements the ModuleService gRPC contract:
//
//   - Handshake: acknowledges the session with an "echo" capability.
//   - Get: returns ConfigData = "echo:" + req.ResourceId.
//   - Set: acknowledges with Applied = true.
//   - Test: returns InCompliance = true.
//   - Shutdown: stops the gRPC server and exits cleanly.
//
// The socket path is supplied via the CFGMS_MODULE_SOCKET environment variable.
package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"google.golang.org/grpc"
)

type echoServer struct {
	proto.UnimplementedModuleServiceServer
	srv *grpc.Server
}

func (s *echoServer) Handshake(_ context.Context, _ *proto.HandshakeRequest) (*proto.HandshakeResponse, error) {
	return &proto.HandshakeResponse{Capabilities: []string{"echo"}}, nil
}

func (s *echoServer) Get(_ context.Context, req *proto.GetRequest) (*proto.GetResponse, error) {
	return &proto.GetResponse{ConfigData: "echo:" + req.ResourceId}, nil
}

func (s *echoServer) Set(_ context.Context, _ *proto.SetRequest) (*proto.SetResponse, error) {
	return &proto.SetResponse{Applied: true}, nil
}

func (s *echoServer) Test(_ context.Context, _ *proto.TestRequest) (*proto.TestResponse, error) {
	return &proto.TestResponse{InCompliance: true}, nil
}

func (s *echoServer) Shutdown(_ context.Context, _ *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	go s.srv.GracefulStop()
	return &proto.ShutdownResponse{}, nil
}

func main() {
	socketPath := os.Getenv("CFGMS_MODULE_SOCKET")
	if socketPath == "" {
		log.Fatal("echo_module: CFGMS_MODULE_SOCKET environment variable is required")
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("echo_module: failed to listen on %s: %v", socketPath, err)
	}

	srv := grpc.NewServer()
	es := &echoServer{srv: srv}
	proto.RegisterModuleServiceServer(srv, es)

	// Handle SIGTERM/SIGINT for graceful shutdown when killed by the runtime.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("echo_module: gRPC server exited with error: %v", err)
	}
}
