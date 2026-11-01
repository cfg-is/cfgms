// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// echo_module is a minimal out-of-process workflow module binary used exclusively
// by runtime tests. It implements the WorkflowModuleService gRPC contract:
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
	"os"
	"os/signal"
	"sync"
	"syscall"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/pkg/modules/contract"
	"google.golang.org/grpc"
)

type echoServer struct {
	proto.UnimplementedWorkflowModuleServiceServer
	srv *grpc.Server

	mu        sync.Mutex
	tenantID  string
	authToken string
}

func (s *echoServer) Handshake(_ context.Context, req *proto.WorkflowHandshakeRequest) (*proto.WorkflowHandshakeResponse, error) {
	s.mu.Lock()
	s.tenantID = req.GetTenantId()
	s.authToken = req.GetAuthToken()
	s.mu.Unlock()
	return &proto.WorkflowHandshakeResponse{Capabilities: []string{"echo"}}, nil
}

// Get returns "echo:<resource_id>"; a resource_id of "handshake" returns
// "tenant=<tenant_id>;token=<auth_token>" as recorded by Handshake.
func (s *echoServer) Get(_ context.Context, req *proto.GetRequest) (*proto.GetResponse, error) {
	if req.ResourceId == "handshake" {
		s.mu.Lock()
		defer s.mu.Unlock()
		return &proto.GetResponse{ConfigData: "tenant=" + s.tenantID + ";token=" + s.authToken}, nil
	}
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

	lis, err := contract.Listen(socketPath)
	if err != nil {
		log.Fatalf("echo_module: failed to listen on %s: %v", socketPath, err)
	}

	srv := grpc.NewServer()
	es := &echoServer{srv: srv}
	proto.RegisterWorkflowModuleServiceServer(srv, es)

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
