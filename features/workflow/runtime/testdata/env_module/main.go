// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// env_module is a minimal out-of-process workflow module binary used exclusively
// by runtime tests. It implements the WorkflowModuleService gRPC contract:
//
//   - Handshake: acknowledges the session with an "env" capability.
//   - Get: reports its own environment (see Get).
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
	"sort"
	"strings"
	"sync"
	"syscall"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/pkg/modules/contract"
	"google.golang.org/grpc"
)

type envServer struct {
	proto.UnimplementedWorkflowModuleServiceServer
	srv *grpc.Server

	mu        sync.Mutex
	tenantID  string
	authToken string
}

func (s *envServer) Handshake(_ context.Context, req *proto.WorkflowHandshakeRequest) (*proto.WorkflowHandshakeResponse, error) {
	s.mu.Lock()
	s.tenantID = req.GetTenantId()
	s.authToken = req.GetAuthToken()
	s.mu.Unlock()
	return &proto.WorkflowHandshakeResponse{Capabilities: []string{"env"}}, nil
}

// Get reports the module's own environment: ResourceId "env:<NAME>" returns
// "set:<value>" or "unset"; "names" returns the sorted variable names, one per line.
func (s *envServer) Get(_ context.Context, req *proto.GetRequest) (*proto.GetResponse, error) {
	if name, ok := strings.CutPrefix(req.ResourceId, "env:"); ok {
		if v, found := os.LookupEnv(name); found {
			return &proto.GetResponse{ConfigData: "set:" + v}, nil
		}
		return &proto.GetResponse{ConfigData: "unset"}, nil
	}
	if req.ResourceId == "names" {
		var names []string
		for _, e := range os.Environ() {
			if i := strings.IndexByte(e, '='); i > 0 {
				names = append(names, e[:i])
			}
		}
		sort.Strings(names)
		return &proto.GetResponse{ConfigData: strings.Join(names, "\n")}, nil
	}
	return &proto.GetResponse{ConfigData: "unknown:" + req.ResourceId}, nil
}

func (s *envServer) Set(_ context.Context, _ *proto.SetRequest) (*proto.SetResponse, error) {
	return &proto.SetResponse{Applied: true}, nil
}

func (s *envServer) Test(_ context.Context, _ *proto.TestRequest) (*proto.TestResponse, error) {
	return &proto.TestResponse{InCompliance: true}, nil
}

func (s *envServer) Shutdown(_ context.Context, _ *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	go s.srv.GracefulStop()
	return &proto.ShutdownResponse{}, nil
}

func main() {
	socketPath := os.Getenv("CFGMS_MODULE_SOCKET")
	if socketPath == "" {
		log.Fatal("env_module: CFGMS_MODULE_SOCKET environment variable is required")
	}

	lis, err := contract.Listen(socketPath)
	if err != nil {
		log.Fatalf("env_module: failed to listen on %s: %v", socketPath, err)
	}

	srv := grpc.NewServer()
	es := &envServer{srv: srv}
	proto.RegisterWorkflowModuleServiceServer(srv, es)

	// Handle SIGTERM/SIGINT for graceful shutdown when killed by the runtime.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("env_module: gRPC server exited with error: %v", err)
	}
}
