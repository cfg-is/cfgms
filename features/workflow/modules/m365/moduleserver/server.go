// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package moduleserver is the shared bootstrap for the out-of-process M365
// workflow module binaries (cmd/main.go of conditional_access, entra_admin_unit,
// entra_application, entra_group, entra_user and intune_policy). It is a helper
// for that module family, not a central provider.
//
// A module process never opens a secret store. The controller mints a
// short-lived Microsoft Graph access token for the execution tenant and delivers
// it, with the tenant, in the module handshake (WorkflowHandshakeRequest
// tenant_id / auth_token); the module's auth.Provider is built from that token
// alone and the session is bound to that tenant.
package moduleserver

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/adapter"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/modules/contract"
	"google.golang.org/grpc"
)

// NewModule is a module constructor, e.g. entrauser.New.
type NewModule func(auth.Provider, graph.Client) modules.Module

// Run serves the module on the socket named by CFGMS_MODULE_SOCKET until it
// receives SIGTERM/SIGINT or a Shutdown RPC, and exits the process on a fatal
// error. It is the whole body of each module's main.
func Run(moduleName string, newModule NewModule) {
	socketPath := os.Getenv("CFGMS_MODULE_SOCKET")
	if socketPath == "" {
		log.Fatalf("cfgms-module-%s: CFGMS_MODULE_SOCKET environment variable is required", moduleName)
	}

	lis, err := contract.Listen(socketPath)
	if err != nil {
		log.Fatalf("cfgms-module-%s: failed to listen on %s: %v", moduleName, socketPath, err) // #nosec G706 - socketPath is system-set (CFGMS_MODULE_SOCKET), not user input
	}

	if err := Serve(lis, moduleName, newModule, newGraphClient(), true); err != nil {
		log.Fatalf("cfgms-module-%s: gRPC server exited with error: %v", moduleName, err)
	}
}

// newGraphClient builds the Graph client for a module process: rate limited
// and retrying, including honouring Retry-After on throttled responses.
// Options exist so tests can point the client at a local server.
func newGraphClient(options ...graph.ClientOption) *graph.HTTPClient {
	return graph.NewRateLimitedHTTPClient(options...)
}

// Serve registers the module on lis and serves until the server stops. The
// module's auth.Provider is an auth.HandshakeTokenProvider bound by the
// handshake. When handleSignals is true, SIGTERM/SIGINT trigger a graceful stop.
func Serve(lis net.Listener, moduleName string, newModule NewModule, graphClient graph.Client, handleSignals bool) error {
	provider := auth.NewHandshakeTokenProvider()
	mod := newModule(provider, graphClient)

	srv := grpc.NewServer()
	proto.RegisterWorkflowModuleServiceServer(srv, adapter.NewWorkflow(mod, moduleName, srv,
		adapter.WithHandshakeHandler(func(tenantID, authToken string) error {
			if err := provider.Bind(tenantID, authToken); err != nil {
				return fmt.Errorf("module %s: %w", moduleName, err)
			}
			return nil
		})))

	if handleSignals {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			<-sigCh
			srv.GracefulStop()
		}()
	}

	return srv.Serve(lis)
}
