// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// cfgms-module-m365-entra-user is the out-of-process gRPC binary for the
// workflow-kind (controller-executed) Entra ID user module. It reads
// CFGMS_MODULE_SOCKET from the environment, registers the ModuleService
// gRPC server, and handles SIGTERM for graceful shutdown — the same
// out-of-process module pattern as the stdlib modules (see
// features/modules/stdlib/hostname/cmd/main.go), adapted for a workflow-kind
// module that needs a Microsoft Graph auth provider and API client rather
// than local-host access.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/modules/adapter"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	entrauser "github.com/cfgis/cfgms/features/workflow/modules/m365/entra_user"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/contract"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"

	// Blank-imported for their init() registration side effects with the
	// global secrets provider registry (pkg/secrets/interfaces). The provider
	// actually used is selected at runtime by CFGMS_M365_SECRETS_PROVIDER.
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/steward"

	"google.golang.org/grpc"
)

const moduleName = "m365-entra-user"

func main() {
	socketPath := os.Getenv("CFGMS_MODULE_SOCKET")
	if socketPath == "" {
		log.Fatalf("cfgms-module-%s: CFGMS_MODULE_SOCKET environment variable is required", moduleName)
	}

	authProvider, err := buildAuthProvider()
	if err != nil {
		log.Fatalf("cfgms-module-%s: failed to build auth provider: %v", moduleName, err)
	}
	graphClient := graph.NewHTTPClient()

	mod := entrauser.New(authProvider, graphClient)

	lis, err := contract.Listen(socketPath)
	if err != nil {
		log.Fatalf("cfgms-module-%s: failed to listen on %s: %v", moduleName, socketPath, err) // #nosec G706 - socketPath is system-set (CFGMS_MODULE_SOCKET), not user input
	}

	srv := grpc.NewServer()
	proto.RegisterWorkflowModuleServiceServer(srv, adapter.NewWorkflow(mod, moduleName, srv))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("cfgms-module-%s: gRPC server exited with error: %v", moduleName, err)
	}
}

// buildAuthProvider constructs the module's Microsoft Graph auth provider
// from the process environment.
//
// CFGMS_M365_SECRETS_PROVIDER selects the pkg/secrets provider backing
// credential storage (defaults to "steward"); provider-specific configuration
// is read from its own env vars. No default OAuth2Config is supplied: a CFGMS
// tenant with no OAuth2Config on file (via CredentialStore.StoreConfig, keyed
// by the authenticated CFGMS tenant — an admin-facing flow outside this
// story's scope) fails closed with "no OAuth2 configuration found for
// tenant", rather than silently falling back to one shared, env-supplied M365
// app registration across every CFGMS tenant this binary might ever serve.
func buildAuthProvider() (auth.Provider, error) {
	providerName := os.Getenv("CFGMS_M365_SECRETS_PROVIDER")
	if providerName == "" {
		providerName = "steward"
	}

	config := map[string]interface{}{}
	switch providerName {
	case "steward":
		secretsDir := os.Getenv("CFGMS_M365_SECRETS_DIR")
		if secretsDir == "" {
			return nil, fmt.Errorf("CFGMS_M365_SECRETS_DIR environment variable is required")
		}
		config["secrets_dir"] = secretsDir
	case "sops":
		keyFile := os.Getenv("CFGMS_M365_SECRETS_KEY_FILE")
		if keyFile == "" {
			return nil, fmt.Errorf("CFGMS_M365_SECRETS_KEY_FILE environment variable is required")
		}
		config["key_file"] = keyFile
		config["storage_provider"] = "flatfile"
		config["storage_config"] = map[string]interface{}{
			"path": os.Getenv("CFGMS_M365_SECRETS_DIR"),
		}
	}

	secretStore, err := secretsif.CreateSecretStoreFromConfig(providerName, config)
	if err != nil {
		return nil, err
	}

	credStore := auth.NewSecretStoreCredentialStore(secretStore)
	return auth.NewOAuth2Provider(credStore, nil, logging.NewNoopLogger()), nil
}
