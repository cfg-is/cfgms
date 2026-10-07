// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// cfgms-module-m365-conditional-access is the out-of-process gRPC binary for the
// workflow-kind (controller-executed) m365-conditional-access module. It reads
// CFGMS_MODULE_SOCKET from the environment, registers the ModuleService
// gRPC server, and handles SIGTERM for graceful shutdown — the same
// out-of-process module pattern as the stdlib modules (see
// features/modules/stdlib/hostname/cmd/main.go) and the entra_user workflow
// module (features/workflow/modules/m365/entra_user/cmd/main.go), adapted
// for a workflow-kind module that needs a Microsoft Graph auth provider and
// API client rather than local-host access.
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
	conditionalaccess "github.com/cfgis/cfgms/features/workflow/modules/m365/conditional_access"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/contract"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"

	// Blank-imported for their init() registration side effects with the
	// global secrets provider registry (pkg/secrets/interfaces). The provider
	// actually used is selected at runtime by CFGMS_M365_SECRETS_PROVIDER.
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/steward"

	// Registers the flatfile storage provider the sops secrets provider layers
	// its encrypted secret data on; without it the sops branch below fails at
	// startup with "storage provider 'flatfile' not found".
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"

	"google.golang.org/grpc"
)

const moduleName = "m365-conditional-access"

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

	mod := conditionalaccess.New(authProvider, graphClient)

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
	providerName, config, err := secretStoreConfigFromEnv()
	if err != nil {
		return nil, err
	}

	secretStore, err := secretsif.CreateSecretStoreFromConfig(providerName, config)
	if err != nil {
		return nil, err
	}

	credStore := auth.NewSecretStoreCredentialStore(secretStore)
	return auth.NewOAuth2Provider(credStore, nil, logging.NewNoopLogger()), nil
}

// secretStoreConfigFromEnv resolves the pkg/secrets provider name and its
// provider-specific configuration from the process environment. It is split out
// of buildAuthProvider so the selection rules — default provider, the required
// env vars per provider, and the shape of the config map each provider is
// handed — are asserted directly rather than only through a constructed store.
//
// CFGMS_M365_SECRETS_DIR is required for every supported provider: it is the
// steward provider's secrets directory and the SOPS provider's flatfile storage
// root, and neither has a safe implicit value for a controller-executed module
// (the package defaults point at the host-wide /var/lib/cfgms/secrets tree).
// An unrecognised provider name is rejected rather than passed through with an
// empty config, which would silently land on those same host-wide defaults.
func secretStoreConfigFromEnv() (string, map[string]interface{}, error) {
	providerName := os.Getenv("CFGMS_M365_SECRETS_PROVIDER")
	if providerName == "" {
		providerName = "steward"
	}

	secretsDir := os.Getenv("CFGMS_M365_SECRETS_DIR")
	if secretsDir == "" {
		return "", nil, fmt.Errorf("CFGMS_M365_SECRETS_DIR environment variable is required")
	}

	config := map[string]interface{}{}
	switch providerName {
	case "steward":
		config["secrets_dir"] = secretsDir
	case "sops":
		keyFile := os.Getenv("CFGMS_M365_SECRETS_KEY_FILE")
		if keyFile == "" {
			return "", nil, fmt.Errorf("CFGMS_M365_SECRETS_KEY_FILE environment variable is required")
		}
		config["key_file"] = keyFile
		config["storage_provider"] = "flatfile"
		// "root" is the key the flatfile storage provider reads
		// (pkg/storage/providers/flatfile.getRootFromConfig); any other key
		// leaves the root empty and fails store construction.
		config["storage_config"] = map[string]interface{}{
			"root": secretsDir,
		}
	default:
		return "", nil, fmt.Errorf("unsupported CFGMS_M365_SECRETS_PROVIDER %q: supported providers are \"steward\" and \"sops\"", providerName)
	}

	return providerName, config, nil
}
