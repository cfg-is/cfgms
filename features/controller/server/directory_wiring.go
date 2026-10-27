// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"fmt"

	"github.com/cfgis/cfgms/features/workflow/modules/m365"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// registerDirectoryProviders builds the controller's DirectoryProviderManager
// and registers the Entra ID provider on it without connecting or health
// checking it (Issue #5431). The manager connects it lazily on first use.
//
// The Entra provider holds no tenant: its OAuth2 provider reads each CFGMS
// tenant's connection from store on every call and has a nil default config, so
// a tenant with no connection on file fails rather than borrowing another
// tenant's app registration. graphOpts configure the Graph HTTP client (tests
// point graph.WithBaseURL at an httptest server).
//
// A nil store skips the Entra registration and logs why; the returned manager is
// still valid (empty) so startup does not fail.
func registerDirectoryProviders(store secretsif.SecretStore, logger logging.Logger, graphOpts ...graph.ClientOption) (*interfaces.DirectoryProviderManager, error) {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	manager := interfaces.NewDirectoryProviderManager(nil)

	if store == nil {
		logger.Warn("Entra ID directory provider not registered: no secret store available")
		return manager, nil
	}

	authProvider := auth.NewOAuth2Provider(auth.NewSecretStoreCredentialStore(store), nil, logger)
	graphClient := graph.NewRateLimitedHTTPClient(graphOpts...)
	entra := m365.NewEntraIDDirectoryProvider(logger, authProvider, graphClient)

	name := entra.GetProviderInfo().Name
	if err := manager.RegisterProvider(name, entra, nil); err != nil {
		return nil, fmt.Errorf("failed to register Entra ID directory provider: %w", err)
	}
	return manager, nil
}
