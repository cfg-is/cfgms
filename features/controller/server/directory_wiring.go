// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"fmt"
	"time"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/directory"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"

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

// tenantLister lists the CFGMS tenants (tenant.Manager satisfies it).
type tenantLister interface {
	ListTenants(ctx context.Context, filter *business.TenantFilter) ([]*business.TenantData, error)
}

// m365ConnectionSource finds the active CFGMS tenants that hold an M365
// connection. A tenant with no connection on file is simply absent.
type m365ConnectionSource struct {
	tenants tenantLister
	creds   auth.CredentialStore
}

func (s m365ConnectionSource) M365Connections(ctx context.Context) ([]directory.M365Connection, error) {
	tenants, err := s.tenants.ListTenants(ctx, &business.TenantFilter{Status: business.TenantStatusActive})
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	var out []directory.M365Connection
	for _, t := range tenants {
		cfg, err := s.creds.GetConfig(t.ID)
		if err != nil || cfg == nil || cfg.TenantID == "" {
			continue
		}
		out = append(out, directory.M365Connection{Tenant: t.ID, EntraTenantID: cfg.TenantID})
	}
	return out, nil
}

// m365InventoryDeps are the controller services the inventory collector runs over.
type m365InventoryDeps struct {
	Providers   *interfaces.DirectoryProviderManager
	Store       secretsif.SecretStore
	Tenants     tenantLister
	Writer      directory.ObservationWriter
	ConfigStore cfgconfig.ConfigStore
	Job         lease.SingletonJob
	Interval    time.Duration
	Audit       *audit.Manager
	Logger      logging.Logger
}

// newM365Inventory builds the lease-gated M365 tenant inventory collector
// (Issue #5561). It returns nil, nil when a dependency it cannot run without is
// absent (no secret store, entity graph or config store).
func newM365Inventory(d m365InventoryDeps) (*directory.M365Inventory, error) {
	if d.Providers == nil || d.Store == nil || d.Tenants == nil || d.Writer == nil || d.ConfigStore == nil {
		return nil, nil
	}
	membership, err := directory.NewMembership(d.ConfigStore, nil, directory.WithLogger(d.Logger))
	if err != nil {
		return nil, fmt.Errorf("m365 inventory membership: %w", err)
	}
	return directory.NewM365Inventory(directory.M365InventoryConfig{
		Providers:    d.Providers,
		ProviderName: "entraid",
		Connections:  m365ConnectionSource{tenants: d.Tenants, creds: auth.NewSecretStoreCredentialStore(d.Store)},
		Writer:       d.Writer,
		Membership:   membership,
		Store:        d.ConfigStore,
		Job:          d.Job,
		Interval:     d.Interval,
		Logger:       d.Logger,
		OnSecurity: func(ctx context.Context, ev directory.SecurityEvent) {
			recordSharedEntraTenantAudit(ctx, d.Audit, d.Logger, ev)
		},
	})
}

// effectiveConfigSource reads a tenant's effective cfg through the controller's
// one effective-config function (ConfigurationServiceV2.GetEffectiveConfiguration,
// the tenant-only cascade).
type effectiveConfigSource struct {
	svc *service.ConfigurationServiceV2
}

func (s effectiveConfigSource) EffectiveConfig(ctx context.Context, tenantID string) (*stewardtypes.StewardConfig, error) {
	eff, err := s.svc.GetEffectiveConfiguration(ctx, tenantID, "")
	if err != nil || eff == nil {
		return nil, err
	}
	return eff.Config, nil
}

// m365ConvergeDeps are the controller services the declared-resource convergence
// loop runs over.
type m365ConvergeDeps struct {
	Inventory   *directory.M365Inventory
	Config      *service.ConfigurationServiceV2
	Modules     workflow.TenantModuleLoader
	Providers   *interfaces.DirectoryProviderManager
	Writer      directory.ObservationWriter
	ConfigStore cfgconfig.ConfigStore
	Audit       *audit.Manager
	Logger      logging.Logger
}

// attachM365Convergence builds the convergence loop (Issue #5562) and hooks it to
// the inventory collector, so it runs under the collector's lease after each
// tenant's inventory pass. It is a no-op when the collector or a dependency the
// loop cannot run without is absent.
func attachM365Convergence(d m365ConvergeDeps) error {
	if d.Inventory == nil || d.Config == nil || d.Modules == nil || d.Providers == nil ||
		d.Writer == nil || d.ConfigStore == nil {
		return nil
	}
	cfg := directory.M365ConvergeConfig{
		Config:       effectiveConfigSource{svc: d.Config},
		Modules:      d.Modules,
		Providers:    d.Providers,
		ProviderName: "entraid",
		Writer:       d.Writer,
		Store:        d.ConfigStore,
		Logger:       d.Logger,
	}
	if d.Audit != nil {
		cfg.Audit = d.Audit
	}
	conv, err := directory.NewM365Converge(cfg)
	if err != nil {
		return fmt.Errorf("m365 convergence: %w", err)
	}
	d.Inventory.AttachConvergence(conv)
	return nil
}

// recordSharedEntraTenantAudit puts the shared-Entra-tenant event on the root
// admin audit stream. It names every CFGMS tenant involved, so it is recorded
// under the system tenant only.
func recordSharedEntraTenantAudit(ctx context.Context, auditManager *audit.Manager, logger logging.Logger, ev directory.SecurityEvent) {
	if auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSecurityEvent).
		Action(ev.Kind).
		User(audit.SystemUserID, business.AuditUserTypeSystem).
		Resource("entra_tenant", logging.SanitizeLogValue(ev.EntraTenantID), "").
		Result(business.AuditResultFailure).
		Severity(business.AuditSeverityHigh).
		Details(map[string]interface{}{"cfgms_tenants": ev.Tenants})
	if err := auditManager.RecordEvent(ctx, b); err != nil {
		logger.Warn("Failed to record shared Entra tenant audit event", "error", logging.SanitizeLogValue(err.Error()))
	}
}
