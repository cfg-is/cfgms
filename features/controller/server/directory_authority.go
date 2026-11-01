// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// directoryAuthorityTimeout bounds one verifier decision (a registry read and an
// effective-config resolution). A decision that cannot finish is a denial.
const directoryAuthorityTimeout = 10 * time.Second

// domainOwnerLookup answers which tenant owns a directory domain in the domain
// registry. service.DirectoryDomainRegistry satisfies it.
type domainOwnerLookup interface {
	Owner(ctx context.Context, domain string) (tenantID string, found bool, err error)
}

// effectiveDomainSource lists the directory domains declared in the effective cfg
// delivered to one steward. service.ConfigurationServiceV2 satisfies it, resolving
// through the same effective-config function that serves the steward.
type effectiveDomainSource interface {
	StewardEffectiveDeclaredDomains(ctx context.Context, tenantID, stewardID string) ([]string, error)
}

// directoryAuthority is the controller-side dnasync.DirectoryAuthority. A peer is
// the authority for a domain only when BOTH hold:
//
//	(a) the domain registry's owner is the peer's registered tenant (the steward
//	    record's TenantID, resolved from the mTLS-verified peer identity, never from
//	    anything the steward sent), and
//	(b) an activedirectory.domain resource for that domain is in the PEER'S OWN
//	    effective configuration.
//
// (a) alone would let any steward in the owning tenant write the domain's
// entities; (b) alone would let any tenant that names a domain claim it. Either
// failing, or any lookup erroring, is a denial.
//
// The ad_pdc_emulator fact (#5545) is intentionally absent here: it only activates
// observation on a steward and is never an input to authorisation. The decision is
// answered from controller state alone.
//
// The dnasync writer memoizes answers per (peer, domain) for one delta batch, so
// this type does not cache.
type directoryAuthority struct {
	owners    domainOwnerLookup
	tenants   interfaces.TenantResolver
	effective effectiveDomainSource
	logger    logging.Logger
}

var _ dnasync.DirectoryAuthority = (*directoryAuthority)(nil)

func newDirectoryAuthority(owners domainOwnerLookup, tenants interfaces.TenantResolver, effective effectiveDomainSource, logger logging.Logger) *directoryAuthority {
	return &directoryAuthority{owners: owners, tenants: tenants, effective: effective, logger: logger}
}

// IsDirectoryAuthority implements dnasync.DirectoryAuthority.
func (a *directoryAuthority) IsDirectoryAuthority(peerHostAuthority, domain string) bool {
	if a == nil || a.owners == nil || a.tenants == nil || a.effective == nil || peerHostAuthority == "" || domain == "" {
		return false
	}
	peerTenant, known := a.tenants.TenantForDevice(peerHostAuthority)
	if !known || peerTenant == "" {
		return false
	}

	// A controller-internal read of the peer's own registry and configuration state;
	// there is no caller context to inherit (the writer interface carries none).
	ctx, cancel := context.WithTimeout(ctxkeys.WithSystem(context.Background()), directoryAuthorityTimeout)
	defer cancel()

	owner, found, err := a.owners.Owner(ctx, domain)
	if err != nil {
		a.warn("directory authority: domain registry read failed", peerHostAuthority, err)
		return false
	}
	if !found || owner != peerTenant {
		return false
	}

	declared, err := a.effective.StewardEffectiveDeclaredDomains(ctx, peerTenant, peerHostAuthority)
	if err != nil {
		a.warn("directory authority: effective configuration unavailable", peerHostAuthority, err)
		return false
	}
	for _, d := range declared {
		if d == domain {
			return true
		}
	}
	return false
}

func (a *directoryAuthority) warn(msg, peer string, err error) {
	if a.logger == nil {
		return
	}
	a.logger.Warn(msg,
		"peer", logging.SanitizeLogValue(peer),
		"error", logging.SanitizeLogValue(err.Error()))
}

// directoryAuthorityVerifier returns the verifier the DNA-sync writer consults, or
// nil when the controller lacks the state it decides from — which the writer treats
// as "deny every directory fragment".
func (s *Server) directoryAuthorityVerifier() dnasync.DirectoryAuthority {
	if s.configService == nil || s.controllerService == nil {
		return nil
	}
	return newDirectoryAuthority(s.configService.DirectoryDomains(), s.controllerService, s.configService, s.logger)
}

// wireDirectoryDomainEffects connects the two controller-side consequences of the
// domain registry to the entity graph:
//
//   - releasing a domain retracts the owning tenant's directory:<domain>/...
//     entities (dnasync.RetractDirectoryDomain), and
//   - a write rejected by owner immutability is recorded in the root admin audit
//     stream (the system tenant), never a tenant's own stream, because the event
//     names two tenants.
func (s *Server) wireDirectoryDomainEffects() {
	if s.egProvider == nil {
		return
	}
	if s.configService != nil {
		provider := s.egProvider
		s.configService.SetDirectoryDomainReleaseHandler(func(ctx context.Context, tenantID, domain string) error {
			_, err := dnasync.RetractDirectoryDomain(ctx, provider, tenantID, domain)
			return err
		})
	}
	if o, ok := s.egProvider.(interface {
		SetOwnerConflictObserver(interfaces.OwnerConflictObserver)
	}); ok {
		o.SetOwnerConflictObserver(func(ctx context.Context, c interfaces.OwnerConflict) {
			s.recordOwnerConflictAudit(ctx, c)
		})
	}
}

// auditActionEntityOwnerConflict is recorded when a write to a directory or m365
// entity is rejected because another tenant owns it.
const auditActionEntityOwnerConflict = "entity_owner_conflict_rejected"

func (s *Server) recordOwnerConflictAudit(ctx context.Context, c interfaces.OwnerConflict) {
	s.mu.RLock()
	am := s.auditManager
	s.mu.RUnlock()
	if am == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSecurityEvent).
		Action(auditActionEntityOwnerConflict).
		User(audit.SystemUserID, business.AuditUserTypeSystem).
		Resource("entity", logging.SanitizeLogValue(c.Subject), "").
		Result(business.AuditResultFailure).
		Severity(business.AuditSeverityHigh).
		Detail("existing_tenant", logging.SanitizeLogValue(c.ExistingTenant)).
		Detail("attempted_tenant", logging.SanitizeLogValue(c.AttemptedTenant)).
		Detail("source", logging.SanitizeLogValue(c.Source))
	if err := am.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to record entity owner conflict audit event",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
