// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"errors"
	"fmt"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/config"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// DirectoryDomainReleaseHandler retracts tenantID's directory:<domain>/... entities
// after the tenant's last declaration of domain is removed. It must be idempotent:
// it also runs before a new tenant claims a domain whose previous release did not
// finish.
type DirectoryDomainReleaseHandler func(ctx context.Context, tenantID, domain string) error

// SetDirectoryDomainReleaseHandler wires the entity retraction run on domain release.
func (s *ConfigurationServiceV2) SetDirectoryDomainReleaseHandler(h DirectoryDomainReleaseHandler) {
	s.releaseMu.Lock()
	s.releaseHandler = h
	s.releaseMu.Unlock()
}

// DirectoryDomains returns the registry the config save paths maintain, for the
// verifier that reads domain ownership.
func (s *ConfigurationServiceV2) DirectoryDomains() *DirectoryDomainRegistry {
	return s.domainRegistry
}

// validateConfiguration is the one validation every config save path runs:
// SetConfiguration (which the config push handler calls), BatchSetConfigurations and
// ValidateConfig. It adds the directory-declaration rules (non-device level,
// credential fields, reserved names, domain shape, domain ownership) to the generic
// config validation. It only reads the domain registry; claiming happens after
// validation, in claimDirectoryDomains.
//
// Every config reaching these paths is a steward's own device-level document, so the
// level passed is config.LevelDevice; a writer of tenant-level, cluster or role
// documents must call CheckDirectoryDeclarations with that document's level.
func (s *ConfigurationServiceV2) validateConfiguration(ctx context.Context, tenantID, stewardID string, cfg *stewardtypes.StewardConfig) *config.ValidationResult {
	result := s.validationManager.ValidateConfiguration(ctx, tenantID, stewardID, cfg)

	errs := CheckDirectoryDeclarations(config.LevelDevice, cfg)
	for i, r := range cfg.Resources {
		if r.Module != DirectoryDomainModule {
			continue
		}
		raw, _ := r.Config["domain"].(string)
		domain, ok := egtypes.NormalizeDirectoryDomain(raw)
		if !ok {
			continue // already reported by CheckDirectoryDeclarations
		}
		if err := s.domainRegistry.Check(ctx, domain, tenantID); err != nil {
			errs = append(errs, s.domainErrorFor(i, err, tenantID, stewardID))
		}
	}
	if len(errs) > 0 {
		result.Valid = false
		result.Errors = append(result.Errors, errs...)
	}
	return result
}

// domainErrorFor converts a registry error into a field-named validation error. A
// conflict never names the other tenant; an infrastructure fault is logged and
// reported generically.
func (s *ConfigurationServiceV2) domainErrorFor(resourceIdx int, err error, tenantID, stewardID string) config.ValidationError {
	field := fmt.Sprintf("resources[%d].config.domain", resourceIdx)
	if errors.Is(err, ErrDomainOwnedByOtherTenant) {
		return config.ValidationError{
			Field: field, Code: CodeDirectoryDomainConflict, Level: "error",
			Message:    "directory domain is already claimed by another tenant",
			Suggestion: "contact the domain's owner or support to release it",
		}
	}
	s.logger.Error("Directory domain registry failure",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"steward_id", logging.SanitizeLogValue(stewardID),
		"error", directoryErrorKind(err))
	return config.ValidationError{
		Field: field, Code: CodeDirectoryRegistryFailure, Level: "error",
		Message: "directory domain registry is unavailable",
	}
}

// previousDeclaredDomains returns the domains stewardID's currently stored device
// cfg declares. An absent cfg declares none.
func (s *ConfigurationServiceV2) previousDeclaredDomains(ctx context.Context, tenantID, stewardID string) ([]string, error) {
	prev, err := s.configManager.GetConfiguration(ctx, tenantID, stewardID)
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("read stored configuration: %w", err)
	}
	return DeclaredDirectoryDomains(prev), nil
}

// domainClaim records what claimDirectoryDomains added, so a failed store can undo it.
type domainClaim struct {
	tenantID, stewardID string
	added               []string
}

// claimDirectoryDomains registers cfg's declared domains for tenantID/stewardID.
// A conflict that appeared after validation (a concurrent save by another tenant)
// is returned as a ValidationFailedError. On any error nothing this call added
// remains registered.
func (s *ConfigurationServiceV2) claimDirectoryDomains(ctx context.Context, tenantID, stewardID string, cfg *stewardtypes.StewardConfig) (*domainClaim, error) {
	claim := &domainClaim{tenantID: tenantID, stewardID: stewardID}
	for i, r := range cfg.Resources {
		if r.Module != DirectoryDomainModule {
			continue
		}
		raw, _ := r.Config["domain"].(string)
		domain, ok := egtypes.NormalizeDirectoryDomain(raw)
		if !ok {
			continue
		}
		// A previous owner whose release did not finish keeps its entities until
		// they are retracted; finish that before a new owner starts writing.
		if err := s.finishStaleRelease(ctx, domain); err != nil {
			s.undoClaim(ctx, claim)
			return nil, s.claimFailure(i, err, tenantID, stewardID)
		}
		added, err := s.domainRegistry.Claim(ctx, domain, tenantID, stewardID)
		if err != nil {
			s.undoClaim(ctx, claim)
			return nil, s.claimFailure(i, err, tenantID, stewardID)
		}
		if added {
			claim.added = append(claim.added, domain)
		}
	}
	return claim, nil
}

func (s *ConfigurationServiceV2) claimFailure(idx int, err error, tenantID, stewardID string) error {
	return &ValidationFailedError{Errors: []config.ValidationError{s.domainErrorFor(idx, err, tenantID, stewardID)}}
}

// undoClaim releases what claim added. Best effort: a failure here is logged, and
// leaves an entry that reads as owned by tenantID until its next save.
func (s *ConfigurationServiceV2) undoClaim(ctx context.Context, claim *domainClaim) {
	for _, d := range claim.added {
		if _, err := s.domainRegistry.Release(ctx, d, claim.tenantID, claim.stewardID); err != nil {
			s.logger.Warn("Failed to undo directory domain claim",
				"tenant_id", logging.SanitizeLogValue(claim.tenantID),
				"error", directoryErrorKind(err))
		}
	}
}

// finishStaleRelease completes the cleanup of a domain whose last declarer was
// removed: retract the previous owner's entities, then drop the registry entry.
func (s *ConfigurationServiceV2) finishStaleRelease(ctx context.Context, domain string) error {
	prevTenant, stale, err := s.domainRegistry.StaleOwner(ctx, domain)
	if err != nil || !stale {
		return err
	}
	if err := s.retractDomain(ctx, prevTenant, domain); err != nil {
		return err
	}
	return s.domainRegistry.Remove(ctx, domain)
}

func (s *ConfigurationServiceV2) retractDomain(ctx context.Context, tenantID, domain string) error {
	s.releaseMu.RLock()
	h := s.releaseHandler
	s.releaseMu.RUnlock()
	if h == nil {
		return nil
	}
	return h(ctx, tenantID, domain)
}

// releaseDirectoryDomains drops stewardID as a declarer of each domain. A domain left
// with no declarer has its entities retracted and its entry removed, freeing it for
// another tenant. A failure leaves the entry unowned-but-present; finishStaleRelease
// completes it before any later claim, so the error is logged rather than failing a
// save that has already been stored.
func (s *ConfigurationServiceV2) releaseDirectoryDomains(ctx context.Context, tenantID, stewardID string, domains []string) {
	for _, d := range domains {
		released, err := s.domainRegistry.Release(ctx, d, tenantID, stewardID)
		if err == nil && released {
			err = s.finishStaleRelease(ctx, d)
		}
		if err != nil {
			s.logger.Error("Failed to release directory domain",
				"tenant_id", logging.SanitizeLogValue(tenantID),
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", directoryErrorKind(err))
		}
	}
}

// domainsRemoved returns the domains in prev that cfg no longer declares.
func domainsRemoved(prev []string, cfg *stewardtypes.StewardConfig) []string {
	now := map[string]struct{}{}
	for _, d := range DeclaredDirectoryDomains(cfg) {
		now[d] = struct{}{}
	}
	var out []string
	for _, d := range prev {
		if _, ok := now[d]; !ok {
			out = append(out, d)
		}
	}
	return out
}

// directoryErrorKind describes err for a log line without ever formatting err's text.
// Errors from the config store, the decoder and the release handler can echo the
// directory config they were handling, and that config carries password fields, so
// the log gets a fixed label chosen by error identity, never err.Error().
func directoryErrorKind(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "context canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline exceeded"
	case errors.Is(err, cfgconfig.ErrConfigNotFound):
		return "registry entry not found"
	default:
		return "directory domain registry operation failed"
	}
}
