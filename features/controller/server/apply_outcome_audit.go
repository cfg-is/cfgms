// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	modulecache "github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// applyOutcomeAuditTimeout bounds one audit write so a slow audit store cannot
// stall event ingestion.
const applyOutcomeAuditTimeout = 5 * time.Second

// applyOutcomeAuditSources are the controller facts the apply-outcome audit
// checks a steward's report against (Issue #5564).
type applyOutcomeAuditSources interface {
	// DeclaredResources returns the steward's registered tenant and the resources
	// declared in that steward's OWN effective cfg at reportedVersion. It errors
	// when the steward is unknown or reportedVersion is not the version the
	// controller serves, so a report is never checked against a cfg the steward
	// was not running.
	DeclaredResources(ctx context.Context, stewardID, reportedVersion string) (tenantID string, resources []stewardtypes.ResourceConfig, err error)

	// AuditOperations returns the audit_operations the approved bundle manifest
	// of the module's bundle lists.
	AuditOperations(moduleName string) ([]string, error)
}

// productionApplyOutcomeSources reads the facts from the controller's steward
// registry, its one effective-config function and the approved module cache.
type productionApplyOutcomeSources struct {
	controller *service.ControllerService
	config     *service.ConfigurationServiceV2
	cache      *modulecache.ModuleCache
}

func (p productionApplyOutcomeSources) DeclaredResources(ctx context.Context, stewardID, reportedVersion string) (string, []stewardtypes.ResourceConfig, error) {
	info, ok := p.controller.GetStewardInfo(stewardID)
	if !ok || info.TenantID == "" {
		return "", nil, fmt.Errorf("steward is not registered")
	}
	// The version string is derived exactly as GetConfiguration derives the one it
	// serves, so equal strings name the same cfg.
	current := "unknown"
	history, err := p.config.GetConfigurationHistory(ctx, info.TenantID, stewardID, 1)
	if err == nil && len(history) > 0 {
		current = fmt.Sprintf("v%d", history[0].Version)
	}
	if reportedVersion != current {
		return "", nil, fmt.Errorf("reported cfg version %q is not the served version %q", reportedVersion, current)
	}
	eff, err := p.config.GetEffectiveConfiguration(ctx, info.TenantID, stewardID)
	if err != nil {
		return "", nil, fmt.Errorf("resolve effective cfg: %w", err)
	}
	if eff == nil || eff.Config == nil {
		return "", nil, fmt.Errorf("steward has no effective cfg")
	}
	return info.TenantID, eff.Config.Resources, nil
}

func (p productionApplyOutcomeSources) AuditOperations(moduleName string) ([]string, error) {
	bundleName, _, _ := strings.Cut(moduleName, ".")
	entries, err := p.cache.List()
	if err != nil {
		return nil, fmt.Errorf("list module cache: %w", err)
	}
	var ops []string
	for _, entry := range entries {
		if entry.Status != modulecache.ApprovalStatusApproved || entry.Addr.Name != bundleName {
			continue
		}
		b, err := p.cache.Get(entry.Addr)
		if err != nil || b.Manifest == nil || b.Manifest.Security == nil {
			continue
		}
		ops = append(ops, b.Manifest.Security.AuditOperations...)
	}
	return ops, nil
}

// applyOutcomeAuditSourcesOrNil returns the wired sources, the production ones
// when the controller services are present, or nil (audit disabled).
func (s *Server) applyOutcomeAuditSourcesOrNil() applyOutcomeAuditSources {
	if s.outcomeAuditSources != nil {
		return s.outcomeAuditSources
	}
	if s.controllerService == nil || s.configService == nil || s.moduleCache == nil {
		return nil
	}
	return productionApplyOutcomeSources{controller: s.controllerService, config: s.configService, cache: s.moduleCache}
}

// auditApplyOutcomes emits one audit event for every apply-outcome record that
// reports a completed write (changed = true) whose operation the module's
// approved manifest lists under audit_operations. The event is recorded under
// the steward's registered tenant and the cfg-declared resource id, with the
// steward as actor.
//
// Outcomes are steward-supplied and the steward may be compromised, so a record
// whose resource id is not declared, under the same module, in that steward's
// own effective cfg at the version it reported is dropped and logged. Any
// failure to establish the declared set drops every candidate: a missed audit
// event is visible in the log, a forged one in the audit trail is not.
//
// Details carry only the module, cfg version and outcome status; cfg field
// values, passwords and sensitive fields are never copied.
func (s *Server) auditApplyOutcomes(ctx context.Context, stewardID, configVersion string, rawOutcomes []interface{}) {
	if s.auditManager == nil {
		return
	}
	sources := s.applyOutcomeAuditSourcesOrNil()
	if sources == nil {
		return
	}

	type candidate struct{ resourceID, module, operation, status string }
	var candidates []candidate
	for _, raw := range rawOutcomes {
		rec, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		changed, _ := rec["changed"].(bool)
		operation, _ := rec["operation"].(string)
		if !changed || operation == "" {
			continue
		}
		resourceID, _ := rec["resource_id"].(string)
		module, _ := rec["module_name"].(string)
		status, _ := rec["status"].(string)
		if resourceID == "" || module == "" {
			continue
		}
		candidates = append(candidates, candidate{resourceID, module, operation, status})
	}
	if len(candidates) == 0 {
		return
	}

	tenantID, declared, err := sources.DeclaredResources(ctx, stewardID, configVersion)
	if err != nil {
		s.logger.Warn("Dropping apply-outcome audit: steward's declared cfg unavailable",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"config_version", logging.SanitizeLogValue(configVersion),
			"dropped", len(candidates),
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	declaredBy := make(map[[2]string]struct{}, len(declared))
	for _, r := range declared {
		declaredBy[[2]string{r.Name, r.Module}] = struct{}{}
	}

	opsCache := make(map[string]map[string]struct{})
	for _, c := range candidates {
		if _, ok := declaredBy[[2]string{c.resourceID, c.module}]; !ok {
			s.logger.Warn("Dropping apply-outcome audit: resource not declared in the steward's own cfg",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"resource_id", logging.SanitizeLogValue(c.resourceID),
				"module", logging.SanitizeLogValue(c.module),
				"config_version", logging.SanitizeLogValue(configVersion))
			continue
		}
		audited, ok := opsCache[c.module]
		if !ok {
			ops, err := sources.AuditOperations(c.module)
			if err != nil {
				s.logger.Warn("Apply-outcome audit: module manifest unavailable",
					"module", logging.SanitizeLogValue(c.module),
					"error", logging.SanitizeLogValue(err.Error()))
			}
			audited = make(map[string]struct{}, len(ops))
			for _, op := range ops {
				audited[op] = struct{}{}
			}
			opsCache[c.module] = audited
		}
		if _, ok := audited[c.operation]; !ok {
			continue
		}

		result := business.AuditResultSuccess
		severity := business.AuditSeverityMedium
		if c.status != "applied" {
			result = business.AuditResultFailure
			severity = business.AuditSeverityHigh
		}
		b := audit.NewEventBuilder().
			Tenant(tenantID).
			Type(business.AuditEventDataModification).
			Action(c.operation).
			User(stewardID, business.AuditUserTypeSystem).
			Resource(c.module, c.resourceID, "").
			Result(result).
			Severity(severity).
			Detail("module", c.module).
			Detail("config_version", configVersion).
			Detail("status", c.status)
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), applyOutcomeAuditTimeout)
		if err := s.auditManager.RecordEvent(auditCtx, b); err != nil {
			s.logger.Warn("Failed to emit apply-outcome audit event",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"action", logging.SanitizeLogValue(c.operation),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		cancel()
	}
}
