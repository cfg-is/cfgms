// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"fmt"
	"strings"
)

// AbsentCapability describes a declared-optional store that is absent in the
// running deployment. Returned by CollectAbsentOptionalCapabilities at
// composition time and served verbatim by the administrative status surface.
type AbsentCapability struct {
	// Capability is the store name (e.g. "PushStore").
	Capability string `json:"capability"`
	// Subsystem is the feature or component that declared the optional dependency.
	Subsystem string `json:"subsystem"`
	// Consequence is an operator-actionable description of what the absence means.
	// Written by the declaring subsystem; must name the functional impact, not the
	// internal type (e.g. "Push-state is not persisted — in-flight config pushes
	// may not resume after a controller restart" rather than "PushStore: nil").
	Consequence string `json:"consequence"`
	// Provider is the storage provider currently running, so an operator knows
	// which provider to switch to if they want to supply the missing capability.
	Provider string `json:"provider"`
}

// StoreName identifies a named store within a StorageManager.
type StoreName string

const (
	StoreNameClientTenant        StoreName = "ClientTenantStore"
	StoreNameConfig              StoreName = "ConfigStore"
	StoreNameAudit               StoreName = "AuditStore"
	StoreNameRBAC                StoreName = "RBACStore"
	StoreNameTenant              StoreName = "TenantStore"
	StoreNameRegistrationToken   StoreName = "RegistrationTokenStore"
	StoreNameSession             StoreName = "SessionStore"
	StoreNameSteward             StoreName = "StewardStore"
	StoreNameCommand             StoreName = "CommandStore"
	StoreNameTrigger             StoreName = "TriggerStore"
	StoreNamePush                StoreName = "PushStore"
	StoreNamePendingRegistration StoreName = "PendingRegistrationStore"
	StoreNameIPTrust             StoreName = "IPTrustStore"
	StoreNameAlert               StoreName = "AlertStore"
	StoreNamePendingRefresh      StoreName = "PendingRefreshStore"
	StoreNameRefreshPolicy       StoreName = "RefreshPolicyStore"
	StoreNameAssurancePolicy     StoreName = "AssurancePolicyStore"
	StoreNameTenantCrossing      StoreName = "TenantCrossingStore"
	StoreNameCase                StoreName = "CaseStore"
	StoreNameLease               StoreName = "LeaseStore"
)

// RequirementSeverity controls whether a missing store blocks startup.
type RequirementSeverity int

const (
	// RequirementRequired means the subsystem cannot function without this store.
	// A missing required store blocks composition and names the subsystem, the store,
	// and the provider in the error.
	RequirementRequired RequirementSeverity = iota
	// RequirementOptional means the subsystem degrades gracefully when this store is
	// absent. A missing optional store is silently skipped during validation.
	RequirementOptional
)

// StoreRequirement declares that a named subsystem depends on a particular store.
//
// Declarations live with the consuming subsystem, adjacent to the code that uses
// the store — not in a central per-deployment-shape registry. This ensures a new
// feature's storage dependency is visible next to the code that consumes it, and
// that disabled subsystems impose no requirement on the deployment.
//
// Example (in the subsystem's own package):
//
//	var StoreRequirements = []interfaces.StoreRequirement{
//	    {Subsystem: "registration", Store: interfaces.StoreNamePendingRegistration, Severity: interfaces.RequirementRequired},
//	    {
//	        Subsystem:   "push",
//	        Store:       interfaces.StoreNamePush,
//	        Severity:    interfaces.RequirementOptional,
//	        Consequence: "Push-state is not persisted — in-flight config pushes may not resume after a controller restart",
//	    },
//	}
type StoreRequirement struct {
	// Subsystem identifies the feature or component that depends on this store.
	// Used verbatim in startup error messages so operators can identify what broke.
	Subsystem string
	// Store names the store this subsystem requires or optionally uses.
	Store StoreName
	// Severity controls whether absence blocks startup.
	Severity RequirementSeverity
	// Consequence is an operator-actionable description of what the absence means.
	// Required when Severity is RequirementOptional so that CollectAbsentOptionalCapabilities
	// can surface a human-readable impact rather than a bare store name.
	// Ignored for RequirementRequired (the error message at startup is authoritative).
	Consequence string
}

// HasStore reports whether the named store is non-nil in sm.
//
// This is the check function used by ValidateStorageRequirements — it avoids the
// Go nil-interface pitfall by comparing the concrete field directly rather than
// boxing it into interface{} and comparing against nil.
func (sm *StorageManager) HasStore(name StoreName) bool {
	switch name {
	case StoreNameClientTenant:
		return sm.clientTenantStore != nil
	case StoreNameConfig:
		return sm.configStore != nil
	case StoreNameAudit:
		return sm.auditStore != nil
	case StoreNameRBAC:
		return sm.rbacStore != nil
	case StoreNameTenant:
		return sm.tenantStore != nil
	case StoreNameRegistrationToken:
		return sm.registrationTokenStore != nil
	case StoreNameSession:
		return sm.sessionStore != nil
	case StoreNameSteward:
		return sm.stewardStore != nil
	case StoreNameCommand:
		return sm.commandStore != nil
	case StoreNameTrigger:
		return sm.triggerStore != nil
	case StoreNamePush:
		return sm.pushStore != nil
	case StoreNamePendingRegistration:
		return sm.pendingRegistrationStore != nil
	case StoreNameIPTrust:
		return sm.ipTrustStore != nil
	case StoreNameAlert:
		return sm.alertStore != nil
	case StoreNamePendingRefresh:
		return sm.pendingRefreshStore != nil
	case StoreNameRefreshPolicy:
		return sm.refreshPolicyStore != nil
	case StoreNameAssurancePolicy:
		return sm.assurancePolicyStore != nil
	case StoreNameTenantCrossing:
		return sm.tenantCrossingStore != nil
	case StoreNameCase:
		return sm.caseStore != nil
	case StoreNameLease:
		return sm.leaseStore != nil
	default:
		return false
	}
}

// ValidateStorageRequirements checks that every required store in reqs is present
// in sm. Missing required stores produce a single error that names the subsystem,
// the store, and the provider for each gap — giving an operator all the context
// needed to diagnose which feature broke and why, without digging through source.
//
// Optional stores that are absent are silently skipped. An empty or nil reqs
// slice always succeeds.
//
// Call this at composition time (immediately after the StorageManager is fully
// constructed) with the union of requirements from all enabled subsystems. Do not
// call it again at request time — the point is to convert a silent nil into a
// loud startup failure, not to add a per-request nil-check.
func ValidateStorageRequirements(sm *StorageManager, reqs []StoreRequirement) error {
	var missing []string
	provider := sm.GetProviderName()
	for _, req := range reqs {
		if req.Severity != RequirementRequired {
			continue
		}
		if !sm.HasStore(req.Store) {
			missing = append(missing, fmt.Sprintf(
				"subsystem %q requires %s but provider %q does not supply it",
				req.Subsystem, req.Store, provider,
			))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("storage composition failed — missing required stores:\n%s",
			strings.Join(missing, "\n"))
	}
	return nil
}

// CollectAbsentOptionalCapabilities returns one AbsentCapability entry for each
// optional store in reqs that is absent in sm. Required stores are ignored — their
// absence is already a fatal startup error caught by ValidateStorageRequirements.
//
// providerName is the operator-facing provider label (e.g. "flatfile", "database")
// reported in each entry's Provider field, so an operator can tell which backend
// to switch to for the capability. Callers must not substitute
// sm.GetProviderName(): that returns the internal composition name — "composite"
// for the OSS flatfile+SQLite backend — which names no backend an operator can
// actually choose between and would silently diverge from the provider named in
// each requirement's own operator-facing Consequence text.
//
// Call this once at composition time alongside ValidateStorageRequirements and pass
// the result to the administrative status surface. Never call it per request.
func CollectAbsentOptionalCapabilities(sm *StorageManager, reqs []StoreRequirement, providerName string) []AbsentCapability {
	var absent []AbsentCapability
	for _, req := range reqs {
		if req.Severity != RequirementOptional {
			continue
		}
		if !sm.HasStore(req.Store) {
			absent = append(absent, AbsentCapability{
				Capability:  string(req.Store),
				Subsystem:   req.Subsystem,
				Consequence: req.Consequence,
				Provider:    providerName,
			})
		}
	}
	return absent
}
