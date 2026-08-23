// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"fmt"
	"strings"
)

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
//	}
type StoreRequirement struct {
	// Subsystem identifies the feature or component that depends on this store.
	// Used verbatim in startup error messages so operators can identify what broke.
	Subsystem string
	// Store names the store this subsystem requires or optionally uses.
	Store StoreName
	// Severity controls whether absence blocks startup.
	Severity RequirementSeverity
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
