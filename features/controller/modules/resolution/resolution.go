// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package resolution implements required-module resolution for cfg file deployment.
// When a fleet cfg file declares required_modules:, the controller must verify that
// each module is cached and approved before allowing deployment to proceed.
package resolution

import (
	"context"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// CacheLister is the subset of cache.ModuleCache used by resolution.
type CacheLister interface {
	List() ([]cache.CacheEntry, error)
}

// BundleResolver resolves a "publisher/name@version" reference to a bundle.
type BundleResolver interface {
	Resolve(ctx context.Context, ref string) (*bundle.Bundle, error)
}

// BundleApprover evaluates a bundle against the trust store and persists the decision.
type BundleApprover interface {
	EvaluateAndStore(b *bundle.Bundle, store trust.TrustStore) (approval.ApprovalDecision, error)
}

// ResolveCfgRequiredModules verifies that every module listed in required is
// present and approved in the controller cache before a cfg file is deployed.
//
// For each RequiredModule:
//   - If the module is in the cache with ApprovalStatusApproved: no action needed.
//   - If the module is in the cache with pending or rejected status: blocked.
//   - If the module is not in the cache: resolver is called to fetch the bundle,
//     then approver.EvaluateAndStore is called. AutoApprove continues; any other
//     decision blocks deployment.
//
// Returns nil when all required modules are approved.
// Returns a descriptive error listing each blocked module if any are not approved.
func ResolveCfgRequiredModules(
	ctx context.Context,
	required []stewardtypes.RequiredModule,
	c CacheLister,
	resolver BundleResolver,
	approver BundleApprover,
	store trust.TrustStore,
) error {
	if len(required) == 0 {
		return nil
	}

	entries, err := c.List()
	if err != nil {
		return fmt.Errorf("list module cache: %w", err)
	}

	// Index cached entries: "publisher/name@version" → ApprovalStatus.
	cached := make(map[string]cache.ApprovalStatus, len(entries))
	for _, e := range entries {
		key := e.Addr.Publisher + "/" + e.Addr.Name + "@" + e.Addr.Version
		cached[key] = e.Status
	}

	var blocked []string
	for _, req := range required {
		key := req.Name + "@" + req.Version

		if status, found := cached[key]; found {
			if status != cache.ApprovalStatusApproved {
				blocked = append(blocked, key)
			}
			continue
		}

		// Not cached: fetch and evaluate.
		b, resolveErr := resolver.Resolve(ctx, key)
		if resolveErr != nil {
			return fmt.Errorf("resolve module %s: %w", key, resolveErr)
		}

		decision, evalErr := approver.EvaluateAndStore(b, store)
		if evalErr != nil {
			return fmt.Errorf("evaluate module %s: %w", key, evalErr)
		}

		if decision != approval.AutoApprove {
			blocked = append(blocked, key)
		}
	}

	if len(blocked) == 0 {
		return nil
	}

	msgs := make([]string, len(blocked))
	for i, mod := range blocked {
		msgs[i] = fmt.Sprintf("cfg deployment blocked: module %s requires approval before deploying", mod)
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}
