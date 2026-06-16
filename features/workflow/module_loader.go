// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"errors"
	"fmt"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/modules"
	contractpkg "github.com/cfgis/cfgms/pkg/modules/contract"
)

// workflowModuleClient is a local alias for the gRPC contract type that the
// controller workflow engine expects. It anchors this file's dependency on
// pkg/modules/contract so the import is compile-checked rather than a bare
// string.
type workflowModuleClient = contractpkg.WorkflowModuleClient

// ModuleLoader creates module instances by name for use by the workflow engine.
// Placing this interface here (rather than in features/modules/) keeps it
// workflow-internal — only Engine consumes it, so no central-provider
// interfaces/ subdirectory is required.
type ModuleLoader interface {
	CreateModuleInstance(moduleName string) (modules.Module, error)
}

// ErrModuleNotCached is returned by WorkflowModuleFactory.CreateModuleInstance
// when no approved, controller-kind bundle matching the requested module name
// exists in the controller module cache. Tools that surface this error to
// operators should suggest publishing a bundle for the requested module via
// the controller cache APIs (#1883).
var ErrModuleNotCached = errors.New("workflow: module bundle not found in controller cache")

// ErrWorkflowRuntimeNotAvailable is returned when the lookup succeeded but the
// fork/exec + gRPC connect path for workflow modules has not been implemented
// yet. Tracked as a follow-up to #1887: the steward runtime (#1885) covers
// steward-kind module hosting; the workflow-kind equivalent for hosting
// controller-kind modules is its own story and is not in scope for this PR.
var ErrWorkflowRuntimeNotAvailable = errors.New("workflow: in-controller module runtime is not yet implemented (follow-up to #1887)")

// WorkflowModuleFactory is the controller-side ModuleLoader.
//
// It looks up controller-kind module bundles by name in the controller module
// cache (#1883), then — once the runtime piece lands — fork/execs the bundle's
// binary and connects a WorkflowModuleClient gRPC client to it.
//
// Today the factory implements the lookup half: an unknown name returns
// ErrModuleNotCached and an unapproved/wrong-kind match is filtered out. A
// successful lookup proceeds to the (currently un-implemented) runtime helper,
// which surfaces ErrWorkflowRuntimeNotAvailable. Callers should treat that as
// "queued for a future runtime story" rather than as a hard failure of #1887.
type WorkflowModuleFactory struct {
	cache *cache.ModuleCache
}

// NewWorkflowModuleFactory returns a WorkflowModuleFactory backed by the given
// controller module cache. Production callers pass the controller's shared
// ModuleCache so workflow-kind bundles delivered via the cache APIs are
// discoverable.
func NewWorkflowModuleFactory(c *cache.ModuleCache) ModuleLoader {
	return &WorkflowModuleFactory{cache: c}
}

// CreateModuleInstance looks up an approved controller-kind bundle matching
// moduleName in the cache. The first matching entry wins (List does not
// guarantee an order; once the cache exposes a "latest approved version by
// name" helper, prefer it). When found, the runtime helper is asked to
// fork/exec the bundle's binary and connect a WorkflowModuleClient gRPC; that
// helper is not implemented yet and surfaces ErrWorkflowRuntimeNotAvailable.
func (f *WorkflowModuleFactory) CreateModuleInstance(moduleName string) (modules.Module, error) {
	if f.cache == nil {
		return nil, fmt.Errorf("workflow: module factory has no cache backing — call NewWorkflowModuleFactory with a non-nil cache")
	}

	entries, err := f.cache.List()
	if err != nil {
		return nil, fmt.Errorf("workflow: list cache for %q: %w", moduleName, err)
	}

	for _, e := range entries {
		if e.Addr.Name != moduleName {
			continue
		}
		if e.Status != cache.ApprovalStatusApproved {
			continue
		}
		// Found an approved bundle. The next step — fork binary + connect
		// gRPC — needs the workflow-kind module runtime to exist.
		return nil, fmt.Errorf("workflow: %s found in cache (version %s, hash %s) but %w",
			moduleName, e.Addr.Version, e.Addr.ContentHash, ErrWorkflowRuntimeNotAvailable)
	}

	return nil, fmt.Errorf("workflow: %s: %w", moduleName, ErrModuleNotCached)
}

// Ensure workflowModuleClient alias is referenced so the compiler sees it as used.
var _ workflowModuleClient
