// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/workflow/runtime"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// ModuleLoader creates module instances by name for use by the workflow engine.
// Placing this interface here (rather than in features/modules/) keeps it
// workflow-internal — only Engine consumes it, so no central-provider
// interfaces/ subdirectory is required.
type ModuleLoader interface {
	CreateModuleInstance(moduleName string) (modules.Module, error)
}

// TenantModuleLoader is the optional tenant-scoped extension of ModuleLoader.
// The engine uses it when its loader implements it, passing the execution
// tenant (ctxkeys.TenantID) so the module session is scoped to that tenant and
// credentialed modules can be issued a tenant-specific credential. It is a
// separate interface so ModuleLoader implementations that need no tenant (the
// steward module factory and its test doubles) stay unchanged.
type TenantModuleLoader interface {
	CreateTenantModuleInstance(ctx context.Context, moduleName, tenantID string) (modules.Module, error)
}

// ErrModuleNotCached is returned by WorkflowModuleFactory.CreateModuleInstance
// when no approved, controller-kind bundle matching the requested module name
// exists in the controller module cache. Tools that surface this error to
// operators should suggest publishing a bundle for the requested module via
// the controller cache APIs (#1883).
var ErrModuleNotCached = errors.New("workflow: module bundle not found in controller cache")

// WorkflowModuleFactory is the controller-side ModuleLoader.
//
// It looks up approved controller-kind module bundles by name in the
// controller module cache (#1883), then fork/execs the bundle's binary and
// connects a WorkflowModuleClient gRPC client to it via the embedded
// workflow module runtime.
type WorkflowModuleFactory struct {
	cache   *cache.ModuleCache
	runtime *runtime.ModuleRuntime

	// credentials issues the Graph access token for CFGMS-published M365
	// modules. Nil until NewEngine hands the factory the controller secret
	// store; with no issuer every credentialed module is refused.
	credentials *M365CredentialIssuer
}

// NewWorkflowModuleFactory returns a WorkflowModuleFactory backed by the given
// controller module cache and workflow module runtime. Production callers pass
// the controller's shared ModuleCache and a ModuleRuntime so workflow-kind
// bundles delivered via the cache APIs are discoverable and executable.
//
// Passing nil for cache causes every CreateModuleInstance call to return a
// descriptive error (useful for REST-only controllers that never resolve
// modules through the engine). Passing nil for rt causes a descriptive error
// when a cache hit is found but the runtime is unavailable.
func NewWorkflowModuleFactory(c *cache.ModuleCache, rt *runtime.ModuleRuntime) ModuleLoader {
	return &WorkflowModuleFactory{cache: c, runtime: rt}
}

// useSecretStore gives the factory the controller secret store its credential
// issuer reads tenant connections from. A nil store leaves the issuer unset.
func (f *WorkflowModuleFactory) useSecretStore(store secretsif.SecretStore) {
	f.credentials = NewM365CredentialIssuer(store)
}

// CreateModuleInstance looks up an approved controller-kind bundle matching
// moduleName in the cache, then fork/execs it via the workflow module runtime
// and returns a connected WorkflowModuleClient as a modules.Module.
//
// Error precedence:
//  1. nil cache — returns a descriptive error
//  2. cache list error — propagated as-is
//  3. no approved bundle for moduleName — ErrModuleNotCached
//  4. bundle load error — propagated as-is
//  5. runtime unavailable (nil rt) — descriptive error
//  6. runtime.Start error — propagated as-is (fork/exec or gRPC failure)
//
// This tenant-less path starts no execution-tenant-scoped session, so it refuses
// every credentialed (CFGMS-published M365) module: use
// CreateTenantModuleInstance for those.
func (f *WorkflowModuleFactory) CreateModuleInstance(moduleName string) (modules.Module, error) {
	return f.create(context.Background(), moduleName, "", false)
}

// CreateTenantModuleInstance is CreateModuleInstance for an execution tenant.
// tenantID scopes the module session (WorkflowHandshakeRequest.tenant_id). For a
// credentialed module the factory mints the tenant's access token BEFORE
// fork/exec; if that fails, or tenantID is empty, or the factory has no secret
// store, it returns an error and starts no process. Every other module gets the
// tenant with an empty auth_token.
func (f *WorkflowModuleFactory) CreateTenantModuleInstance(ctx context.Context, moduleName, tenantID string) (modules.Module, error) {
	return f.create(ctx, moduleName, tenantID, true)
}

func (f *WorkflowModuleFactory) create(ctx context.Context, moduleName, tenantID string, tenantScoped bool) (modules.Module, error) {
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

		// Found an approved bundle — load it from the cache to get the binary paths.
		b, loadErr := f.cache.Get(e.Addr)
		if loadErr != nil {
			return nil, fmt.Errorf("workflow: load bundle %q: %w", moduleName, loadErr)
		}

		// Derive Kind from Executors since Kind is yaml:"-" and is not persisted
		// in the cache YAML — it must be re-derived after deserialization.
		if b.Manifest != nil && b.Manifest.Kind == "" &&
			len(b.Manifest.Executors) > 0 && b.Manifest.Executors[0] == "controller" {
			b.Manifest.Kind = "workflow"
		}

		if f.runtime == nil {
			return nil, fmt.Errorf("workflow: %s found in cache (version %s, hash %s) but no workflow module runtime is configured",
				moduleName, e.Addr.Version, e.Addr.ContentHash)
		}

		authToken := ""
		if isCredentialedModule(b) {
			switch {
			case !tenantScoped:
				return nil, fmt.Errorf("workflow: module %q requires an execution tenant for its M365 credential and cannot be created without one", moduleName)
			case tenantID == "":
				return nil, fmt.Errorf("workflow: module %q requires an execution tenant for its M365 credential: no tenant in the execution context", moduleName)
			case f.credentials == nil:
				return nil, fmt.Errorf("workflow: module %q cannot be issued an M365 credential for tenant %q: the workflow engine has no secret store", moduleName, tenantID)
			}
			var issueErr error
			authToken, issueErr = f.credentials.Issue(ctx, moduleName, tenantID)
			if issueErr != nil {
				return nil, issueErr
			}
		}

		handle, startErr := f.runtime.Start(b, tenantID, authToken)
		if startErr != nil {
			return nil, fmt.Errorf("workflow: start module %q: %w", moduleName, startErr)
		}
		return handle, nil
	}

	return nil, fmt.Errorf("workflow: %s: %w", moduleName, ErrModuleNotCached)
}
