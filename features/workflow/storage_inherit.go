// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ErrWorkflowNotFound is returned when no tenant in the chain holds the workflow,
// or the nearest holder lacks the requested version.
var ErrWorkflowNotFound = errors.New("workflow not found in the tenant chain")

// ErrWorkflowVersionRequired is returned when an inherited lookup has no version.
var ErrWorkflowVersionRequired = errors.New("workflow version is required")

func validWorkflowSegment(v string) bool {
	return v != "" && !strings.ContainsAny(v, `/\`) && !strings.Contains(v, "..")
}

// ResolveInherited finds an exact workflow version in the first tenant of chain
// (nearest first, as built by tenant.LibraryChain) that holds the name, and
// reports the tenant that owns the stored object. The name decides: if the
// nearest holder lacks the requested version the call returns
// ErrWorkflowNotFound and never falls through to an ancestor. The version is
// required; there is no "latest".
func ResolveInherited(ctx context.Context, configStore cfgconfig.ConfigStore, chain []string, name, version string) (*VersionedWorkflow, string, error) {
	sv, err := validateInheritedLookup(configStore, chain, name, version)
	if err != nil {
		return nil, "", err
	}
	for _, tenantID := range chain {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		wf, owner, held, err := resolveInTenant(ctx, configStore, tenantID, name, sv)
		if err != nil || held {
			return wf, owner, err
		}
	}
	return nil, "", ErrWorkflowNotFound
}

// validateInheritedLookup checks the inputs of ResolveInherited and parses the
// required exact version.
func validateInheritedLookup(configStore cfgconfig.ConfigStore, chain []string, name, version string) (SemanticVersion, error) {
	if configStore == nil {
		return SemanticVersion{}, fmt.Errorf("config store is required")
	}
	if len(chain) == 0 {
		return SemanticVersion{}, fmt.Errorf("tenant chain is required")
	}
	for _, id := range chain {
		if !validWorkflowSegment(id) {
			return SemanticVersion{}, fmt.Errorf("invalid tenant id in tenant chain")
		}
	}
	if !validWorkflowSegment(name) {
		return SemanticVersion{}, fmt.Errorf("invalid workflow name")
	}
	if version == "" {
		return SemanticVersion{}, ErrWorkflowVersionRequired
	}
	sv, err := ParseSemanticVersion(version)
	if err != nil {
		return SemanticVersion{}, fmt.Errorf("invalid workflow version")
	}
	return *sv, nil
}

// resolveInTenant looks the workflow up in a single tenant. held reports
// whether the tenant holds any version of the name; when it does, the result
// (workflow or error) is final and the caller must not fall through to an
// ancestor.
func resolveInTenant(ctx context.Context, configStore cfgconfig.ConfigStore, tenantID, name string, sv SemanticVersion) (*VersionedWorkflow, string, bool, error) {
	store := NewWorkflowStore(configStore, tenantID)
	versions, err := store.ListWorkflowVersions(ctx, name)
	if err != nil {
		return nil, "", false, err
	}
	if len(versions) == 0 {
		return nil, "", false, nil
	}
	wf, err := store.GetWorkflow(ctx, name, sv)
	if errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return nil, "", true, ErrWorkflowNotFound
	}
	if err != nil {
		return nil, "", true, err
	}
	owner, err := workflowOwner(ctx, configStore, tenantID, name, sv)
	if err != nil {
		return nil, "", true, err
	}
	return wf, owner, true, nil
}

// workflowOwner reads the owner tenant back from the stored entry's key rather
// than assuming it from the chain position.
func workflowOwner(ctx context.Context, configStore cfgconfig.ConfigStore, tenantID, name string, v SemanticVersion) (string, error) {
	entry, err := configStore.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID: tenantID, Namespace: WorkflowNamespace, Name: name, Scope: v.String(),
	})
	if err != nil {
		return "", err
	}
	if entry.Key == nil || entry.Key.TenantID == "" {
		return "", fmt.Errorf("workflow object has no owner tenant")
	}
	return entry.Key.TenantID, nil
}
