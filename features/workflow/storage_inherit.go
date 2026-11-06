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
	if configStore == nil {
		return nil, "", fmt.Errorf("config store is required")
	}
	if len(chain) == 0 {
		return nil, "", fmt.Errorf("tenant chain is required")
	}
	for _, id := range chain {
		if !validWorkflowSegment(id) {
			return nil, "", fmt.Errorf("invalid tenant id in tenant chain")
		}
	}
	if !validWorkflowSegment(name) {
		return nil, "", fmt.Errorf("invalid workflow name")
	}
	if version == "" {
		return nil, "", ErrWorkflowVersionRequired
	}
	sv, err := ParseSemanticVersion(version)
	if err != nil {
		return nil, "", fmt.Errorf("invalid workflow version")
	}

	for _, tenantID := range chain {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		store := NewWorkflowStore(configStore, tenantID)
		held, err := store.ListWorkflowVersions(ctx, name)
		if err != nil {
			return nil, "", err
		}
		if len(held) == 0 {
			continue
		}
		wf, err := store.GetWorkflow(ctx, name, *sv)
		if err != nil {
			if errors.Is(err, cfgconfig.ErrConfigNotFound) {
				return nil, "", ErrWorkflowNotFound
			}
			return nil, "", err
		}
		owner, err := workflowOwner(ctx, configStore, tenantID, name, *sv)
		if err != nil {
			return nil, "", err
		}
		return wf, owner, nil
	}
	return nil, "", ErrWorkflowNotFound
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
