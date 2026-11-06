// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ErrScriptNotFound is returned when no library in the chain holds the script,
// or the nearest holder lacks the requested version.
var ErrScriptNotFound = errors.New("script not found in the library chain")

// InheritedScriptMetadata is a listed script with the tenant that owns it.
type InheritedScriptMetadata struct {
	*ScriptMetadata
	OwnerTenant string
}

func validSegment(v string) bool {
	return v != "" && !strings.ContainsAny(v, `/\`) && !strings.Contains(v, "..")
}

func validateChain(chain []string) error {
	if len(chain) == 0 {
		return ErrTenantRequired
	}
	for _, id := range chain {
		if !validSegment(id) {
			return fmt.Errorf("invalid tenant id in library chain")
		}
	}
	return nil
}

// ownerOf returns the tenant of the library object that served the script, read
// back from the stored entry key rather than assumed from the chain position.
func (r *GitScriptRepository) ownerOf(ctx context.Context, id, version string) (string, error) {
	if version == "" {
		version = "latest"
	}
	entry, err := r.configStore.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID: r.tenantID, Namespace: r.namespace, Name: id, Scope: version,
	})
	if err != nil {
		return "", err
	}
	if entry.Key == nil || entry.Key.TenantID == "" {
		return "", fmt.Errorf("library object has no owner tenant")
	}
	return entry.Key.TenantID, nil
}

// ResolveInherited finds a script in the first library of chain (nearest first)
// that holds id, and reports the tenant owning that library object. The id
// decides: if the nearest holder lacks the requested version the call returns
// ErrScriptNotFound and never falls through to an ancestor.
func (t *TenantScriptRepository) ResolveInherited(ctx context.Context, chain []string, id, version string) (*VersionedScript, string, error) {
	if err := validateChain(chain); err != nil {
		return nil, "", err
	}
	if !validSegment(id) {
		return nil, "", fmt.Errorf("invalid script id")
	}
	for _, tenantID := range chain {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		repo, err := t.ForTenant(tenantID)
		if err != nil {
			return nil, "", err
		}
		// Does this library hold the id at all?
		if _, err := repo.configStore.GetConfig(ctx, &cfgconfig.ConfigKey{
			TenantID: tenantID, Namespace: repo.namespace, Name: id, Scope: "latest",
		}); err != nil {
			if errors.Is(err, cfgconfig.ErrConfigNotFound) {
				continue
			}
			return nil, "", fmt.Errorf("library lookup failed: %w", err)
		}
		s, err := repo.Get(id, version)
		if err != nil {
			if errors.Is(err, cfgconfig.ErrConfigNotFound) {
				return nil, "", ErrScriptNotFound
			}
			return nil, "", err
		}
		owner, err := repo.ownerOf(ctx, id, version)
		if err != nil {
			return nil, "", err
		}
		return s, owner, nil
	}
	return nil, "", ErrScriptNotFound
}

// ListInherited lists the scripts visible through chain, de-duplicated by id with
// the nearest copy winning and its owner shown.
func (t *TenantScriptRepository) ListInherited(ctx context.Context, chain []string, filter *ScriptFilter) ([]*InheritedScriptMetadata, error) {
	if err := validateChain(chain); err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var out []*InheritedScriptMetadata
	for _, tenantID := range chain {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		repo, err := t.ForTenant(tenantID)
		if err != nil {
			return nil, err
		}
		// Unfiltered so a nearer copy that the filter excludes still shadows ancestors.
		all, err := repo.List(nil)
		if err != nil {
			return nil, err
		}
		for _, m := range all {
			if seen[m.ID] {
				continue
			}
			seen[m.ID] = true
			if filter != nil && !repo.matchesFilter(m, filter) {
				continue
			}
			out = append(out, &InheritedScriptMetadata{ScriptMetadata: m, OwnerTenant: tenantID})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
