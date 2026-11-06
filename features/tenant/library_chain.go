// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// TenantPathGetter is the part of Manager that LibraryChain needs.
type TenantPathGetter interface {
	GetTenantPath(ctx context.Context, tenantID string) ([]string, error)
}

var _ TenantPathGetter = (*Manager)(nil)

// ErrInvalidLibraryTenantID is returned for a tenant id that is empty or could
// escape a store key (path separator or traversal sequence).
var ErrInvalidLibraryTenantID = errors.New("invalid tenant id for library chain")

// ErrCeilingNotAncestor is returned when the ceiling tenant is neither the run
// tenant nor one of its ancestors.
var ErrCeilingNotAncestor = errors.New("ceiling tenant is not the run tenant or one of its ancestors")

func validateLibraryTenantID(id string) error {
	if id == "" || strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
		return ErrInvalidLibraryTenantID
	}
	return nil
}

// LibraryChain returns the ordered tenants whose script libraries a run tenant
// may resolve from: the run tenant first, then each ancestor up to and including
// ceilingTenant. Any hierarchy error fails the call; it never degrades to a
// one-element chain.
func LibraryChain(ctx context.Context, mgr TenantPathGetter, runTenant, ceilingTenant string) ([]string, error) {
	if mgr == nil {
		return nil, fmt.Errorf("tenant manager is required")
	}
	if err := validateLibraryTenantID(runTenant); err != nil {
		return nil, err
	}
	if err := validateLibraryTenantID(ceilingTenant); err != nil {
		return nil, err
	}

	path, err := mgr.GetTenantPath(ctx, runTenant)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant path: %w", err)
	}
	// The path is root-first and must end with the tenant itself.
	if len(path) == 0 || path[len(path)-1] != runTenant {
		return nil, fmt.Errorf("tenant path for run tenant is malformed")
	}

	ceilingIdx := -1
	for i, id := range path {
		if err := validateLibraryTenantID(id); err != nil {
			return nil, err
		}
		if id == ceilingTenant {
			ceilingIdx = i
		}
	}
	if ceilingIdx < 0 {
		return nil, ErrCeilingNotAncestor
	}

	chain := make([]string, 0, len(path)-ceilingIdx)
	for i := len(path) - 1; i >= ceilingIdx; i-- {
		chain = append(chain, path[i])
	}
	return chain, nil
}
