// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces_test — provider factory for contract tests.
// Kept in a file named providers_test.go so that the check-providers.sh
// architecture script allows the direct flatfile import (*/providers_test.go exception).
package interfaces_test

import (
	"context"
	"fmt"
	"testing"

	routerinterfaces "github.com/cfgis/cfgms/pkg/configrouting/interfaces"
	controllerrouter "github.com/cfgis/cfgms/pkg/configrouting/providers/controller"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	flatfile "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// contractTenantStore is the in-memory tenant store used by the contract test factory.
// It provides a fixed 3-level hierarchy: root → msp → client.
type contractTenantStore struct {
	tenants map[string]*business.TenantData
}

func newContractTenantStore() *contractTenantStore {
	ts := &contractTenantStore{tenants: make(map[string]*business.TenantData)}
	for _, td := range []*business.TenantData{
		{ID: "root", Name: "Root", Status: business.TenantStatusActive},
		{ID: "msp", Name: "MSP", ParentID: "root", Status: business.TenantStatusActive},
		{ID: "client", Name: "Client", ParentID: "msp", Status: business.TenantStatusActive},
	} {
		ts.tenants[td.ID] = td
	}
	return ts
}

func (s *contractTenantStore) Initialize(_ context.Context) error { return nil }
func (s *contractTenantStore) Close() error                       { return nil }
func (s *contractTenantStore) CreateTenant(_ context.Context, t *business.TenantData) error {
	s.tenants[t.ID] = t
	return nil
}
func (s *contractTenantStore) GetTenant(_ context.Context, id string) (*business.TenantData, error) {
	t, ok := s.tenants[id]
	if !ok {
		return nil, fmt.Errorf("tenant not found: %s", id)
	}
	return t, nil
}
func (s *contractTenantStore) UpdateTenant(_ context.Context, t *business.TenantData) error {
	s.tenants[t.ID] = t
	return nil
}
func (s *contractTenantStore) DeleteTenant(_ context.Context, id string) error {
	delete(s.tenants, id)
	return nil
}
func (s *contractTenantStore) ListTenants(_ context.Context, _ *business.TenantFilter) ([]*business.TenantData, error) {
	out := make([]*business.TenantData, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	return out, nil
}
func (s *contractTenantStore) GetTenantHierarchy(_ context.Context, id string) (*business.TenantHierarchy, error) {
	path, _ := s.GetTenantPath(context.Background(), id)
	return &business.TenantHierarchy{TenantID: id, Path: path, Depth: len(path) - 1}, nil
}
func (s *contractTenantStore) GetChildTenants(_ context.Context, parentID string) ([]*business.TenantData, error) {
	var children []*business.TenantData
	for _, t := range s.tenants {
		if t.ParentID == parentID {
			children = append(children, t)
		}
	}
	return children, nil
}
func (s *contractTenantStore) GetTenantPath(_ context.Context, tenantID string) ([]string, error) {
	var path []string
	cur := tenantID
	seen := make(map[string]bool)
	for {
		if seen[cur] {
			return nil, fmt.Errorf("cycle detected for %q", tenantID)
		}
		seen[cur] = true
		path = append([]string{cur}, path...)
		t, ok := s.tenants[cur]
		if !ok {
			return nil, fmt.Errorf("tenant not found: %s", cur)
		}
		if t.ParentID == "" {
			break
		}
		cur = t.ParentID
	}
	return path, nil
}
func (s *contractTenantStore) IsTenantAncestor(_ context.Context, ancestorID, descendantID string) (bool, error) {
	cur := descendantID
	seen := make(map[string]bool)
	for {
		if seen[cur] {
			return false, nil
		}
		seen[cur] = true
		t, ok := s.tenants[cur]
		if !ok {
			return false, nil
		}
		if t.ParentID == ancestorID {
			return true, nil
		}
		if t.ParentID == "" {
			return false, nil
		}
		cur = t.ParentID
	}
}

// controllerRouterFactory creates a ControllerRouter backed by a FlatFileConfigStore
// and an in-memory tenant store with the required 3-level hierarchy (root → msp → client).
func controllerRouterFactory(t *testing.T) (routerinterfaces.ConfigSourceRouter, func()) {
	t.Helper()
	flatfileRoot := t.TempDir()
	cs, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	if err != nil {
		t.Fatalf("failed to create flatfile store: %v", err)
	}
	ts := newContractTenantStore()
	router := controllerrouter.NewControllerRouter(cs, ts)
	return router, func() {}
}

// TestControllerRouter_ContractSuite runs all ConfigSourceRouter contract tests against
// the Phase 1 controller provider implementation.
func TestControllerRouter_ContractSuite(t *testing.T) {
	RunRouterContractTests(t, controllerRouterFactory)
}
