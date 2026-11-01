// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// This file is the single billing aggregation (ADR-025 Amendment 6, A6.1 and A6.3).
// rollupTenantCounts computes one whole-tree roll-up; aggregateBilling is a thin
// projection of it for one tenant subtree. Every billing surface (tenant list
// device_count, boundary rows, root and MSP reports, CLI) reads from here so the
// surfaces cannot disagree.
//
// The data is unscoped and unredacted: it carries real names, IDs and labels.
// Each caller projects what its audience may see. Nothing here takes a caller or
// principal.

// errBillingTenantNotFound is returned by aggregateBilling for an unknown subtree root.
var errBillingTenantNotFound = errors.New("billing: tenant not found")

// stewardCountsTowardBilling is the single definition of an endpoint: registered,
// active and lost stewards count. Terminal states (deregistered, archived, dormant,
// revoked) do not. Hidden is a view flag, not a billing state, so it is not consulted.
func stewardCountsTowardBilling(status business.StewardStatus) bool {
	switch status {
	case business.StewardStatusRegistered, business.StewardStatusActive, business.StewardStatusLost:
		return true
	}
	return false
}

// platformCounts is the per-platform endpoint split. Fixed fields, so the JSON keys
// are exactly windows/linux/darwin/other.
type platformCounts struct {
	Windows int `json:"windows"`
	Linux   int `json:"linux"`
	Darwin  int `json:"darwin"`
	Other   int `json:"other"`
}

// billingMetrics are anonymized platform metrics derived from steward records
// (A6.1). The type holds counts only: it has no field that can carry a host name,
// device ID, IP address or steward ID, so leaking one is a compile error.
// EndpointsByVersion maps a steward version string (not a device identifier) to a count.
type billingMetrics struct {
	EndpointsOnline     int            `json:"endpoints_online"`  // status active
	EndpointsOffline    int            `json:"endpoints_offline"` // status lost
	EndpointsPending    int            `json:"endpoints_pending"` // status registered
	EndpointsByPlatform platformCounts `json:"endpoints_by_platform"`
	EndpointsByVersion  map[string]int `json:"endpoints_by_version"`
}

// unknownStewardVersion buckets stewards that never reported a version.
const unknownStewardVersion = "unknown"

// addSteward counts one billable steward record into m.
func (m *billingMetrics) addSteward(rec *business.StewardRecord) {
	switch rec.Status {
	case business.StewardStatusActive:
		m.EndpointsOnline++
	case business.StewardStatusLost:
		m.EndpointsOffline++
	case business.StewardStatusRegistered:
		m.EndpointsPending++
	}
	switch strings.ToLower(rec.Platform) {
	case "windows":
		m.EndpointsByPlatform.Windows++
	case "linux":
		m.EndpointsByPlatform.Linux++
	case "darwin":
		m.EndpointsByPlatform.Darwin++
	default:
		m.EndpointsByPlatform.Other++
	}
	version := rec.Version
	if version == "" {
		version = unknownStewardVersion
	}
	if m.EndpointsByVersion == nil {
		m.EndpointsByVersion = make(map[string]int)
	}
	m.EndpointsByVersion[version]++
}

// add folds o into m.
func (m *billingMetrics) add(o *billingMetrics) {
	m.EndpointsOnline += o.EndpointsOnline
	m.EndpointsOffline += o.EndpointsOffline
	m.EndpointsPending += o.EndpointsPending
	m.EndpointsByPlatform.Windows += o.EndpointsByPlatform.Windows
	m.EndpointsByPlatform.Linux += o.EndpointsByPlatform.Linux
	m.EndpointsByPlatform.Darwin += o.EndpointsByPlatform.Darwin
	m.EndpointsByPlatform.Other += o.EndpointsByPlatform.Other
	if len(o.EndpointsByVersion) > 0 && m.EndpointsByVersion == nil {
		m.EndpointsByVersion = make(map[string]int, len(o.EndpointsByVersion))
	}
	for v, n := range o.EndpointsByVersion {
		m.EndpointsByVersion[v] += n
	}
}

// tenantRollup is one tenant's entry in the whole-tree roll-up. Own* counts cover
// resources attached to the tenant itself; Subtree* and Metrics cover the tenant and
// every ParentID descendant.
type tenantRollup struct {
	Name         string
	BillingLabel string
	ParentID     string
	Children     []string // direct children, sorted by ID

	OwnTechs         int
	OwnEndpoints     int
	SubtreeTechs     int
	SubtreeEndpoints int
	Metrics          billingMetrics // whole subtree
}

// rollupTenantCounts computes the whole-tree roll-up from one ListTenants, one
// ListStewards and one account listing. It is unscoped.
func (s *Server) rollupTenantCounts(ctx context.Context) (map[string]*tenantRollup, error) {
	if s.tenantManager == nil {
		return map[string]*tenantRollup{}, nil
	}
	tenants, err := s.tenantManager.ListTenants(ctx, &business.TenantFilter{})
	if err != nil {
		return nil, err
	}
	return s.rollupTenants(ctx, tenants)
}

// rollupTenants is rollupTenantCounts over an already-listed tenant set, for callers
// that hold the listing and must not read it twice. It is the only function in this
// package that groups stewards by tenant and rolls the groups up the ParentID chain.
func (s *Server) rollupTenants(ctx context.Context, tenants []*business.TenantData) (map[string]*tenantRollup, error) {
	rollup := make(map[string]*tenantRollup, len(tenants))
	for _, td := range tenants {
		rollup[td.ID] = &tenantRollup{Name: td.Name, BillingLabel: td.BillingLabel, ParentID: td.ParentID}
	}
	for id, tr := range rollup {
		if parent, ok := rollup[tr.ParentID]; ok && tr.ParentID != id {
			parent.Children = append(parent.Children, id)
		}
	}
	for _, tr := range rollup {
		sort.Strings(tr.Children)
	}

	ownMetrics := make(map[string]*billingMetrics)
	s.mu.RLock()
	store := s.stewardStore
	s.mu.RUnlock()
	if store != nil {
		records, listErr := store.ListStewards(ctx)
		if listErr != nil {
			return nil, listErr
		}
		for _, rec := range records {
			tr, ok := rollup[rec.TenantID]
			if !ok || !stewardCountsTowardBilling(rec.Status) {
				continue
			}
			tr.OwnEndpoints++
			m := ownMetrics[rec.TenantID]
			if m == nil {
				m = &billingMetrics{}
				ownMetrics[rec.TenantID] = m
			}
			m.addSteward(rec)
		}
	}

	if s.secretStore != nil {
		metas, listErr := s.listAccountSecrets(ctx)
		if listErr != nil {
			return nil, listErr
		}
		for _, meta := range metas {
			// Root-scope and tenantless accounts belong to no MSP.
			if meta.Metadata["root_scope"] == "true" || meta.Metadata["disabled"] == "true" ||
				meta.TenantID == "" || meta.TenantID == audit.SystemTenantID {
				continue
			}
			if tr, ok := rollup[meta.TenantID]; ok {
				tr.OwnTechs++
			}
		}
	}

	for id, tr := range rollup {
		if tr.OwnTechs == 0 && tr.OwnEndpoints == 0 {
			continue
		}
		// Walk to the root; the visited set guards against a ParentID cycle.
		visited := make(map[string]struct{})
		for cur := id; cur != ""; cur = rollup[cur].ParentID {
			if _, seen := visited[cur]; seen {
				break
			}
			visited[cur] = struct{}{}
			anc, ok := rollup[cur]
			if !ok {
				break
			}
			anc.SubtreeTechs += tr.OwnTechs
			anc.SubtreeEndpoints += tr.OwnEndpoints
			if m := ownMetrics[id]; m != nil {
				anc.Metrics.add(m)
			}
		}
	}
	return rollup, nil
}

// billingCounts is a tech and endpoint pair.
type billingCounts struct {
	Techs     int
	Endpoints int
}

// billingClient is one direct child of the subtree root, sized over its whole subtree.
type billingClient struct {
	ID           string
	Name         string
	BillingLabel string
	Techs        int
	Endpoints    int
}

// billingAggregate is the projection of the roll-up for one tenant subtree.
// TechCount == MSPOwn.Techs + sum(Clients[].Techs), and the same for endpoints.
type billingAggregate struct {
	TechCount     int
	EndpointCount int
	Metrics       billingMetrics
	ClientCount   int
	MSPOwn        billingCounts
	Clients       []billingClient
}

// aggregateBilling projects the whole-tree roll-up onto the subtree at subtreeRoot.
// Descendants deeper than one level are rolled into their direct-child client row.
func (s *Server) aggregateBilling(ctx context.Context, subtreeRoot string) (*billingAggregate, error) {
	rollup, err := s.rollupTenantCounts(ctx)
	if err != nil {
		return nil, err
	}
	root, ok := rollup[subtreeRoot]
	if !ok {
		return nil, errBillingTenantNotFound
	}
	agg := &billingAggregate{
		TechCount:     root.SubtreeTechs,
		EndpointCount: root.SubtreeEndpoints,
		Metrics:       root.Metrics,
		ClientCount:   len(root.Children),
		MSPOwn:        billingCounts{Techs: root.OwnTechs, Endpoints: root.OwnEndpoints},
		Clients:       make([]billingClient, 0, len(root.Children)),
	}
	for _, id := range root.Children {
		c := rollup[id]
		agg.Clients = append(agg.Clients, billingClient{
			ID: id, Name: c.Name, BillingLabel: c.BillingLabel,
			Techs: c.SubtreeTechs, Endpoints: c.SubtreeEndpoints,
		})
	}
	return agg, nil
}
