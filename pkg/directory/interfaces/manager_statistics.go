// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package interfaces

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// UnknownCount is reported in ProviderStatistics when a provider does not
// supply a total count.
const UnknownCount = -1

// ProviderStatistics describes one managed provider: live directory counts
// plus the operations the manager has run against it.
type ProviderStatistics struct {
	ProviderName   string        `json:"provider_name"`
	UserCount      int           `json:"user_count"`  // UnknownCount when the provider reports no total
	GroupCount     int           `json:"group_count"` // UnknownCount when the provider reports no total
	RequestCount   int64         `json:"request_count"`
	ErrorCount     int64         `json:"error_count"`
	AverageLatency time.Duration `json:"average_latency"`
}

// ExecuteProviderOp resolves the named provider (empty means default), connects
// it lazily, runs fn and records one request, its latency and its error. A
// resolve or connect failure counts as one request and one error. This is the
// only way operations are counted.
func (m *DirectoryProviderManager) ExecuteProviderOp(ctx context.Context, name string, fn func(DirectoryProvider) error) error {
	reg, resolved, err := m.registration(name)
	if err != nil {
		return err
	}

	start := time.Now()
	err = reg.ensureConnected(ctx, resolved)
	if err == nil {
		err = fn(reg.provider)
	}
	reg.record(time.Since(start), err)
	return err
}

func (r *providerRegistration) record(d time.Duration, err error) {
	r.requests.Add(1)
	r.totalNanos.Add(int64(d))
	if err != nil {
		r.errors.Add(1)
	}
}

// GetProviderStatistics returns live user and group counts for the named
// provider (empty means default) with the accumulated operation counters.
// The count reads are administrative and are not themselves counted.
func (m *DirectoryProviderManager) GetProviderStatistics(ctx context.Context, name string) (*ProviderStatistics, error) {
	reg, resolved, err := m.registration(name)
	if err != nil {
		return nil, err
	}
	if err := reg.ensureConnected(ctx, resolved); err != nil {
		return nil, err
	}

	filters := &SearchFilters{Limit: 1, Offset: 0}
	users, err := reg.provider.ListUsers(ctx, filters)
	if err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}
	groups, err := reg.provider.ListGroups(ctx, filters)
	if err != nil {
		return nil, fmt.Errorf("failed to count groups: %w", err)
	}

	if users == nil || groups == nil {
		return nil, fmt.Errorf("provider '%s' returned no list result", logging.SanitizeLogValue(resolved))
	}

	stats := &ProviderStatistics{
		ProviderName: resolved,
		UserCount:    countOrUnknown(users.TotalCount, len(users.Users) > 0, users.HasMore),
		GroupCount:   countOrUnknown(groups.TotalCount, len(groups.Groups) > 0, groups.HasMore),
		RequestCount: reg.requests.Load(),
		ErrorCount:   reg.errors.Load(),
	}
	if stats.RequestCount > 0 {
		stats.AverageLatency = time.Duration(reg.totalNanos.Load() / stats.RequestCount)
	}
	return stats, nil
}

// countOrUnknown treats a zero total alongside returned items or HasMore as a
// provider that did not populate TotalCount.
func countOrUnknown(total int, hasItems, hasMore bool) int {
	if total == 0 && (hasItems || hasMore) {
		return UnknownCount
	}
	return total
}
