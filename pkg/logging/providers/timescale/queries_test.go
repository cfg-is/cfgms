// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package timescale

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// newTestQueryProvider returns a TimescaleProvider with just enough config to
// exercise buildTimeRangeQuery's pure string construction. No database
// connection is made — these tests never touch p.db.
func newTestQueryProvider() *TimescaleProvider {
	return &TimescaleProvider{
		config: &TimescaleConfig{
			SchemaName: "public",
			TableName:  "log_entries",
		},
	}
}

// TestBuildTimeRangeQuery_RejectsUnknownOrderByColumn is a REQUIRED test
// (Issue #4348): buildTimeRangeQuery must never interpolate an arbitrary
// caller-supplied OrderBy value directly into the ORDER BY clause — that is
// only safe today because every current caller happens to leave OrderBy
// unset or "timestamp". A value outside the fixed column allow-list must be
// ignored (falling back to the "timestamp" default), not appended to the SQL
// text verbatim.
func TestBuildTimeRangeQuery_RejectsUnknownOrderByColumn(t *testing.T) {
	p := newTestQueryProvider()

	injected := "timestamp; DROP TABLE log_entries; --"
	sql, _ := p.buildTimeRangeQuery(interfaces.TimeRangeQuery{OrderBy: injected})

	assert.NotContains(t, sql, injected, "an unrecognized OrderBy value must never reach the SQL text")
	assert.Contains(t, sql, "ORDER BY timestamp ASC", "an unrecognized OrderBy value must fall back to the timestamp default")
}

// TestBuildTimeRangeQuery_AcceptsAllowlistedOrderByColumn verifies a column
// name that IS in the allow-list is still honored — the fix must not disable
// custom sorting entirely, only close the injection vector.
func TestBuildTimeRangeQuery_AcceptsAllowlistedOrderByColumn(t *testing.T) {
	p := newTestQueryProvider()

	sql, _ := p.buildTimeRangeQuery(interfaces.TimeRangeQuery{OrderBy: "level", SortDesc: true})

	assert.Contains(t, sql, "ORDER BY level DESC")
}

// TestBuildTimeRangeQuery_DefaultOrderByIsTimestamp verifies the unset-OrderBy
// default is unchanged by the allow-list check.
func TestBuildTimeRangeQuery_DefaultOrderByIsTimestamp(t *testing.T) {
	p := newTestQueryProvider()

	sql, _ := p.buildTimeRangeQuery(interfaces.TimeRangeQuery{})

	assert.Contains(t, sql, "ORDER BY timestamp ASC")
}

// TestBuildTimeRangeQuery_FiltersAreParameterized verifies query.Filters
// values never appear as literal text in the generated SQL — every filter
// value must be passed as a bound placeholder argument instead.
func TestBuildTimeRangeQuery_FiltersAreParameterized(t *testing.T) {
	p := newTestQueryProvider()

	const canary = "tenant-should-never-appear-literally"
	sql, args := p.buildTimeRangeQuery(interfaces.TimeRangeQuery{
		Filters: map[string]interface{}{"tenant_id": canary},
	})

	assert.False(t, strings.Contains(sql, canary), "filter values must never be interpolated into the SQL text")
	assert.Contains(t, args, canary, "filter values must be passed as bound arguments")
}
