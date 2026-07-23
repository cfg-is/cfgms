// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package database contains unit tests for the PostgreSQL entity graph
// provider helpers. The full contract suite (interfaces.RunEntityGraphContractTests)
// runs against a live PostgreSQL instance in
// pkg/entitygraph/interfaces/providers_test.go, which uses the
// */providers_test.go architecture exception to import the provider directly.
// Tests here cover the pure-function helpers that do not require a connection.
package database

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

func TestResolveSourceClass_Database(t *testing.T) {
	tests := []struct {
		source string
		want   types.SourceClass
	}{
		{"enforcing-module:hyperv", types.SourceClassEnforcingModule},
		{"managing-integration:m365", types.SourceClassManagingIntegration},
		{"observer:network-scan", types.SourceClassObserver},
		{"operator-assertion:manual", types.SourceClassOperatorAssertion},
		{"correlator-inference:ml", types.SourceClassCorrelatorInference},
		{"unknown-source:anything", types.SourceClassObserver},
		{"nocoion", types.SourceClassObserver},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveSourceClass(tc.source))
		})
	}
}

func TestTenantVisible_Database(t *testing.T) {
	tests := []struct {
		owning string
		filter string
		want   bool
	}{
		{"root/msp-a", "", true},                    // empty filter sees everything
		{"root/msp-a", "root/msp-a", true},          // exact match
		{"root/msp-a/client-1", "root/msp-a", true}, // subtree match
		{"root/msp-ab", "root/msp-a", false},        // prefix but not a child path
		{"root/msp-b", "root/msp-a", false},         // sibling
		{"root/msp-a", "root/msp-b", false},         // wrong root
	}
	for _, tc := range tests {
		t.Run(tc.owning+"|"+tc.filter, func(t *testing.T) {
			assert.Equal(t, tc.want, tenantVisible(tc.owning, tc.filter))
		})
	}
}

func TestSourceClassRank_Ordering(t *testing.T) {
	// enforcing-module must rank strictly lower (higher precedence) than all others.
	enfRank := sourceClassRank(types.SourceClassEnforcingModule)
	for _, sc := range []types.SourceClass{
		types.SourceClassManagingIntegration,
		types.SourceClassObserver,
		types.SourceClassOperatorAssertion,
		types.SourceClassCorrelatorInference,
	} {
		assert.Less(t, enfRank, sourceClassRank(sc), "enforcing-module must outrank %s", sc)
	}
}

func TestMergeAttributes_Database(t *testing.T) {
	low := sourceEntry{
		source:      "observer:scan",
		sourceClass: string(types.SourceClassObserver),
		observedAt:  time.Now(),
		payload:     map[string]interface{}{"color": "blue", "only_low": "x"},
	}
	high := sourceEntry{
		source:      "enforcing-module:paint",
		sourceClass: string(types.SourceClassEnforcingModule),
		observedAt:  time.Now(),
		payload:     map[string]interface{}{"color": "red"},
	}
	merged := mergeAttributes([]sourceEntry{low, high})
	require.Equal(t, "red", merged["color"], "high-precedence source must win")
	assert.Equal(t, "x", merged["only_low"], "low-precedence-only keys survive in merged view")
}

func TestBetterSource_TieBreak(t *testing.T) {
	ts := time.Now()
	a := sourceEntry{sourceClass: string(types.SourceClassObserver), observedAt: ts, payloadHash: "aaa"}
	b := sourceEntry{sourceClass: string(types.SourceClassObserver), observedAt: ts, payloadHash: "bbb"}
	// Same rank, same time: hash tie-break (lower hash wins).
	assert.True(t, betterSource(a, b), "lower payload hash must win tie-break")
	assert.False(t, betterSource(b, a))
}

func TestSubjectKind_Database(t *testing.T) {
	assert.Equal(t, "entity", subjectKind("host:abc123"))
	assert.Equal(t, "entity", subjectKind("m365:tenant-x/user1"))
	assert.Equal(t, "edge", subjectKind("contains|host:a|host:b"))
	assert.Equal(t, "edge", subjectKind("arbitrary-edge-string"))
}

func TestParseEdgeSubject_Database(t *testing.T) {
	edgeType, from, to, err := parseEdgeSubject("contains|host:a|host:b")
	require.NoError(t, err)
	assert.Equal(t, "contains", edgeType)
	assert.Equal(t, "host:a", from)
	assert.Equal(t, "host:b", to)

	// to_subject may contain slashes (local_id component of EID).
	edgeType, from, to, err = parseEdgeSubject("runs-on|cluster:cl1|host:cl1/vm1")
	require.NoError(t, err)
	assert.Equal(t, "runs-on", edgeType)
	assert.Equal(t, "cluster:cl1", from)
	assert.Equal(t, "host:cl1/vm1", to)

	// Missing components must error.
	_, _, _, err = parseEdgeSubject("only-one-part")
	require.Error(t, err)

	_, _, _, err = parseEdgeSubject("two|parts")
	require.Error(t, err)
}
