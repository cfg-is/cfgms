// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/scripts/complexity/analyzer"
)

func fn(id string, cc int) analyzer.Function {
	return analyzer.Function{Identity: id, Package: "pkg/x", File: "pkg/x/a.go", CC: cc}
}

func TestCheckPartitionClean(t *testing.T) {
	a, b := fn("a", 12), fn("b", 3)
	assert.Empty(t, CheckPartition([]analyzer.Function{a, b},
		map[string][]analyzer.Function{"pkg": {a}, "cmd": {b}}))
}

func TestCheckPartitionUnclassified(t *testing.T) {
	a, b := fn("a", 1), fn("b", 1)
	got := CheckPartition([]analyzer.Function{a, b}, map[string][]analyzer.Function{"pkg": {a}})
	require.NotEmpty(t, got)
	assert.Equal(t, KindUnclassified, got[0].Kind)
	assert.Equal(t, "b", got[0].Identity)
	assert.Contains(t, got[0].String(), "b")
}

func TestCheckPartitionClaimedTwice(t *testing.T) {
	a := fn("a", 1)
	got := CheckPartition([]analyzer.Function{a}, map[string][]analyzer.Function{"pkg": {a}, "cmd": {a}})
	var found *Violation
	for i := range got {
		if got[i].Kind == KindClaimedTwice {
			found = &got[i]
		}
	}
	require.NotNil(t, found)
	assert.Contains(t, found.String(), "cmd")
	assert.Contains(t, found.String(), "pkg")
}

func TestCheckPartitionForeign(t *testing.T) {
	a, ghost := fn("a", 1), fn("ghost", 1)
	got := CheckPartition([]analyzer.Function{a}, map[string][]analyzer.Function{"pkg": {a, ghost}})
	kinds := map[string]string{}
	for _, v := range got {
		kinds[v.Kind] = v.Identity
	}
	assert.Equal(t, "ghost", kinds[KindForeign])
	assert.Contains(t, kinds, KindSumMismatch)
}

func TestCheckPartitionExcessMismatch(t *testing.T) {
	a := fn("a", 20)
	changed := fn("a", 12)
	got := CheckPartition([]analyzer.Function{a}, map[string][]analyzer.Function{"pkg": {changed}})
	require.Len(t, got, 1)
	assert.Equal(t, KindSumMismatch, got[0].Kind)
}
