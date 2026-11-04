// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package registration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeProvenance(t *testing.T) {
	got := NormalizeProvenance(map[string]string{
		" machine_id ": " m-1\n", "empty": "  ", "": "x", "os_version": "6.1", "nic_macs": "aa:bb",
	})
	assert.Equal(t, map[string]string{"machine_id": "m-1", "nic_macs": "aa:bb"}, got)
	assert.Nil(t, NormalizeProvenance(map[string]string{"os_version": "6.1", "k": " "}))
	assert.Nil(t, NormalizeProvenance(nil))
}

func TestNormalizeStoredProvenance(t *testing.T) {
	assert.JSONEq(t, `{"a":"1"}`, NormalizeStoredProvenance(`{"a":" 1 ","uptime_seconds":"5"}`))
	assert.Equal(t, "not json", NormalizeStoredProvenance("not json"))
	assert.Equal(t, "", NormalizeStoredProvenance(""))
	assert.Equal(t, `{"os_version":"1"}`, NormalizeStoredProvenance(`{"os_version":"1"}`))
}

func TestProvenanceKeyDiff(t *testing.T) {
	matched, divergent := ProvenanceKeyDiff(`{"b":"2","a":"1","c":"3","os_version":"x"}`,
		map[string]string{"a": "1", "b": "other"})
	assert.Equal(t, []string{"a"}, matched)
	assert.Equal(t, []string{"b", "c"}, divergent)

	m, d := ProvenanceKeyDiff("not json", map[string]string{"a": "1"})
	require.Nil(t, m)
	require.Nil(t, d)
}

func TestNormalizeProvenance_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]string
		want map[string]string
	}{
		{"empty map", map[string]string{}, nil},
		{"whitespace-only key dropped", map[string]string{" \t": "v", "a": "1"}, map[string]string{"a": "1"}},
		{"whitespace-only value dropped", map[string]string{"a": "\n\t ", "b": "2"}, map[string]string{"b": "2"}},
		{"every DNA key dropped", func() map[string]string {
			m := map[string]string{"keep": "x"}
			for k := range DNAFieldKeys {
				m[k] = "v"
			}
			return m
		}(), map[string]string{"keep": "x"}},
		{"padded DNA key dropped after trim", map[string]string{" os_version ": "6.1", "a": "1"}, map[string]string{"a": "1"}},
		{"interior whitespace preserved", map[string]string{"a": " x y "}, map[string]string{"a": "x y"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NormalizeProvenance(tc.in))
		})
	}
}

func TestNormalizeProvenance_DoesNotMutateInput(t *testing.T) {
	in := map[string]string{" a ": " 1 ", "os_version": "6.1"}
	require.Equal(t, map[string]string{"a": "1"}, NormalizeProvenance(in))
	assert.Equal(t, map[string]string{" a ": " 1 ", "os_version": "6.1"}, in)
}

func TestProvenanceKeyDiff_EdgeCases(t *testing.T) {
	t.Run("all matched", func(t *testing.T) {
		m, d := ProvenanceKeyDiff(`{"z":"1","a":"2"}`, map[string]string{"a": "2", "z": "1", "extra": "x"})
		assert.Equal(t, []string{"a", "z"}, m, "extra incoming keys are ignored")
		assert.Nil(t, d)
	})
	t.Run("missing incoming", func(t *testing.T) {
		m, d := ProvenanceKeyDiff(`{"b":"1","a":"2"}`, nil)
		assert.Nil(t, m)
		assert.Equal(t, []string{"a", "b"}, d)
	})
	t.Run("DNA-only baseline", func(t *testing.T) {
		m, d := ProvenanceKeyDiff(`{"os_version":"1","uptime_seconds":"2"}`, map[string]string{"os_version": "9"})
		assert.Nil(t, m)
		assert.Nil(t, d)
	})
	t.Run("empty stored", func(t *testing.T) {
		m, d := ProvenanceKeyDiff("", map[string]string{"a": "1"})
		assert.Nil(t, m)
		assert.Nil(t, d)
	})
	t.Run("agrees with FuzzyMatch", func(t *testing.T) {
		stored := `{"a":"1","b":"2","c":"3","kernel_version":"k"}`
		in := map[string]string{"a": "1", "c": "x", "kernel_version": "other"}
		m, d := ProvenanceKeyDiff(stored, in)
		r := ProvenanceMatcher{}.FuzzyMatch(stored, in)
		assert.Equal(t, r.MatchedFields, len(m))
		assert.Equal(t, r.TotalFields, len(m)+len(d))
	})
}
