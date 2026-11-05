// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package egcommon

import (
	"encoding/json"
	"sort"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
)

// ComputeAttributeChanges returns the set of attributes that differ between two
// merged state snapshots. Either snapshot may be nil (entity did not exist at
// that time). Attributes present in only one snapshot are included (Before or
// After nil). The result is sorted by attribute name for deterministic output.
func ComputeAttributeChanges(atT1, atT2 map[string]interface{}) []interfaces.AttributeChange {
	keys := make(map[string]struct{})
	for k := range atT1 {
		keys[k] = struct{}{}
	}
	for k := range atT2 {
		keys[k] = struct{}{}
	}

	var changes []interfaces.AttributeChange
	for k := range keys {
		v1, ok1 := atT1[k]
		v2, ok2 := atT2[k]
		if !ok1 && !ok2 {
			continue
		}
		j1, _ := json.Marshal(v1)
		j2, _ := json.Marshal(v2)
		if ok1 == ok2 && string(j1) == string(j2) {
			continue
		}
		changes = append(changes, interfaces.AttributeChange{
			Attribute: k,
			Before:    v1,
			After:     v2,
		})
	}

	sort.Slice(changes, func(i, j int) bool {
		return changes[i].Attribute < changes[j].Attribute
	})
	return changes
}
