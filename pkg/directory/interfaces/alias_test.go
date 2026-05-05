// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package interfaces_test

import (
	"testing"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/directory/types"
)

// Compile-time assertions: all four aliased types are identical to their types package counterparts.
var _ types.DirectoryUser = interfaces.DirectoryUser{}
var _ types.DirectoryGroup = interfaces.DirectoryGroup{}
var _ types.GroupType = interfaces.GroupType("")
var _ types.GroupScope = interfaces.GroupScope("")

func TestTypeAliasIdentity(t *testing.T) {
	u := interfaces.DirectoryUser{Source: "test-source"}
	canonical := u
	if canonical.Source != "test-source" {
		t.Fatal("DirectoryUser alias identity failed: field value not preserved")
	}

	g := interfaces.DirectoryGroup{Source: "test-source"}
	canonicalGroup := g
	if canonicalGroup.Source != "test-source" {
		t.Fatal("DirectoryGroup alias identity failed: field value not preserved")
	}

	// Verify GroupType constants round-trip correctly across the alias boundary.
	if interfaces.GroupTypeSecurity != types.GroupTypeSecurity {
		t.Fatalf("GroupTypeSecurity mismatch: %q vs %q", interfaces.GroupTypeSecurity, types.GroupTypeSecurity)
	}
	if interfaces.GroupTypeDistribution != types.GroupTypeDistribution {
		t.Fatalf("GroupTypeDistribution mismatch: %q vs %q", interfaces.GroupTypeDistribution, types.GroupTypeDistribution)
	}
	if interfaces.GroupTypeMicrosoft365 != types.GroupTypeMicrosoft365 {
		t.Fatalf("GroupTypeMicrosoft365 mismatch: %q vs %q", interfaces.GroupTypeMicrosoft365, types.GroupTypeMicrosoft365)
	}

	// Verify GroupScope constants round-trip correctly.
	if interfaces.GroupScopeDomainLocal != types.GroupScopeDomainLocal {
		t.Fatalf("GroupScopeDomainLocal mismatch: %q vs %q", interfaces.GroupScopeDomainLocal, types.GroupScopeDomainLocal)
	}
	if interfaces.GroupScopeGlobal != types.GroupScopeGlobal {
		t.Fatalf("GroupScopeGlobal mismatch: %q vs %q", interfaces.GroupScopeGlobal, types.GroupScopeGlobal)
	}
	if interfaces.GroupScopeUniversal != types.GroupScopeUniversal {
		t.Fatalf("GroupScopeUniversal mismatch: %q vs %q", interfaces.GroupScopeUniversal, types.GroupScopeUniversal)
	}
}
