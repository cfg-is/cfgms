// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import "testing"

// TestSessionPermissionsAreKnown verifies that session:create, session:list, and
// session:revoke are present in knownPermissions so tenant-scoped administrators can
// be granted CLI access (Issue #3584). Their absence before #3576 landed was a
// deliberate policy guard, not a bug — see the comments in permissions.go.
func TestSessionPermissionsAreKnown(t *testing.T) {
	for _, perm := range []string{"session:create", "session:list", "session:revoke"} {
		if !isKnownPermission(perm) {
			t.Errorf("isKnownPermission(%q) = false, want true (Issue #3584: session:* must be grantable)", perm)
		}
	}
}

// TestWildcardNotKnownPermission verifies that "*" is never a valid permission ID.
// C1 in permissions.go: wildcard grants are not supported; each permission must be named.
func TestWildcardNotKnownPermission(t *testing.T) {
	if isKnownPermission("*") {
		t.Error(`isKnownPermission("*") = true, want false (C1: wildcard must be rejected)`)
	}
}

// TestUnknownPermissionRejected verifies that arbitrary strings are not known permissions.
func TestUnknownPermissionRejected(t *testing.T) {
	if isKnownPermission("not:a:real:permission") {
		t.Error(`isKnownPermission("not:a:real:permission") = true, want false`)
	}
}
