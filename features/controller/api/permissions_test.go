// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"testing"

	"github.com/cfgis/cfgms/pkg/session"
)

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

// TestSoftwareAuthenticatorFlagPermission is a REQUIRED test (Issue #6141): the flag route's
// permission is grantable, and sits on the strong surface with a presence tap and no
// machine access.
func TestSoftwareAuthenticatorFlagPermission(t *testing.T) {
	const perm = "account:set-software-authenticator"
	if !isKnownPermission(perm) {
		t.Errorf("isKnownPermission(%q) = false, want true", perm)
	}
	req, ok := permissionAssurance[perm]
	if !ok {
		t.Fatalf("permissionAssurance has no entry for %q", perm)
	}
	if req.Min != session.AssuranceStrong {
		t.Errorf("%q Min = %v, want AssuranceStrong", perm, req.Min)
	}
	if !req.RequireUserPresence {
		t.Errorf("%q must require a presence tap", perm)
	}
	if req.AllowMachine {
		t.Errorf("%q must not be open to a machine principal", perm)
	}
}
