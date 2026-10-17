// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package security

import "errors"

// ErrUntrustedDirOwner is returned by EnsureAdminOnlyDir when the directory
// already exists and is owned by a principal other than SYSTEM or
// BUILTIN\Administrators. The helper never takes ownership of such a directory:
// a non-admin principal that created it keeps full control, so nothing placed
// in it can be trusted.
var ErrUntrustedDirOwner = errors.New("directory is owned by a principal other than SYSTEM or BUILTIN\\Administrators")

// ErrUntrustedDirEntry is returned by EnsureAdminOnlyDir when an entry below
// the directory is a link or reparse point, or still grants access to a
// principal other than SYSTEM or BUILTIN\Administrators after the lockdown.
// Such an entry could let a local user regain access to, or redirect, material
// the steward trusts.
var ErrUntrustedDirEntry = errors.New("directory contains an entry that is a reparse point or grants access to a non-administrator principal")
