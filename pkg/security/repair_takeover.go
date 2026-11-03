// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package security

import "errors"

// ErrTakeoverIncomplete is returned by TakeOverForRepair when at least one
// entry was refused or could not be secured, so the tree must not be trusted
// even though the rest of it was taken over. TakeoverReport.Refused names the
// entries.
var ErrTakeoverIncomplete = errors.New("repair takeover left entries unsecured")

// TakeoverReport lists what TakeOverForRepair did, by absolute path.
type TakeoverReport struct {
	// Secured entries had their owner and rights reset to the owner-only
	// state (Administrators on Windows, root elsewhere).
	Secured []string
	// Quarantined entries were links found under a root (symlinks, junctions,
	// other reparse points, and on non-Windows hard links). The link itself
	// was removed; its target was not opened, followed or modified.
	Quarantined []string
	// Refused entries were left untouched: a regular file with more than one
	// hard link on Windows (it shares the target's security descriptor), a
	// root that is itself a link, a special file, or an entry whose owner or
	// rights could not be reset. Each reason is in the entry text.
	Refused []string
}
