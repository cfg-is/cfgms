// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !(linux && cgo)

package controller

// Issue #6227: a root agent account registers only with a TPM-attested key, and the
// software TPM that produces one for these tests needs cgo on Linux.

// newTPMKey skips the test: there is no software TPM to hold a root agent's key in.
func (e *swaEnv) newTPMKey() swaTPMKey {
	e.t.Skip("a root agent account requires a TPM-attested key; the software TPM simulator needs cgo on Linux")
	return nil
}
