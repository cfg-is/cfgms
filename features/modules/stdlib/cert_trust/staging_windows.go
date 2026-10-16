// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package cert_trust

// checkStagingBase is a no-op on Windows: directory ownership and ACLs are not
// expressed as Unix modes, so the caller is responsible for choosing a base
// directory that only privileged users can write.
func checkStagingBase(string) error { return nil }
