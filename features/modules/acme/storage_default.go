//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package acme

import "path/filepath"

// newCertBackend creates the appropriate certificate backend for the given path.
// On non-Windows platforms, only filesystem backends are supported.
// Paths starting with "cert:\" are rejected with ErrCertStoreUnsupported.
func newCertBackend(certStorePath string) (CertBackend, error) {
	if isCertStorePath(certStorePath) {
		return nil, ErrCertStoreUnsupported
	}
	return newFsCertBackend(filepath.Join(certStorePath, "acme", "certificates"))
}
