// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !linux && !windows

package tpmkey

import "github.com/google/go-tpm/tpm2/transport"

// OpenDevice reports ErrUnsupported: only Linux and Windows have a TPM transport.
func OpenDevice() (transport.TPMCloser, error) { return nil, ErrUnsupported }
