// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package tpmkey

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// OpenDevice opens the host TPM through the TPM Base Services (TBS).
func OpenDevice() (transport.TPMCloser, error) { return windowstpm.Open() }
