// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package tpmkey

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// devicePath is the kernel's resource-managed TPM device. Unlike /dev/tpm0 it
// swaps transient objects in and out, so other users of the TPM cannot exhaust
// its object slots.
const devicePath = "/dev/tpmrm0"

// OpenDevice opens the host TPM.
func OpenDevice() (transport.TPMCloser, error) { return linuxtpm.Open(devicePath) }
