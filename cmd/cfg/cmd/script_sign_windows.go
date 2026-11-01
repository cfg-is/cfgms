// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build windows

package cmd

import (
	"bytes"
	"fmt"
	"strings"
)

func init() {
	windowsAuthenticodeSigner = authenticodeSign
	windowsAuthenticodeScriptVerifier = authenticodeVerify
}

// authenticodeSign invokes Set-AuthenticodeSignature via PowerShell to embed
// an Authenticode signature into a PowerShell script file.
//
// The certificate is selected from the CurrentUser\My store with the
// CodeSigning EKU. If multiple code-signing certificates are present,
// PowerShell selects the most recently issued one.
func authenticodeSign(filePath string) error {
	cmd := authenticodeCommand(authenticodeOpSign, filePath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("signing failed: %s", msg)
	}
	return nil
}

// authenticodeVerify invokes Get-AuthenticodeSignature via PowerShell to verify
// the Authenticode signature embedded in a PowerShell script file.
func authenticodeVerify(filePath string) error {
	cmd := authenticodeCommand(authenticodeOpVerify, filePath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
