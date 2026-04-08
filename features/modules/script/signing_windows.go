// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cfgis/cfgms/features/modules"
)

func init() {
	// Register the Authenticode verifier so that verifyScriptSignature in signing.go
	// can dispatch to it for PowerShell scripts on Windows builds without requiring
	// a build-tag split on the shared dispatch function.
	windowsAuthenticodeVerifier = verifyAuthenticodeSignature
}

// verifyAuthenticodeSignature verifies a PowerShell script's embedded Authenticode
// signature by writing the content to a temporary .ps1 file and invoking
// Get-AuthenticodeSignature via PowerShell.
//
// The Authenticode format embeds the signature block at the end of the script
// between the well-known markers:
//
//	# SIG # Begin signature block
//	# SIG # End signature block
//
// Trust mode enforcement uses the signer certificate's thumbprint reported by
// Get-AuthenticodeSignature.
func verifyAuthenticodeSignature(content []byte, sig *ScriptSignature, cfg ModuleSigningConfig) error {
	// Write script content to a temporary file so PowerShell can inspect it.
	tmpFile, err := os.CreateTemp("", "cfgms-verify-*.ps1")
	if err != nil {
		return fmt.Errorf("failed to create temp file for Authenticode verification: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) //nolint:errcheck // temp file cleanup; error is not actionable

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close() //nolint:errcheck // closing before returning error; original write error takes precedence
		return fmt.Errorf("failed to write temp file for Authenticode verification: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file for Authenticode verification: %w", err)
	}

	// Escape single quotes in the path to prevent injection into the PowerShell command.
	safePath := strings.ReplaceAll(tmpPath, "'", "''")

	// Get-AuthenticodeSignature returns a Signature object; extract Status and the
	// signer certificate's Thumbprint. Status is one of: Valid, NotSigned, HashMismatch,
	// NotTrusted, UnknownError, etc.
	psCmd := fmt.Sprintf(
		`$s=Get-AuthenticodeSignature -FilePath '%s'; $s.Status.ToString()+'|'+$s.SignerCertificate.Thumbprint`,
		safePath,
	)

	// #nosec G204 — the file path is sourced from os.CreateTemp (not user input) and
	// single-quote characters are escaped via strings.ReplaceAll above. The PowerShell
	// executable is a fixed string; no user-controlled data reaches the command name.
	out, err := exec.Command( //nolint:gosec // see #nosec comment above
		"powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd,
	).Output()
	if err != nil {
		return fmt.Errorf("%w: Get-AuthenticodeSignature execution failed: %v", modules.ErrInvalidInput, err)
	}

	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	status := parts[0]
	if status != "Valid" {
		return fmt.Errorf("%w: Authenticode signature status is %q (expected \"Valid\")", modules.ErrInvalidInput, status)
	}

	certThumbprint := ""
	if len(parts) == 2 {
		certThumbprint = strings.TrimSpace(parts[1])
	}

	return applyTrustMode(certThumbprint, cfg)
}
