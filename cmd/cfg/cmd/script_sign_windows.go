// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
//go:build windows

package cmd

import (
	"bytes"
	"fmt"
	"os/exec"
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
	script := fmt.Sprintf(
		`$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1; `+
			`if (-not $cert) { Write-Error "no code signing certificate found in CurrentUser\My"; exit 1 }; `+
			`$result = Set-AuthenticodeSignature -FilePath '%s' -Certificate $cert; `+
			`if ($result.Status -ne 'Valid') { Write-Error "Authenticode signing failed: $($result.StatusMessage)"; exit 1 }`,
		escapePSPath(filePath),
	)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script) // #nosec G204 — filePath is escaped via escapePSPath
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("Authenticode signing failed: %s", msg)
	}
	return nil
}

// authenticodeVerify invokes Get-AuthenticodeSignature via PowerShell to verify
// the Authenticode signature embedded in a PowerShell script file.
func authenticodeVerify(filePath string) error {
	script := fmt.Sprintf(
		`$result = Get-AuthenticodeSignature -FilePath '%s'; `+
			`if ($result.Status -eq 'Valid') { exit 0 } `+
			`elseif ($result.Status -eq 'NotSigned') { Write-Error "no signature found"; exit 1 } `+
			`else { Write-Error "signature invalid — $($result.StatusMessage)"; exit 1 }`,
		escapePSPath(filePath),
	)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script) // #nosec G204 — filePath is escaped via escapePSPath
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
