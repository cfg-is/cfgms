// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var (
	scriptSignKey       string
	scriptSignAlgorithm string
)

// scriptSignCmd represents the `cfg script sign` subcommand.
var scriptSignCmd = &cobra.Command{
	Use:   "sign <file>",
	Short: "Sign a script with a private key",
	Long: `Sign a script file with a PEM-encoded private key and write the
detached signature to <file>.sig.

The .sig file contains raw DER-encoded cryptographic signature bytes.
Use the same --algorithm when verifying with 'cfg script verify'.

On Windows, PowerShell files (.ps1, .psm1, .psd1) are signed using
Set-AuthenticodeSignature with the certificate store instead of a
detached .sig file.

Examples:
  # Sign with an RSA private key (default algorithm: rsa-sha256)
  cfg script sign deploy.sh --key signing.pem

  # Sign with a specific algorithm
  cfg script sign deploy.sh --key signing.pem --algorithm ecdsa-sha256

  # Sign a shell script; creates deploy.sh.sig
  cfg script sign deploy.sh --key /etc/cfgms/keys/signing.pem`,
	Args: cobra.ExactArgs(1),
	RunE: runScriptSign,
}

func init() {
	scriptSignCmd.Flags().StringVar(&scriptSignKey, "key", "", "path to PEM-encoded private key file (required for non-Authenticode signing)")
	scriptSignCmd.Flags().StringVar(&scriptSignAlgorithm, "algorithm", "rsa-sha256",
		"signing algorithm (rsa-sha256, rsa-sha384, rsa-sha512, ecdsa-sha256, ecdsa-sha384, ecdsa-sha512)")
}

func runScriptSign(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// On Windows, PowerShell files use Authenticode (no --key required).
	// On all other platforms or non-PowerShell files, --key is required.
	if windowsAuthenticodeSigner == nil || !isPowerShellExt(filePath) {
		if scriptSignKey == "" {
			return fmt.Errorf("--key is required\n\nProvide the path to a PEM-encoded PKCS#8 private key.\n\nExample:\n  cfg script sign %s --key signing.pem", filePath)
		}
	}

	if err := signScript(filePath, scriptSignKey, scriptSignAlgorithm); err != nil {
		return err
	}

	if windowsAuthenticodeSigner != nil && isPowerShellExt(filePath) {
		fmt.Printf("signed %s using Authenticode\n", filePath)
	} else {
		fmt.Printf("signed %s → %s.sig\n", filePath, filePath)
	}
	return nil
}

// Authenticode operations accepted by authenticodeCommand.
const (
	authenticodeOpSign   = "sign"
	authenticodeOpVerify = "verify"

	// authenticodePathEnv carries the target file path to PowerShell as data.
	authenticodePathEnv = "CFGMS_AUTHENTICODE_PATH"
)

const authenticodeSignScript = `$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1; ` +
	`if (-not $cert) { Write-Error "no code signing certificate found in CurrentUser\My"; exit 1 }; ` +
	`$result = Set-AuthenticodeSignature -LiteralPath $env:` + authenticodePathEnv + ` -Certificate $cert; ` +
	`if ($result.Status -ne 'Valid') { Write-Error "Authenticode signing failed: $($result.StatusMessage)"; exit 1 }`

const authenticodeVerifyScript = `$result = Get-AuthenticodeSignature -LiteralPath $env:` + authenticodePathEnv + `; ` +
	`if ($result.Status -eq 'Valid') { exit 0 } ` +
	`elseif ($result.Status -eq 'NotSigned') { Write-Error "no signature found"; exit 1 } ` +
	`else { Write-Error "signature invalid — $($result.StatusMessage)"; exit 1 }`

// authenticodeCommand builds the PowerShell command for an Authenticode
// operation (authenticodeOpSign or authenticodeOpVerify). The script text is
// fixed and contains no caller data; filePath is passed in the child's
// environment so it can never be parsed as PowerShell code. It is not
// build-tagged so it can be tested on every platform.
func authenticodeCommand(op, filePath string) *exec.Cmd {
	script := authenticodeVerifyScript
	if op == authenticodeOpSign {
		script = authenticodeSignScript
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script) // #nosec G204 — fixed script; filePath passed via environment, not command text
	cmd.Env = append(os.Environ(), authenticodePathEnv+"="+filePath)
	return cmd
}
