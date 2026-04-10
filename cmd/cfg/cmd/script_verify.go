// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	scriptVerifyPubKey    string
	scriptVerifyAlgorithm string
)

// scriptVerifyCmd represents the `cfg script verify` subcommand.
var scriptVerifyCmd = &cobra.Command{
	Use:   "verify <file>",
	Short: "Verify a script's detached signature",
	Long: `Verify the detached signature for a script file.

The signature is read from <file>.sig, which must contain raw DER-encoded
cryptographic signature bytes as created by 'cfg script sign'.

Use the same --algorithm that was used during signing.

On Windows, PowerShell files (.ps1, .psm1, .psd1) are verified using
Get-AuthenticodeSignature instead of a detached .sig file.

Exit codes:
  0  signature valid
  1  signature invalid, tampered, or missing

Examples:
  # Verify with an RSA public key (default algorithm: rsa-sha256)
  cfg script verify deploy.sh --pubkey signing-pub.pem

  # Verify with a specific algorithm
  cfg script verify deploy.sh --pubkey signing-pub.pem --algorithm ecdsa-sha256

  # Verify in CI (non-zero exit on failure)
  cfg script verify deploy.sh --pubkey /etc/cfgms/keys/signing-pub.pem || exit 1`,
	Args: cobra.ExactArgs(1),
	RunE: runScriptVerify,
}

func init() {
	scriptVerifyCmd.Flags().StringVar(&scriptVerifyPubKey, "pubkey", "", "path to PEM-encoded public key file (required for non-Authenticode verification)")
	scriptVerifyCmd.Flags().StringVar(&scriptVerifyAlgorithm, "algorithm", "rsa-sha256",
		"signing algorithm (rsa-sha256, rsa-sha384, rsa-sha512, ecdsa-sha256, ecdsa-sha384, ecdsa-sha512)")
}

func runScriptVerify(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// On Windows, PowerShell files use Authenticode (no --pubkey required).
	// On all other platforms or non-PowerShell files, --pubkey is required.
	if windowsAuthenticodeScriptVerifier == nil || !isPowerShellExt(filePath) {
		if scriptVerifyPubKey == "" {
			return fmt.Errorf("--pubkey is required\n\nProvide the path to a PEM-encoded public key.\n\nExample:\n  cfg script verify %s --pubkey signing-pub.pem", filePath)
		}
	}

	err := verifyScript(filePath, scriptVerifyPubKey, scriptVerifyAlgorithm)
	if err != nil {
		if errors.Is(err, errNoSignatureFound) {
			return fmt.Errorf("no signature found")
		}
		return err
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "signature valid")
	return nil
}
