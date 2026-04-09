// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"fmt"

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
