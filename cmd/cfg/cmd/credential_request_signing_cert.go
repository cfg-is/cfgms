// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var (
	credentialRequestSigningCertAPIURL      string
	credentialRequestSigningCertTLSInsecure bool
	credentialRequestSigningCertServerName  string
	credentialRequestSigningCertKeyOut      string
	credentialRequestSigningCertCertOut     string
)

// credentialCmd is the parent command: cfg credential ...
var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage CFGMS operator credentials",
}

// credentialRequestSigningCertCmd implements cfg credential request-signing-cert.
var credentialRequestSigningCertCmd = &cobra.Command{
	Use:   "request-signing-cert",
	Short: "Generate a payload-signing keypair and request a signed certificate",
	Long: `Generates an ECDSA P-256 keypair locally and submits only the public key to
the controller's CSR-based issuance endpoint, which signs it into a
payload-signing certificate. The private key never leaves this machine.

This is a new, separate credential from the mTLS admin bundle used to
authenticate cfg itself (see 'cfg connect'): it exists specifically to sign
operatorpayload.Envelopes (a future 'cfg payload sign' command), never for
mTLS session authentication.

Requires an existing admin mTLS bundle or active session (see 'cfg connect')
that holds the signing-credential:request permission, plus a fresh WebAuthn
presence assertion — the CLI opens a browser automatically if one is needed.

Examples:
  cfg credential request-signing-cert
  cfg credential request-signing-cert --key-out ~/.config/cfgms/signing-key.pem --cert-out ~/.config/cfgms/signing-cert.pem`,
	RunE: runCredentialRequestSigningCert,
}

func init() {
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	credentialRequestSigningCertCmd.Flags().BoolVar(&credentialRequestSigningCertTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertServerName, "server-name", "", "Override TLS server name for certificate verification")
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertKeyOut, "key-out", "", "path to write the generated private key PEM (default: <user config dir>/cfgms/signing-key.pem)")
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertCertOut, "cert-out", "", "path to write the issued certificate PEM (default: <user config dir>/cfgms/signing-cert.pem)")

	credentialCmd.AddCommand(credentialRequestSigningCertCmd)
	rootCmd.AddCommand(credentialCmd)
}

// signingCredentialRequestBody mirrors api.SigningCredentialRequest on the controller.
// It has exactly one field, the caller-generated public key — there is no field
// capable of carrying a private key across the wire.
type signingCredentialRequestBody struct {
	PublicKeyPEM string `json:"public_key_pem"`
}

// signingCredentialResponseBody mirrors api.SigningCredentialResponse on the controller.
type signingCredentialResponseBody struct {
	CertificatePEM   string    `json:"certificate_pem"`
	CACertificatePEM string    `json:"ca_certificate_pem"`
	SerialNumber     string    `json:"serial_number"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// getCredentialAPIClient resolves an authenticated client for signing-credential
// commands. requireSessionOrBundleClient wires OnStepUpRequired to
// defaultStepUpHandler, so the AssuranceStrong + user-presence gate on
// signing-credential:request is satisfied transparently (browser relay ceremony)
// rather than needing bespoke step-up handling here.
func getCredentialAPIClient() (*APIClient, error) {
	apiURL := credentialRequestSigningCertAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}
	tlsInsecure := credentialRequestSigningCertTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	return requireSessionOrBundleClient(apiURL, tlsInsecure, credentialRequestSigningCertServerName)
}

func runCredentialRequestSigningCert(cmd *cobra.Command, _ []string) error {
	keyOutPath, certOutPath, err := resolveSigningCredentialOutputPaths()
	if err != nil {
		return err
	}

	// The keypair is generated locally; only the public half is ever marshaled
	// for the request below.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate signing keypair: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	client, err := getCredentialAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	reqBody, err := json.Marshal(signingCredentialRequestBody{PublicKeyPEM: string(pubPEM)})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/signing-credential/request", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("signing-credential request failed (%s): %s", resp.Status, string(body))
	}

	var envelope struct {
		Data signingCredentialResponseBody `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Write the private key before the certificate: the key was generated locally
	// and never transmitted, so if anything below fails the operator must still be
	// left with it on disk — the controller has no copy to reissue from.
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := writeCredentialFile(keyOutPath, keyPEM); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	if err := writeCredentialFile(certOutPath, []byte(envelope.Data.CertificatePEM)); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Signing credential issued (serial: %s, expires: %s)\n",
		envelope.Data.SerialNumber, envelope.Data.ExpiresAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Private key: %s\n", keyOutPath)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate: %s\n", certOutPath)
	return nil
}

// writeCredentialFile creates path's parent directory (mode 0700) and writes data
// to it at mode 0600.
func writeCredentialFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { // #nosec G301 -- 0700: traversable but private to the user
		return fmt.Errorf("create directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil { // #nosec G306 -- 0600: private to the user
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// resolveSigningCredentialOutputPaths returns the key and cert output paths,
// applying --key-out/--cert-out or defaulting under <user config dir>/cfgms/.
func resolveSigningCredentialOutputPaths() (keyPath, certPath string, err error) {
	keyPath = credentialRequestSigningCertKeyOut
	certPath = credentialRequestSigningCertCertOut
	if keyPath != "" && certPath != "" {
		return keyPath, certPath, nil
	}
	configDir, dirErr := userConfigDirFn()
	if dirErr != nil {
		return "", "", fmt.Errorf("cannot determine user config directory: %w", dirErr)
	}
	if keyPath == "" {
		keyPath = filepath.Join(configDir, "cfgms", "signing-key.pem")
	}
	if certPath == "" {
		certPath = filepath.Join(configDir, "cfgms", "signing-cert.pem")
	}
	return keyPath, certPath, nil
}
