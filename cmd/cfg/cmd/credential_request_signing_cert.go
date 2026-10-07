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
	credentialRequestSigningCertExportPlain bool
	credentialRequestSigningCertCredential  string
)

// signingCredentialName is the CredentialStore entry the signing private key is
// persisted under, as <user config dir>/cfgms/credentials/<name>.enc, encrypted
// with the machine-bound key. It shares the namespace used by connection
// credentials (cfg connect), so --credential-name exists for the rare case where
// an operator has a connection registered under this name.
const signingCredentialName = "signing-key"

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

The private key is persisted encrypted at rest through the same machine-bound
credential store 'cfg connect' uses for the admin bundle — no cleartext key is
written to disk. The issued certificate, which carries no secret, is written to
--cert-out.

This is a new, separate credential from the mTLS admin bundle used to
authenticate cfg itself (see 'cfg connect'): it exists specifically to sign
operatorpayload.Envelopes (a future 'cfg payload sign' command), never for
mTLS session authentication.

Requires an existing admin mTLS bundle or active session (see 'cfg connect')
that holds the signing-credential:request permission, plus a fresh WebAuthn
presence assertion — the CLI opens a browser automatically if one is needed.

Examples:
  cfg credential request-signing-cert
  cfg credential request-signing-cert --cert-out ~/.config/cfgms/signing-cert.pem
  cfg credential request-signing-cert --export-plaintext-key --key-out ./dev-signing-key.pem`,
	RunE: runCredentialRequestSigningCert,
}

func init() {
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	credentialRequestSigningCertCmd.Flags().BoolVar(&credentialRequestSigningCertTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertServerName, "server-name", "", "Override TLS server name for certificate verification")
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertKeyOut, "key-out", "", "path for the cleartext private key PEM export; requires --export-plaintext-key (default: <user config dir>/cfgms/signing-key.pem)")
	credentialRequestSigningCertCmd.Flags().BoolVar(&credentialRequestSigningCertExportPlain, "export-plaintext-key", false, "also export the private key as a cleartext PEM file (development only; the key is always stored encrypted regardless)")
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertCertOut, "cert-out", "", "path to write the issued certificate PEM (default: <user config dir>/cfgms/signing-cert.pem)")
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertCredential, "credential-name", signingCredentialName, "name the encrypted signing key is stored under in the credential store")

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
	credName := credentialRequestSigningCertCredential
	if credName == "" {
		credName = signingCredentialName
	}

	// Open the encrypted credential store before generating or requesting
	// anything: the private key has no other durable home, so a store that
	// cannot be initialised must fail the command before it consumes a
	// WebAuthn presence ceremony and a controller-issued serial.
	credStore, err := newCredentialStore()
	if err != nil {
		return fmt.Errorf("failed to open credential store: %w", err)
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

	// Persist the private key before the certificate: the key was generated
	// locally and never transmitted, so if anything below fails the operator must
	// still hold it — the controller has no copy to reissue from. It is stored
	// encrypted at rest (machine-bound), never as a cleartext file.
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := credStore.Store(context.Background(), credName, keyPEM); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}
	if err := writeCredentialFile(certOutPath, []byte(envelope.Data.CertificatePEM)); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Signing credential issued (serial: %s, expires: %s)\n",
		envelope.Data.SerialNumber, envelope.Data.ExpiresAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Private key: stored encrypted as credential %q\n", credName)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate: %s\n", certOutPath)

	// Cleartext export is opt-in only, and happens last so a failed export never
	// costs the operator the encrypted copy.
	if keyOutPath != "" {
		if err := writeCredentialFile(keyOutPath, keyPEM); err != nil {
			return fmt.Errorf("failed to export cleartext private key: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"WARNING: cleartext private key exported to %s — it is unencrypted at rest; delete it once consumed\n", keyOutPath)
	}
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

// resolveSigningCredentialOutputPaths returns the cleartext key export path and
// the certificate output path.
//
// keyPath is empty unless --export-plaintext-key was passed: the private key is
// stored encrypted by default, and a cleartext copy is written only on explicit
// opt-in. Passing --key-out without that opt-in is an error rather than a silent
// downgrade to a cleartext key on disk.
func resolveSigningCredentialOutputPaths() (keyPath, certPath string, err error) {
	if credentialRequestSigningCertKeyOut != "" && !credentialRequestSigningCertExportPlain {
		return "", "", fmt.Errorf(
			"--key-out writes an unencrypted private key: pass --export-plaintext-key to confirm, " +
				"or omit --key-out to keep the key encrypted in the credential store")
	}
	if credentialRequestSigningCertExportPlain {
		keyPath = credentialRequestSigningCertKeyOut
	}
	certPath = credentialRequestSigningCertCertOut
	needsDefault := certPath == "" || (credentialRequestSigningCertExportPlain && keyPath == "")
	if !needsDefault {
		return keyPath, certPath, nil
	}
	configDir, dirErr := userConfigDirFn()
	if dirErr != nil {
		return "", "", fmt.Errorf("cannot determine user config directory: %w", dirErr)
	}
	if credentialRequestSigningCertExportPlain && keyPath == "" {
		keyPath = filepath.Join(configDir, "cfgms", "signing-key.pem")
	}
	if certPath == "" {
		certPath = filepath.Join(configDir, "cfgms", "signing-cert.pem")
	}
	return keyPath, certPath, nil
}
