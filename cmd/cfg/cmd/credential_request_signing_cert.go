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

The private key is persisted encrypted at rest through the same machine-bound
credential store 'cfg connect' uses for the admin bundle — no cleartext key is
written to disk. The issued certificate, which carries no secret, is written to
--cert-out.

This is a new, separate credential from the mTLS admin bundle used to
authenticate cfg itself (see 'cfg connect'): it exists specifically to sign
operatorpayload.Envelopes (a future 'cfg payload sign' command), never for
mTLS session authentication.

The credential is stored per controller connection: by default the key is named
signing-key.<active connection> and the certificate is written to
<user config dir>/cfgms/signing-cert.<active connection>.pem, and signing commands
('cfg steward exec', 'cfg steward run-command', 'cfg steward service|process')
pick it automatically while that connection is active. Without a session the
legacy name signing-key is used. --signing-credential <name> stores (and later
selects) the credential under an explicit name instead.

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
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertAPIURL, "url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	credentialRequestSigningCertCmd.Flags().BoolVar(&credentialRequestSigningCertTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertServerName, "server-name", "", "Override TLS server name for certificate verification")
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertKeyOut, "key-out", "", "path for the cleartext private key PEM export; requires --export-plaintext-key (default: <user config dir>/cfgms/<signing credential name>.pem)")
	credentialRequestSigningCertCmd.Flags().BoolVar(&credentialRequestSigningCertExportPlain, "export-plaintext-key", false, "also export the private key as a cleartext PEM file (development only; the key is always stored encrypted regardless)")
	credentialRequestSigningCertCmd.Flags().StringVar(&credentialRequestSigningCertCertOut, "cert-out", "", "path to write the issued certificate PEM (default: <user config dir>/cfgms/signing-cert.<connection>.pem; signing-cert.pem for the legacy signing-key)")
	credentialRequestSigningCertCmd.Flags().StringVar(&signingCredentialSelector, "signing-credential", "", "name the encrypted signing key is stored under; select it with the same flag when signing (default: signing-key.<active connection>, or the legacy signing-key when no session is active)")

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

// requestSigningCertificate submits pubPEM — the only field the request carries — to
// the CSR issuance endpoint and returns the issued certificate response.
func requestSigningCertificate(client *APIClient, pubPEM []byte) (signingCredentialResponseBody, error) {
	reqBody, err := json.Marshal(signingCredentialRequestBody{PublicKeyPEM: string(pubPEM)})
	if err != nil {
		return signingCredentialResponseBody{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/signing-credential/request", bytes.NewReader(reqBody))
	if err != nil {
		return signingCredentialResponseBody{}, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return signingCredentialResponseBody{}, fmt.Errorf("signing-credential request failed (%s): %s", resp.Status, string(body))
	}

	var envelope struct {
		Data signingCredentialResponseBody `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return signingCredentialResponseBody{}, fmt.Errorf("failed to parse response: %w", err)
	}
	return envelope.Data, nil
}

func runCredentialRequestSigningCert(cmd *cobra.Command, _ []string) error {
	ref, err := resolveSigningCredentialRef()
	if err != nil {
		return err
	}
	credName := ref.KeyName
	keyOutPath, certOutPath, err := resolveSigningCredentialOutputPaths(ref)
	if err != nil {
		return err
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

	issued, err := requestSigningCertificate(client, pubPEM)
	if err != nil {
		return err
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
	if err := writeCredentialFile(certOutPath, []byte(issued.CertificatePEM)); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	printSigningCredentialIssued(cmd.OutOrStdout(), ref, certOutPath, issued)

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

// printSigningCredentialIssued reports where the credential landed and the selector
// that signing commands use to pick it.
func printSigningCredentialIssued(w io.Writer, ref signingCredentialRef, certOutPath string, issued signingCredentialResponseBody) {
	_, _ = fmt.Fprintf(w, "Signing credential issued (serial: %s, expires: %s)\n",
		issued.SerialNumber, issued.ExpiresAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(w, "Private key: stored encrypted as credential %q\n", ref.KeyName)
	_, _ = fmt.Fprintf(w, "Certificate: %s\n", certOutPath)
	_, _ = fmt.Fprintf(w, "Select this credential with: --signing-credential %s\n", ref.KeyName)
	if ref.Connection != "" {
		_, _ = fmt.Fprintf(w, "It is chosen automatically while connection %q is active.\n", ref.Connection)
	}
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
func resolveSigningCredentialOutputPaths(ref signingCredentialRef) (keyPath, certPath string, err error) {
	if credentialRequestSigningCertKeyOut != "" && !credentialRequestSigningCertExportPlain {
		return "", "", fmt.Errorf(
			"--key-out writes an unencrypted private key: pass --export-plaintext-key to confirm, " +
				"or omit --key-out to keep the key encrypted in the credential store")
	}
	certPath = credentialRequestSigningCertCertOut
	if certPath == "" {
		certPath = ref.CertPath
	}
	if credentialRequestSigningCertExportPlain {
		keyPath = credentialRequestSigningCertKeyOut
		if keyPath == "" {
			keyPath = filepath.Join(filepath.Dir(ref.CertPath), ref.KeyName+".pem")
		}
	}
	return keyPath, certPath, nil
}
