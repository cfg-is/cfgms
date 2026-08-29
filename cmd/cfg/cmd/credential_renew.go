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
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/cert/bundle"
)

var (
	credentialRenewAPIURL      string
	credentialRenewTLSInsecure bool
	credentialRenewServerName  string
	credentialRenewUnattended  bool
)

// credentialRenewalWindow bounds how long before expiry --unattended treats renewal
// as due. This is a client-side courtesy only — the controller enforces its own
// window (features/controller/api/handlers_credential_renewal.go's
// credentialRenewalWindow, Issue #3724) and is the actual authority; keep the two
// values in sync so --unattended does not needlessly wake up 29 days before the
// controller would accept the call, nor sleep past the point the controller expects
// renewal to have already happened.
const credentialRenewalWindow = 30 * 24 * time.Hour

// credentialRenewCmd implements cfg credential renew.
var credentialRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew this host's admin mTLS credential before it expires",
	Long: `Renews the mTLS admin credential in the admin bundle (see 'cfg connect'): a
fresh keypair is generated locally, only the new public key is sent to the
controller as a certificate signing request, and the controller signs a new
certificate bound to the same account the current certificate is already bound
to. The old certificate is revoked once the new one is confirmed bound — the
account itself is never selectable or nameable in this request.

Renewal is authorised by presenting the current, still-valid certificate over
mutual TLS — there is no separate renewal credential. The controller refuses
the call outside its renewal window, for an already-expired certificate, or for
a revoked certificate. If the bound account has been administratively disabled,
the certificate can no longer even authenticate, and renewal (like everything
else) fails.

--unattended is for periodic/cron/systemd-timer invocation: it checks the
current certificate's expiry locally first and exits 0 without contacting the
controller when renewal is not yet due, so a scheduled job can run frequently
without generating noise or load. Without --unattended, renewal is attempted
unconditionally and the controller's own window check is authoritative.

If renewal fails because the certificate has already fully expired, or because
the bound account was disabled, there is no recovery path through this command:
an administrator must issue a new enrolment token and this host must re-enrol
from scratch.

Examples:
  cfg credential renew
  cfg credential renew --unattended
  cfg credential renew --bundle /etc/cfgms/admin.bundle.yaml --unattended`,
	RunE: runCredentialRenew,
}

func init() {
	credentialRenewCmd.Flags().StringVar(&credentialRenewAPIURL, "api-url", "", "Controller REST API URL override (default: the bundle's stored controller_url)")
	credentialRenewCmd.Flags().BoolVar(&credentialRenewTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	credentialRenewCmd.Flags().StringVar(&credentialRenewServerName, "server-name", "", "Override TLS server name for certificate verification")
	credentialRenewCmd.Flags().BoolVar(&credentialRenewUnattended, "unattended", false,
		"Only contact the controller if the certificate is within its renewal window; exit 0 without renewing otherwise (for periodic/cron invocation)")

	credentialCmd.AddCommand(credentialRenewCmd)
}

// renewCredentialRequestBody mirrors api.RenewCredentialRequest on the controller.
// CSRPEM is the only field — the account being renewed into is derived entirely from
// the certificate presented over mutual TLS, never from this body.
type renewCredentialRequestBody struct {
	CSRPEM string `json:"csr_pem"`
}

// renewCredentialResponseBody mirrors api.RenewCredentialResponse on the controller.
type renewCredentialResponseBody struct {
	CertificatePEM   string   `json:"certificate_pem"`
	CACertificatePEM string   `json:"ca_certificate_pem"`
	SerialNumber     string   `json:"serial_number"`
	AccountID        string   `json:"account_id"`
	GrantedMarkers   []string `json:"granted_markers"`
	ExpiresAt        string   `json:"expires_at"`
}

// resolveRenewalBundlePath walks the same admin-bundle lookup chain as
// resolveBundleClient (client_helpers.go), but returns the resolved path directly
// instead of an already-built APIClient: renewal needs the path a second time, to
// write the renewed bundle back to the exact file it was read from.
func resolveRenewalBundlePath() (string, error) {
	if noBundle {
		return "", fmt.Errorf("renewal requires an admin bundle; --no-bundle was set")
	}
	bundleEnvVal, bundleEnvSet := os.LookupEnv("CFGMS_ADMIN_BUNDLE")
	if bundleEnvSet && bundleEnvVal == "" {
		return "", fmt.Errorf("renewal requires an admin bundle; CFGMS_ADMIN_BUNDLE is explicitly empty")
	}
	path, err := findBundlePath(bundleEnvVal)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", errNoCredential
	}
	return path, nil
}

// parseBundleCertificate decodes the single PEM certificate block in a bundle's CertPEM.
func parseBundleCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("bundle certificate is not valid PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// certificateWithinRenewalWindow reports whether notAfter is within
// credentialRenewalWindow of now — the same local courtesy check --unattended uses
// to decide whether to contact the controller at all.
func certificateWithinRenewalWindow(notAfter time.Time) bool {
	return time.Now().Add(credentialRenewalWindow).After(notAfter)
}

func runCredentialRenew(cmd *cobra.Command, _ []string) error {
	bundleFilePath, err := resolveRenewalBundlePath()
	if err != nil {
		return err
	}
	b, err := bundle.Read(bundleFilePath)
	if err != nil {
		return fmt.Errorf("failed to read admin bundle: %w", err)
	}

	currentCert, err := parseBundleCertificate(b.CertPEM)
	if err != nil {
		return fmt.Errorf("failed to parse bundle certificate: %w", err)
	}

	if credentialRenewUnattended && !certificateWithinRenewalWindow(currentCert.NotAfter) {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"Certificate not yet due for renewal (expires %s); nothing to do\n",
			currentCert.NotAfter.UTC().Format(time.RFC3339))
		return nil
	}

	client, err := newClientFromBundle(bundleFilePath, credentialRenewAPIURL, credentialRenewTLSInsecure, credentialRenewServerName)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// A fresh keypair every renewal — reusing the current certificate's key is
	// refused by the controller (Issue #3724).
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate renewal keypair: %w", err)
	}
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: currentCert.Subject.CommonName}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
	if err != nil {
		return fmt.Errorf("failed to build certificate signing request: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	reqBody, err := json.Marshal(renewCredentialRequestBody{CSRPEM: string(csrPEM)})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/credential-renewal", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("renewal request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("credential renewal failed (%s): %s", resp.Status, string(body))
	}

	var envelope struct {
		Data renewCredentialResponseBody `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal renewed private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if _, err := parseBundleCertificate(envelope.Data.CertificatePEM); err != nil {
		return fmt.Errorf("failed to parse renewed certificate: %w", err)
	}

	// Write the renewed bundle to the exact file it was read from, preserving
	// everything except the fields renewal actually changed. bundle.Write is
	// atomic (write-temp-then-rename), so a crash mid-write never leaves a
	// half-written bundle — the old file remains intact until the new one is
	// fully staged.
	renewed := &bundle.Bundle{
		CertPEM:         envelope.Data.CertificatePEM,
		KeyPEM:          string(keyPEM),
		CAPEM:           envelope.Data.CACertificatePEM,
		ControllerURL:   b.ControllerURL,
		AuditSubject:    b.AuditSubject,
		CertSerial:      envelope.Data.SerialNumber,
		CertFingerprint: certificateFingerprint(envelope.Data.CertificatePEM),
	}
	if err := bundle.Write(bundleFilePath, renewed); err != nil {
		return fmt.Errorf("failed to write renewed bundle: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Credential renewed (serial: %s, expires: %s)\n",
		envelope.Data.SerialNumber, envelope.Data.ExpiresAt)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Bundle updated: %s\n", bundleFilePath)
	return nil
}
