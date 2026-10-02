// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3720 (Epic #3711 — browser-authenticated CLI enrolment): enrolment-token
// minting for administrators, and headless credential enrolment for the machine that
// spends one. Sibling to the signing-credential request command added by #3693 — it
// shares that command's local keypair generation and the connection/session wiring
// runConnectFirstTime uses, rather than duplicating either.
package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	certbundle "github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---- errors -----------------------------------------------------------------------

// Distinct, clear terminal outcomes for the enrol poll loop (Issue #3720 AC). Each
// leaves no partial credential on disk — nothing is written until collection succeeds.
var (
	errCredentialRequestDenied      = errors.New("credential request was denied by an administrator")
	errCredentialRequestExpired     = errors.New("credential request expired before it was approved")
	errCredentialRequestGone        = errors.New("credential request was already collected")
	errCredentialRequestInterrupted = errors.New("enrolment interrupted; no credential was stored")
)

// ---- shared keypair generation (Issue #3693 / #3720) -------------------------------

// generateECDSAP256Keypair generates a fresh ECDSA P-256 keypair. Used by every command
// that generates a credential locally: the private key this returns never leaves the
// machine that called it.
func generateECDSAP256Keypair() (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}
	return priv, nil
}

// ---- flags --------------------------------------------------------------------------

var (
	credentialEnrolmentTokenMintTenantID string
	credentialEnrolmentTokenAPIURL       string
	credentialEnrolmentTokenTLSInsecure  bool
	credentialEnrolmentTokenServerName   string

	credentialEnrolToken        string
	credentialEnrolURL          string
	credentialEnrolName         string
	credentialEnrolHostname     string
	credentialEnrolLabel        string
	credentialEnrolPlatform     string
	credentialEnrolPurpose      string
	credentialEnrolTLSInsecure  bool
	credentialEnrolServerName   string
	credentialEnrolPollInterval time.Duration
)

// credentialEnrolSignalContextFn creates the cancelable context the enrol command
// polls under, canceled on an operator interrupt (SIGINT/Ctrl-C) so the poll loop exits
// cleanly with the distinct errCredentialRequestInterrupted message and no partial
// credential on disk (Issue #3720 AC). Overridable in tests, which cannot send a real
// OS signal to the test process without affecting the whole `go test` run.
var credentialEnrolSignalContextFn = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

// ---- commands -------------------------------------------------------------------

// credentialEnrolmentTokenCmd is the parent command: cfg credential enrolment-token ...
var credentialEnrolmentTokenCmd = &cobra.Command{
	Use:   "enrolment-token",
	Short: "Mint and revoke enrolment tokens for headless credential enrolment",
	Long: `An enrolment token is a short-lived, single-use pre-shared secret an
administrator mints from their own authenticated workstation and hands to a headless
machine out of band (read over a phone call, pasted into a terminal). The receiving
machine spends it exactly once, via 'cfg credential enrol', to lodge a certificate
signing request.`,
}

// credentialEnrolmentTokenMintCmd implements cfg credential enrolment-token mint.
var credentialEnrolmentTokenMintCmd = &cobra.Command{
	Use:   "mint",
	Short: "Mint a single-use enrolment token for a tenant",
	Long: `Mints a short-lived (one hour), single-use enrolment token scoped to
--tenant-id. The raw token value is displayed exactly once, in this command's output —
it cannot be retrieved again afterward, only its non-secret prefix. Hand it to the
enrolling machine out of band, then run 'cfg credential enrol' there.

Requires an authenticated admin mTLS bundle or session (see 'cfg connect') holding the
enrolment-token:mint permission.`,
	RunE: runCredentialEnrolmentTokenMint,
}

// credentialEnrolmentTokenRevokeCmd implements cfg credential enrolment-token revoke.
var credentialEnrolmentTokenRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke an unspent enrolment token",
	Long: `Revokes an enrolment token before it is spent, so it can never be used to
lodge a credential request. A token that has already been spent cannot be revoked —
its one use is already consumed.`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialEnrolmentTokenRevoke,
}

// credentialEnrolCmd implements cfg credential enrol.
var credentialEnrolCmd = &cobra.Command{
	Use:   "enrol",
	Short: "Enrol this machine for a cfg credential using an enrolment token",
	Long: `Generates an ECDSA P-256 keypair locally, lodges a certificate signing
request against the controller authenticated by --token, then polls until an
administrator approves or denies it. The private key never leaves this machine — only
the public key, inside the signing request, crosses the wire.

Prints the human-comparable public-key fingerprint the lodge call returns: the
administrator must compare it on screen before approving. On approval the command
collects the signed certificate, registers the connection, and exchanges the
certificate for a session — exactly as 'cfg connect --bundle' does on first import —
so the next ordinary cfg command against this controller succeeds.

A denial, an expiry, or an operator interrupt (Ctrl-C) each exit with a distinct
message and leave no credential on disk.

Examples:
  cfg credential enrol --token <token> --url https://controller:9443
  cfg credential enrol --token <token> --url https://controller:9443 --name prod`,
	RunE: runCredentialEnrol,
}

func init() {
	credentialEnrolmentTokenMintCmd.Flags().StringVar(&credentialEnrolmentTokenMintTenantID, "tenant-id", "", "Tenant to mint the token for (required)")

	credentialEnrolmentTokenCmd.PersistentFlags().StringVar(&credentialEnrolmentTokenAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	credentialEnrolmentTokenCmd.PersistentFlags().BoolVar(&credentialEnrolmentTokenTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	credentialEnrolmentTokenCmd.PersistentFlags().StringVar(&credentialEnrolmentTokenServerName, "server-name", "", "Override TLS server name for certificate verification")

	credentialEnrolmentTokenCmd.AddCommand(credentialEnrolmentTokenMintCmd)
	credentialEnrolmentTokenCmd.AddCommand(credentialEnrolmentTokenRevokeCmd)
	credentialCmd.AddCommand(credentialEnrolmentTokenCmd)

	credentialEnrolCmd.Flags().StringVar(&credentialEnrolToken, "token", "", "Enrolment token minted by an administrator (env: CFGMS_ENROLMENT_TOKEN)")
	credentialEnrolCmd.Flags().StringVar(&credentialEnrolURL, "url", "", "Controller HTTPS URL (required)")
	credentialEnrolCmd.Flags().StringVar(&credentialEnrolName, "name", "", "Connection name to register (default: derived from --url host)")
	credentialEnrolCmd.Flags().StringVar(&credentialEnrolHostname, "hostname", "", "Display-only hostname sent with the request (default: this machine's hostname)")
	credentialEnrolCmd.Flags().StringVar(&credentialEnrolLabel, "label", "", "Display-only label sent with the request")
	credentialEnrolCmd.Flags().StringVar(&credentialEnrolPlatform, "platform", "", "Display-only platform sent with the request")
	credentialEnrolCmd.Flags().StringVar(&credentialEnrolPurpose, "purpose", "cli enrolment", "Display-only purpose sent with the request")
	credentialEnrolCmd.Flags().BoolVar(&credentialEnrolTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	credentialEnrolCmd.Flags().StringVar(&credentialEnrolServerName, "server-name", "", "Override TLS server name for certificate verification")
	credentialEnrolCmd.Flags().DurationVar(&credentialEnrolPollInterval, "poll-interval", 5*time.Second, "Interval between collect polls")

	credentialCmd.AddCommand(credentialEnrolCmd)
}

// ---- enrolment-token mint / revoke ------------------------------------------------

// resolveCredentialManagementClient resolves an authenticated admin client (mTLS bundle
// or session) for enrolment-token management, applying the same CFGMS_API_URL /
// CFGMS_TLS_INSECURE env fallbacks getCredentialAPIClient uses (#3693).
func resolveCredentialManagementClient(apiURL string, tlsInsecure bool, serverName string) (*APIClient, error) {
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	return requireSessionOrBundleClient(apiURL, tlsInsecure, serverName)
}

func runCredentialEnrolmentTokenMint(cmd *cobra.Command, _ []string) error {
	if credentialEnrolmentTokenMintTenantID == "" {
		return fmt.Errorf("--tenant-id is required")
	}

	client, err := resolveCredentialManagementClient(credentialEnrolmentTokenAPIURL, credentialEnrolmentTokenTLSInsecure, credentialEnrolmentTokenServerName)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.MintEnrolmentToken(context.Background(), credentialEnrolmentTokenMintTenantID)
	if err != nil {
		return fmt.Errorf("failed to mint enrolment token: %w", err)
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Enrolment token minted (id: %s, tenant: %s, expires: %s)\n",
		logging.SanitizeLogValue(resp.ID), logging.SanitizeLogValue(resp.TenantID), logging.SanitizeLogValue(resp.ExpiresAt))
	_, _ = fmt.Fprintf(out, "Token (shown once, cannot be retrieved again): %s\n", resp.Token)
	_, _ = fmt.Fprintln(out, "Hand this value to the enrolling machine out of band, then run there:")
	_, _ = fmt.Fprintln(out, "  cfg credential enrol --token <token> --url <controller-url>")
	return nil
}

func runCredentialEnrolmentTokenRevoke(cmd *cobra.Command, args []string) error {
	client, err := resolveCredentialManagementClient(credentialEnrolmentTokenAPIURL, credentialEnrolmentTokenTLSInsecure, credentialEnrolmentTokenServerName)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.RevokeEnrolmentToken(context.Background(), args[0])
	if err != nil {
		return fmt.Errorf("failed to revoke enrolment token: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Enrolment token %s revoked\n", logging.SanitizeLogValue(resp.ID))
	return nil
}

// ---- enrol --------------------------------------------------------------------------

// buildEnrolCSR generates a self-signed PEM CERTIFICATE REQUEST over priv's public key.
// The lodge endpoint requires an actual signing request whose own signature it verifies
// (features/controller/api/handlers_credential_requests.go parseAndVerifyCSR) — unlike
// the public-key-only body #3693 sends to the signing-credential endpoint. priv never
// appears in the result.
func buildEnrolCSR(priv *ecdsa.PrivateKey, commonName string) (string, error) {
	if commonName == "" {
		commonName = "cfg-enrol"
	}
	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate signing request: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// certificateFingerprint returns the hex SHA-256 fingerprint of a PEM-encoded
// certificate's DER bytes, matching pkg/cert's own calculateFingerprint — computed
// client-side here purely for display/revocation-lookup parity with a connect-imported
// bundle; the server response carries no such field.
func certificateFingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// pollForCollection polls collectClient for requestID every interval until the request
// is approved and collected, denied, expired, already gone, or ctx is canceled (an
// operator interrupt). It writes nothing to disk — only its return value carries the
// signed certificate onward, so every exit path here leaves no partial credential.
func pollForCollection(ctx context.Context, collectClient *APIClient, requestID string, interval time.Duration, out io.Writer) (*CollectCredentialRequestResponse, error) {
	for {
		result, err := collectClient.CollectCredentialRequest(ctx, requestID)
		if err != nil {
			// A canceled context can abort the in-flight HTTP call itself, not just
			// the sleep between polls — that failure is an operator interrupt too,
			// not a transport error, and must produce the same distinct message.
			if ctx.Err() != nil {
				return nil, errCredentialRequestInterrupted
			}
			return nil, fmt.Errorf("failed to poll for collection: %w", err)
		}
		switch {
		case result.Certificate != nil:
			return result.Certificate, nil
		case result.AlreadyGone:
			return nil, errCredentialRequestGone
		case result.Status == "denied":
			return nil, errCredentialRequestDenied
		case result.Status == "expired":
			return nil, errCredentialRequestExpired
		case result.Status == "pending", result.Status == "retry":
			// keep polling
		default:
			return nil, fmt.Errorf("unexpected credential request status %q", logging.SanitizeLogValue(result.Status))
		}

		_, _ = fmt.Fprintln(out, "Waiting for administrator approval...")

		select {
		case <-ctx.Done():
			return nil, errCredentialRequestInterrupted
		case <-time.After(interval):
		}
	}
}

func runCredentialEnrol(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	token := credentialEnrolToken
	if token == "" {
		token = os.Getenv("CFGMS_ENROLMENT_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("--token is required (or set CFGMS_ENROLMENT_TOKEN)")
	}
	controllerURL := credentialEnrolURL
	if controllerURL == "" {
		return fmt.Errorf("--url is required")
	}
	if err := requireHTTPS(controllerURL); err != nil {
		return err
	}

	name := credentialEnrolName
	if name == "" {
		name = deriveConnectionName(controllerURL)
	}

	hostname := credentialEnrolHostname
	if hostname == "" {
		if h, hErr := os.Hostname(); hErr == nil {
			hostname = h
		}
	}

	tlsInsecure := credentialEnrolTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := credentialEnrolServerName

	// Fail fast if the credential store can't be opened, before the single-use
	// enrolment token or the collect secret is ever spent.
	credStore, err := newCredentialStore()
	if err != nil {
		return fmt.Errorf("failed to open credential store: %w", err)
	}

	priv, err := generateECDSAP256Keypair()
	if err != nil {
		return fmt.Errorf("failed to generate enrolment keypair: %w", err)
	}
	csrPEM, err := buildEnrolCSR(priv, hostname)
	if err != nil {
		return fmt.Errorf("failed to build certificate signing request: %w", err)
	}

	lodgeClient, err := NewAPIClient(&APIClientConfig{
		BaseURL:     controllerURL,
		BearerToken: token,
		TLSInsecure: tlsInsecure,
		ServerName:  serverName,
	})
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	lodgeResp, err := lodgeClient.LodgeCredentialRequest(context.Background(), LodgeCredentialRequestBody{
		CSRPEM:   csrPEM,
		Hostname: hostname,
		Label:    credentialEnrolLabel,
		Platform: credentialEnrolPlatform,
		Purpose:  credentialEnrolPurpose,
	})
	if err != nil {
		return fmt.Errorf("failed to lodge credential request: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Credential request lodged (id: %s)\n", logging.SanitizeLogValue(lodgeResp.RequestID))
	_, _ = fmt.Fprintf(out, "Public key fingerprint: %s\n", logging.SanitizeLogValue(lodgeResp.PublicKeyFingerprintShort))
	_, _ = fmt.Fprintln(out, "Compare this fingerprint with the administrator before they approve the request.")
	_, _ = fmt.Fprintf(out, "Approval endpoint (an administrator lists and approves pending requests here): %s/api/v1/credential-requests\n",
		strings.TrimRight(controllerURL, "/"))
	_, _ = fmt.Fprintf(out, "Expires: %s\n", logging.SanitizeLogValue(lodgeResp.ExpiresAt))

	// The collect secret lives only in this local variable for the life of the
	// process — never written to disk, never logged (Issue #3720 AC).
	collectSecret := lodgeResp.CollectSecret

	collectClient, err := NewAPIClient(&APIClientConfig{
		BaseURL:     controllerURL,
		BearerToken: collectSecret,
		TLSInsecure: tlsInsecure,
		ServerName:  serverName,
	})
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	ctx, stopPolling := credentialEnrolSignalContextFn()
	defer stopPolling()

	certResp, err := pollForCollection(ctx, collectClient, lodgeResp.RequestID, credentialEnrolPollInterval, out)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "Credential request approved and collected (serial: %s)\n", logging.SanitizeLogValue(certResp.SerialNumber))

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	b := &certbundle.Bundle{
		CertPEM:         certResp.CertificatePEM,
		KeyPEM:          string(keyPEM),
		CAPEM:           certResp.CACertificatePEM,
		ControllerURL:   controllerURL,
		AuditSubject:    certResp.AccountID,
		CertSerial:      certResp.SerialNumber,
		CertFingerprint: certificateFingerprint(certResp.CertificatePEM),
	}
	bundleBytes, err := yaml.Marshal(b)
	if err != nil {
		return fmt.Errorf("failed to encode credential: %w", err)
	}

	// Register non-secret connection metadata, exactly as runConnectFirstTime does.
	reg, err := newConnectionRegistry()
	if err != nil {
		return fmt.Errorf("failed to open connection registry: %w", err)
	}
	if err := reg.Register(ConnectionEntry{
		Name:          name,
		ControllerURL: controllerURL,
		AdminIdentity: certResp.AccountID,
		UnlockMethod:  "machine",
	}); err != nil {
		return fmt.Errorf("failed to register connection: %w", err)
	}

	if err := credStore.Store(context.Background(), name, bundleBytes); err != nil {
		return fmt.Errorf("failed to store credential: %w", err)
	}

	// Exchange the newly collected certificate for a session so the next ordinary cfg
	// command against this controller succeeds without a further manual step.
	client, err := newClientFromBundleData(b, controllerURL, tlsInsecure, serverName)
	if err != nil {
		return fmt.Errorf("failed to build mTLS client: %w", err)
	}
	sessResp, err := client.IssueSession(context.Background(), name)
	if err != nil {
		return fmt.Errorf("failed to issue session: %w", err)
	}

	if err := storeSessionToken(&sessionRecord{
		Token:          sessResp.Token,
		SessionID:      sessResp.SessionID,
		ControllerURL:  controllerURL,
		ConnectionName: name,
		AbsoluteExpiry: sessResp.AbsoluteExpiry,
		CACertPEM:      certResp.CACertificatePEM,
	}); err != nil {
		return fmt.Errorf("failed to store session token: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Enrolled as %q (expires %s)\n", logging.SanitizeLogValue(name), sessResp.AbsoluteExpiry.Format(time.RFC3339))
	return nil
}
