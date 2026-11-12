// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package initialization

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// reservedCNs are CN values that cannot be used for operator admin bundles.
// "system" prevents impersonation of audit.SystemUserID (pkg/audit/manager.go:90).
// "cfgms", "cfgms-internal", and "cfgms-admin" are reserved for system-internal certs.
// "cfgms-admin" is the CN used by the system admin bundle issued during --init; reserving
// it prevents audit log ambiguity from a duplicate operator bundle with the same CN.
var reservedCNs = []string{"system", "cfgms", "cfgms-internal", "cfgms-admin"}

// stewardCNPattern matches raw steward UUIDs as used in the controller registration
// handler (features/controller/api/handlers_registration.go:206-211).
// Steward client certs use the raw steward UUID as CN with Organization="CFGMS Stewards".
var stewardCNPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// adminCertValidityDays is the hard-coded maximum validity for admin certs (L3 fix).
// All admin cert issuance paths pass this value explicitly; no caller can supply higher.
const adminCertValidityDays = 365

// validateBundleExternalURL returns an actionable error if cfg.ExternalURL is
// unset or invalid. Both admin bundle issuance paths call this before writing any
// cert or init marker — a controller whose config omits external_url must not
// silently produce bundles with a wrong ControllerURL that surfaces only as a
// connection error on the operator's machine.
func validateBundleExternalURL(cfg *config.Config) error {
	if cfg.ExternalURL == "" {
		return fmt.Errorf("external_url must be set in the controller config before issuing admin bundles; " +
			"it is the externally-reachable HTTPS address operators use to connect " +
			"(e.g. external_url: https://controller.example.com:8080)")
	}
	u, err := url.Parse(cfg.ExternalURL)
	if err != nil {
		return fmt.Errorf("external_url %q is not a valid URL: %w", cfg.ExternalURL, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("external_url must use the https scheme, got %q", cfg.ExternalURL)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("external_url must include a hostname, got %q", cfg.ExternalURL)
	}
	return nil
}

// IssueAdminBundle issues a new admin client cert+key bundle for the named operator.
// The name must be non-empty, alphanumeric+hyphens only, max 64 chars, and must not
// match any reserved CN or steward UUID pattern. The bundle is written to outputPath
// with mode 0600 (enforced by bundle.Write).
//
// rootScoped is the ADR-025 Amendment 1 A1.3 opt-in (founder decision 2026-08-09,
// PR #3215): when true, the issued cert also carries cert.SetRootScopeMarker, marking
// its holder as a root-scoped SaaS-operator principal subject to ADR-025 Decision 1's
// root<->MSP boundary rather than an unrestricted superadmin. The marker is never
// inferred — this is the only production path that sets it, and issuance is audited.
// The system admin bundle (first boot / --regenerate, issueAdminBundle in
// initialization.go) never sets it; see that function's doc comment for why.
//
// ADR-025 Amendment 3: the certificate authenticates and confers nothing on its own, so
// the issued serial is bound to an administrator account (username == name, created or
// reused) in the same operation, before the bundle is written. If the account or binding
// write fails, no bundle is written and the certificate is revoked.
func IssueAdminBundle(cfg *config.Config, logger logging.Logger, name, outputPath string, rootScoped bool) error {
	if err := validateBundleRequest(cfg, name, outputPath); err != nil {
		return err
	}

	certManager, err := loadCertManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to load cert manager: %w", err)
	}

	// Open the account store before issuing anything: a deployment whose secret store is
	// unreachable must fail here, with no certificate minted and no bundle written.
	accountStore, err := openAccountStore(cfg)
	if err != nil {
		return err
	}
	defer closeAccountStore(accountStore, logger)

	adminCert, err := certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       name,
		Organization:     "CFGMS",
		ValidityDays:     adminCertValidityDays,
		TemplateModifier: adminTemplateModifier(rootScoped),
	})
	if err != nil {
		return fmt.Errorf("failed to issue admin certificate: %w", err)
	}
	if err := checkAdminCertValidity(adminCert); err != nil {
		return err
	}

	caPEM, err := certManager.GetCACertificate()
	if err != nil {
		return fmt.Errorf("failed to get CA certificate PEM: %w", err)
	}

	// ADR-025 Amendment 3: bind before the bundle exists. An unbound admin certificate
	// is inert, so it must never be handed to the operator.
	if err := BindAdminCertificate(context.Background(), accountStore, name, adminCert.SerialNumber, adminCert.Fingerprint); err != nil {
		revokeUndeliveredCert(certManager, logger, adminCert.SerialNumber)
		return err
	}

	b := &bundle.Bundle{
		CertPEM:         string(adminCert.CertificatePEM),
		KeyPEM:          string(adminCert.PrivateKeyPEM),
		CAPEM:           string(caPEM),
		ControllerURL:   cfg.ExternalURL,
		AuditSubject:    "admin:" + name,
		CertSerial:      adminCert.SerialNumber,
		CertFingerprint: adminCert.Fingerprint,
	}

	if err := bundle.Write(outputPath, b); err != nil {
		revokeUndeliveredCert(certManager, logger, adminCert.SerialNumber)
		return fmt.Errorf("failed to write admin bundle: %w", err)
	}

	bm := &BundleMarker{
		Serial:      adminCert.SerialNumber,
		Fingerprint: adminCert.Fingerprint,
		IssuedAt:    time.Now().UTC(),
		BundlePath:  outputPath,
	}
	if err := writeBundleMarker(outputPath, bm); err != nil {
		return fmt.Errorf("failed to write bundle issuance marker: %w", err)
	}

	logger.Info("Admin bundle issued",
		"path", logging.SanitizeLogValue(outputPath),
		"name", logging.SanitizeLogValue(name),
		"serial", adminCert.SerialNumber,
		"root_scoped", rootScoped)

	if rootScoped {
		// A credential that changes which side of the ADR-025 Decision 1 tenant boundary
		// its holder sits on must not be mintable without a trace (founder decision,
		// PR #3215, 2026-08-09). Fail closed: the bundle is already on disk at this point
		// (the operator has a valid credential either way), but a storage/audit failure
		// here is still returned as a hard error so the CLI never silently produces an
		// unaudited root-scoped credential — the operator sees the failure and can
		// investigate or revoke.
		if auditErr := auditRootScopedBundleIssuance(cfg, logger, name, adminCert); auditErr != nil {
			return fmt.Errorf("root-scoped admin bundle issued but audit record failed: %w", auditErr)
		}
	}
	return nil
}

// adminTemplateModifier returns the certificate template modifier for an operator bundle:
// the admin marker, plus the root-scope marker when rootScoped (ADR-025 Amendment 1 A1.3).
func adminTemplateModifier(rootScoped bool) func(*x509.Certificate) {
	if !rootScoped {
		return cert.SetAdminMarker
	}
	return func(template *x509.Certificate) {
		cert.SetAdminMarker(template)
		cert.SetRootScopeMarker(template)
	}
}

// checkAdminCertValidity is the L3 defensive check: it catches future regressions in
// GenerateClientCertificate that would issue an admin certificate valid beyond the cap.
func checkAdminCertValidity(adminCert *cert.Certificate) error {
	validity := adminCert.ExpiresAt.Sub(adminCert.CreatedAt)
	maxValidity := time.Duration(adminCertValidityDays+1) * 24 * time.Hour
	if validity > maxValidity {
		return fmt.Errorf("issued cert validity %v exceeds cap of %d days: this is a bug in GenerateClientCertificate",
			validity, adminCertValidityDays)
	}
	return nil
}

// validateBundleRequest checks an operator bundle request before anything is issued: the
// external URL the bundle will carry, the certificate CN, the output path, and that the name
// is also usable as the administrator account username (ADR-025 Amendment 3).
func validateBundleRequest(cfg *config.Config, name, outputPath string) error {
	if err := validateBundleExternalURL(cfg); err != nil {
		return err
	}
	if err := validateCN(name); err != nil {
		return err
	}
	if outputPath == defaultAdminBundlePath() {
		return fmt.Errorf("cannot overwrite the system admin bundle; use --regenerate to replace it")
	}
	return validateAdminAccountUsername(name)
}

// auditRootScopedBundleIssuance records a Critical-severity audit event for the issuance
// of a root-scoped admin bundle. Opens a short-lived storage+audit manager scoped to this
// single call — bootstrap-admin is a one-shot CLI invocation with no long-running server
// to own a persistent audit manager.
func auditRootScopedBundleIssuance(cfg *config.Config, logger logging.Logger, name string, adminCert *cert.Certificate) error {
	storageManager, err := openStorageManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to open storage for issuance audit: %w", err)
	}
	defer func() {
		if cErr := storageManager.Close(); cErr != nil {
			logger.Warn("failed to close storage manager after issuance audit", "error", cErr)
		}
	}()

	auditManager, err := audit.NewManager(storageManager.GetAuditStore(), "bootstrap-admin")
	if err != nil {
		return fmt.Errorf("failed to create audit manager: %w", err)
	}

	ctx := context.Background()
	recordErr := auditManager.RecordEvent(ctx, audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSystemAccess).
		Action("root_scoped_admin_bundle_issued").
		User(audit.SystemUserID, business.AuditUserTypeSystem).
		Resource("admin_bundle", adminCert.SerialNumber, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityCritical).
		Detail("operator_name", logging.SanitizeLogValue(name)).
		Detail("cert_fingerprint", adminCert.Fingerprint))

	// Stop flushes the queued entry to durable storage before this one-shot process
	// exits; without it RecordEvent's async enqueue could be lost on process exit.
	if stopErr := auditManager.Stop(ctx); stopErr != nil {
		logger.Warn("failed to stop audit manager cleanly after issuance audit", "error", stopErr)
	}

	if recordErr != nil {
		return fmt.Errorf("failed to record root-scoped issuance audit event: %w", recordErr)
	}
	return nil
}

// RegenerateSystemBundle issues a fresh admin cert, binds it to the system administrator
// account (reusing the account when it already exists) and overwrites the system bundle.
// The old cert remains valid until explicitly revoked via RevokeAdminBundle — the
// caller is responsible for running revocation after regeneration.
func RegenerateSystemBundle(cfg *config.Config, logger logging.Logger) error {
	bundlePath := cfg.AdminBundlePath
	if bundlePath == "" {
		bundlePath = defaultAdminBundlePath()
	}

	certManager, err := loadCertManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to load cert manager: %w", err)
	}

	return issueAdminBundle(bundlePath, cfg, certManager, logger)
}

// RunRegenerate handles the --regenerate flow with an explicit confirmation prompt.
// The caller supplies in (user input) and out (prompt destination) so tests can
// inject non-interactive readers without relying on os.Stdin.
//
// After regenerating, run `cfgms-controller bootstrap-admin --revoke <old-serial>`
// to invalidate the previous bundle.
func RunRegenerate(cfg *config.Config, logger logging.Logger, in io.Reader, out io.Writer) error {
	bundlePath := cfg.AdminBundlePath
	if bundlePath == "" {
		bundlePath = defaultAdminBundlePath()
	}

	_, _ = fmt.Fprintf(out, "This will issue a new system admin bundle and overwrite the existing one at %s.\n", bundlePath)
	_, _ = fmt.Fprintln(out, "The old bundle remains valid until you explicitly revoke its certificate.")
	_, _ = fmt.Fprintln(out, "Type 'yes' to confirm:")

	scanner := bufio.NewScanner(in)
	var response string
	if scanner.Scan() {
		response = scanner.Text()
	}

	if response != "yes" {
		_, _ = fmt.Fprintln(out, "Regeneration cancelled.")
		return fmt.Errorf("regeneration cancelled by operator")
	}

	return RegenerateSystemBundle(cfg, logger)
}

// RevokeAdminBundle revokes the admin bundle identified by serialNumber.
// Returns an error if the serial is not found in the certificate store.
func RevokeAdminBundle(cfg *config.Config, logger logging.Logger, serialNumber string) error {
	certManager, err := loadCertManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to load cert manager: %w", err)
	}

	if err := certManager.Revoke(serialNumber); err != nil {
		return fmt.Errorf("failed to revoke serial %s: %w", serialNumber, err)
	}

	logger.Info("Admin bundle revoked", "serial", logging.SanitizeLogValue(serialNumber))
	return nil
}

// validateCN enforces naming rules for operator admin cert CNs.
// Returns an error with code "RESERVED_CN" in the message when the name is reserved.
func validateCN(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > 64 {
		return fmt.Errorf("name must be 64 characters or fewer")
	}
	for _, c := range name {
		if !isAlphanumHyphen(c) {
			return fmt.Errorf("name must contain only alphanumeric characters and hyphens, got %q", name)
		}
	}
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return fmt.Errorf("name must not begin or end with a hyphen, got %q", name)
	}
	lower := strings.ToLower(name)
	for _, reserved := range reservedCNs {
		if lower == reserved {
			return fmt.Errorf("RESERVED_CN: %q is a reserved common name", name)
		}
	}
	if stewardCNPattern.MatchString(lower) {
		return fmt.Errorf("RESERVED_CN: %q matches the steward UUID CN pattern and cannot be used for operator bundles", name)
	}
	return nil
}

func isAlphanumHyphen(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-'
}

// loadCertManager loads a cert.Manager from an already-initialized controller.
// StoragePath is derived as filepath.Dir(cfg.Certificate.CAPath) — the parent of the
// "ca/" subdirectory — matching the invariant that cert.NewManager stores the CA at
// filepath.Join(StoragePath,"ca").
func loadCertManager(cfg *config.Config) (*cert.Manager, error) {
	if cfg.Certificate == nil || cfg.Certificate.CAPath == "" {
		return nil, fmt.Errorf("certificate path not configured (certificate.ca_path required)")
	}
	certPath := filepath.Dir(filepath.Clean(cfg.Certificate.CAPath))
	return cert.NewManager(&cert.ManagerConfig{
		StoragePath:    certPath,
		LoadExistingCA: true,
	})
}

// systemAdminUsername is the account the system admin bundle (first boot and
// --regenerate) is bound to. It equals the certificate CN and is a reserved CN, so no
// operator bundle can collide with it.
const systemAdminUsername = "cfgms-admin"

// SecretStoreOpener opens the controller's central secret store — the store that holds
// administrator accounts and their certificate bindings. The caller closes the store.
//
// The opener is injected rather than called directly because the store is built by
// features/controller/api (NewSecretStore: external key file, ephemeral-path guard,
// cluster-atomic CAS check), and that package imports this one. Registering the same
// constructor the server uses means bootstrap writes to exactly the store the server
// later reads — no second storage configuration to drift.
type SecretStoreOpener func(cfg *config.Config) (secretsinterfaces.SecretStore, error)

var secretStoreOpener atomic.Pointer[SecretStoreOpener]

// RegisterSecretStoreOpener installs the opener used to bind admin certificates to
// accounts. A nil opener clears the registration, after which every issuance fails
// closed: issuing an unbound certificate is never the fallback.
func RegisterSecretStoreOpener(open SecretStoreOpener) {
	if open == nil {
		secretStoreOpener.Store(nil)
		return
	}
	secretStoreOpener.Store(&open)
}

// openAccountStore opens the account store through the registered opener.
func openAccountStore(cfg *config.Config) (secretsinterfaces.SecretStore, error) {
	open := secretStoreOpener.Load()
	if open == nil {
		return nil, fmt.Errorf("cannot bind the admin certificate to an account: no secret store opener is registered")
	}
	store, err := (*open)(cfg)
	if err != nil {
		return nil, fmt.Errorf("cannot bind the admin certificate to an account: failed to open secret store: %w", err)
	}
	if store == nil {
		return nil, fmt.Errorf("cannot bind the admin certificate to an account: secret store is unavailable")
	}
	return store, nil
}

func closeAccountStore(store secretsinterfaces.SecretStore, logger logging.Logger) {
	if err := store.Close(); err != nil {
		logger.Warn("failed to close secret store after binding admin certificate",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// revokeUndeliveredCert revokes a certificate whose bundle was never delivered, so a
// failed issuance leaves no live credential behind. Best effort: the original failure
// is what the caller reports.
func revokeUndeliveredCert(certManager *cert.Manager, logger logging.Logger, serial string) {
	if err := certManager.Revoke(serial); err != nil {
		logger.Warn("failed to revoke certificate after failed admin bundle issuance",
			"serial", logging.SanitizeLogValue(serial),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// accountUsernameRegex mirrors the controller API's account username rule
// (features/controller/api validateUsername) — it cannot be imported (import cycle).
var accountUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$`)

// validateAdminAccountUsername checks that name is usable as the administrator account
// username as well as the certificate CN (validateCN is the CN rule; this adds the
// account's 3-character minimum).
func validateAdminAccountUsername(name string) error {
	if !accountUsernameRegex.MatchString(name) {
		return fmt.Errorf("name %q cannot be used as an administrator account username: "+
			"3-64 characters, alphanumerics and hyphens, starting with an alphanumeric", name)
	}
	return nil
}

const (
	// accountSecretType, accountKeyPrefix and accountTag identify administrator account
	// records in the secret store. They must equal the constants in
	// features/controller/api/handlers_accounts.go.
	accountSecretType = "account"
	accountKeyPrefix  = "account-"
	accountTag        = "account"

	// systemTenant is the storage tenant root-scope accounts are filed under
	// (features/controller/api accountStorageTenant).
	systemTenant = audit.SystemTenantID
)

// BindAdminCertificate creates the administrator account for username — or reuses it —
// and binds the certificate (serial, fingerprint) to it, in one record write (ADR-025
// Amendment 3). The bootstrap paths call it before they write a bundle; it is exported so
// an integration test that mints its own admin certificate can bind it the same way
// instead of writing account records by hand. The
// account is root-scope (ADR-025 Amendment 7): the bootstrap credential is the deployment's
// platform administrator. Permission breadth comes from the account's root scope, so no
// permission list is stored.
//
// An existing account is reused only when it is an enabled root-scope account: bootstrap
// must not quietly widen a tenant-scoped account to root, and must not hand out a
// certificate that is inert on arrival because the account is disabled. A serial
// already bound is left as is.
//
// The record format is written here, mirroring features/controller/api buildAccountSecretRequest,
// because that package imports this one. TestBootstrapBundle_BoundCertAuthenticatesAfterRestart
// (features/controller/api) reads the record back through the API's own lookup, so a drift
// between the two fails a test.
func BindAdminCertificate(ctx context.Context, store secretsinterfaces.SecretStore, username, serial, fingerprint string) error {
	if err := validateAdminAccountUsername(username); err != nil {
		return err
	}
	binding, err := json.Marshal(struct {
		Serial      string    `json:"serial"`
		Fingerprint string    `json:"fingerprint"`
		Label       string    `json:"label,omitempty"`
		BoundAt     time.Time `json:"bound_at"`
	}{
		Serial:      serial,
		Fingerprint: fingerprint,
		Label:       "bootstrap-admin",
		BoundAt:     time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("failed to encode certificate binding: %w", err)
	}

	existing, err := store.ListSecrets(ctx, &secretsinterfaces.SecretFilter{
		Tags: []string{accountTag},
		Metadata: map[string]string{
			secretsinterfaces.MetadataKeySecretType: accountSecretType,
			"username":                              username,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to look up administrator account %q: %w", username, err)
	}
	if len(existing) == 0 {
		return createAdminAccount(ctx, store, username, binding)
	}
	return appendAdminBinding(ctx, store, existing[0], username, serial, binding)
}

// createAdminAccount writes a new root-scope account carrying one certificate binding.
func createAdminAccount(ctx context.Context, store secretsinterfaces.SecretStore, username string, binding []byte) error {
	bindings, err := json.Marshal([]json.RawMessage{binding})
	if err != nil {
		return fmt.Errorf("failed to encode certificate bindings: %w", err)
	}
	err = store.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
		Key:         accountKeyPrefix + username,
		Value:       "", // accounts are passkey-only; no secret value
		TenantID:    systemTenant,
		CreatedBy:   "bootstrap-admin",
		Description: "web admin account",
		Tags:        []string{accountTag},
		Metadata: map[string]string{
			secretsinterfaces.MetadataKeySecretType: accountSecretType,
			"id":                                    uuid.NewString(),
			"username":                              username,
			"permissions":                           "",
			"created_at":                            time.Now().UTC().Format(time.RFC3339),
			"root_scope":                            "true",
			"cert_bindings":                         string(bindings),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create administrator account %q: %w", username, err)
	}
	return nil
}

// appendAdminBinding adds binding to an existing account record with a version-checked
// write, so a concurrent change to the account (disable, permissions) is never overwritten.
func appendAdminBinding(ctx context.Context, store secretsinterfaces.SecretStore, rec *secretsinterfaces.SecretMetadata, username, serial string, binding []byte) error {
	if err := checkAccountReusable(rec, username); err != nil {
		return err
	}
	bindings, err := parseAccountBindings(rec, username)
	if err != nil {
		return err
	}
	if bindingsContain(bindings, serial) {
		return nil
	}
	bindingsJSON, err := json.Marshal(append(bindings, binding))
	if err != nil {
		return fmt.Errorf("failed to encode certificate bindings: %w", err)
	}

	meta := make(map[string]string, len(rec.Metadata)+1)
	for k, v := range rec.Metadata {
		meta[k] = v
	}
	meta["cert_bindings"] = string(bindingsJSON)

	key := accountKeyPrefix + username
	_, ok, err := store.CompareAndSwapSecret(ctx, rec.TenantID+"/"+key, rec.Version, &secretsinterfaces.SecretRequest{
		Key:         key,
		Value:       "",
		TenantID:    rec.TenantID,
		CreatedBy:   rec.CreatedBy,
		Description: rec.Description,
		Tags:        rec.Tags,
		Metadata:    meta,
	})
	if err != nil {
		return fmt.Errorf("failed to bind certificate to administrator account %q: %w", username, err)
	}
	if !ok {
		return fmt.Errorf("administrator account %q changed while binding the certificate; run the command again", username)
	}
	return nil
}

// checkAccountReusable refuses an existing account bootstrap must not bind to: one that is
// not root-scope (bootstrap does not widen a tenant account to root) or is disabled (the
// certificate would be inert on arrival).
func checkAccountReusable(rec *secretsinterfaces.SecretMetadata, username string) error {
	if rec.Metadata["root_scope"] != "true" {
		return fmt.Errorf("administrator account %q already exists and is not root-scope; "+
			"bootstrap-admin will not change its scope: choose another name", username)
	}
	if rec.Metadata["disabled"] == "true" {
		return fmt.Errorf("administrator account %q is disabled; a certificate bound to it would be inert: "+
			"enable the account or choose another name", username)
	}
	return nil
}

// parseAccountBindings returns the account's certificate bindings as stored, undecoded, so
// fields this package does not know are carried forward unchanged.
func parseAccountBindings(rec *secretsinterfaces.SecretMetadata, username string) ([]json.RawMessage, error) {
	raw := rec.Metadata["cert_bindings"]
	if raw == "" {
		return nil, nil
	}
	var bindings []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &bindings); err != nil {
		return nil, fmt.Errorf("administrator account %q has unreadable certificate bindings: %w", username, err)
	}
	return bindings, nil
}

// bindingsContain reports whether one of bindings already binds serial.
func bindingsContain(bindings []json.RawMessage, serial string) bool {
	for _, b := range bindings {
		var existing struct {
			Serial string `json:"serial"`
		}
		if json.Unmarshal(b, &existing) == nil && existing.Serial == serial {
			return true
		}
	}
	return false
}
