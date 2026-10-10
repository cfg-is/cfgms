// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ErrSigningSerialNotMigrated is returned when an election names a serial that no
// node has imported into the migration namespace. Only validated material can be
// elected.
var ErrSigningSerialNotMigrated = errors.New("signing certificate serial is not in the migration namespace")

// ErrNoSigningKeyStore is returned by the migration operations on a Manager with
// no shared SigningKeyStore (single-node controllers have nothing to migrate to).
var ErrNoSigningKeyStore = errors.New("no shared signing key store configured")

// ErrSigningSerialRevoked is returned when a signing certificate serial is in the
// revocation store. A revoked serial is never imported, elected or promoted, so
// the migration cannot re-arm a certificate an operator withdrew.
var ErrSigningSerialRevoked = errors.New("signing certificate serial is revoked")

// Signing migration audit actions.
const (
	SigningMigrationImported   = "signing_migration_imported"
	SigningMigrationRefused    = "signing_migration_refused"
	SigningMigrationPromoted   = "signing_migration_promoted"
	SigningMigrationKeyRemoved = "signing_migration_local_key_removed"
)

// SigningMigrationEvent describes one step of the move from node-local signing
// certificates to the shared identity. It carries a serial, a fingerprint and a
// reason; never PEM or key bytes.
type SigningMigrationEvent struct {
	Action      string
	Serial      string
	Fingerprint string
	Reason      string
}

// SigningMigrationAuditSink receives migration events so the controller can
// record them in its audit log.
type SigningMigrationAuditSink func(ctx context.Context, event SigningMigrationEvent)

// SetSigningMigrationAuditSink wires the sink migration events are sent to. Call
// it once, before running the migration steps.
func (m *Manager) SetSigningMigrationAuditSink(sink SigningMigrationAuditSink) {
	m.migrationAuditMu.Lock()
	defer m.migrationAuditMu.Unlock()
	m.migrationAudit = sink
}

func (m *Manager) emitMigration(ctx context.Context, ev SigningMigrationEvent) {
	m.migrationAuditMu.RLock()
	sink := m.migrationAudit
	m.migrationAuditMu.RUnlock()
	level := certLog().Info
	if ev.Action == SigningMigrationRefused {
		level = certLog().Warn
	}
	level("Signing identity migration",
		"action", ev.Action,
		"serial", logging.SanitizeLogValue(ev.Serial),
		"reason", logging.SanitizeLogValue(ev.Reason))
	if sink != nil {
		sink(ctx, ev)
	}
}

// SigningImportResult is the outcome of importing one local signing certificate.
type SigningImportResult struct {
	Serial   string
	Imported bool
	Refused  bool
	// Reason says why the certificate was refused. It never contains key bytes.
	Reason string
}

// SigningKeyRemovalResult is the outcome for one local signing key file.
type SigningKeyRemovalResult struct {
	Serial  string
	Removed bool
	// Reason says why the key was kept.
	Reason string
}

// validateSigningMaterial applies the checks every signing certificate must pass
// before it enters the migration or shared namespace: not expired, issued by the
// cluster CA, CodeSigning EKU, a key that matches, and not revoked.
func (m *Manager) validateSigningMaterial(certPEM, keyPEM []byte) (*x509.Certificate, error) {
	x509Cert, err := ParseCertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("certificate cannot be parsed")
	}
	if err := m.refuseRevokedSigningSerial(x509Cert.SerialNumber.String()); err != nil {
		return nil, err
	}
	now := time.Now()
	if now.After(x509Cert.NotAfter) {
		return nil, fmt.Errorf("certificate is expired")
	}
	if now.Before(x509Cert.NotBefore) {
		return nil, fmt.Errorf("certificate is not yet valid")
	}
	res, err := m.validator.ValidateCertificate(x509Cert)
	if err != nil || res == nil || !res.IsValid {
		return nil, fmt.Errorf("certificate was not issued by the cluster CA")
	}
	hasCodeSigning := false
	for _, eku := range x509Cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
			break
		}
	}
	if !hasCodeSigning {
		return nil, fmt.Errorf("certificate lacks the CodeSigning extended key usage")
	}
	if err := ValidateKeyPair(certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("private key does not match the certificate")
	}
	return x509Cert, nil
}

// refuseRevokedSigningSerial returns ErrSigningSerialRevoked when serial is in the
// revocation store. A store read failure also refuses: revocation status that
// cannot be determined is never treated as "not revoked".
func (m *Manager) refuseRevokedSigningSerial(serial string) error {
	revoked, err := m.IsRevoked(serial)
	if err != nil {
		return fmt.Errorf("revocation status cannot be determined")
	}
	if revoked {
		return ErrSigningSerialRevoked
	}
	return nil
}

func certFingerprintHex(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// ImportLocalSigningCertificates validates every node-local signing certificate
// that still has its key and stores it create-if-absent in the migration
// namespace. A certificate that is expired, was not issued by the cluster CA,
// lacks the CodeSigning EKU, whose key does not match, that is revoked, or that conflicts with
// different material already stored for its serial is refused: reported in the
// results, logged, audited and never imported. Safe to run on every node,
// repeatedly and concurrently.
func (m *Manager) ImportLocalSigningCertificates(ctx context.Context) ([]SigningImportResult, error) {
	if m.signingKeys == nil {
		return nil, ErrNoSigningKeyStore
	}
	infos, err := m.store.getCertificatesByType(CertificateTypeConfigSigning)
	if err != nil {
		return nil, fmt.Errorf("list local signing certificates: %w", err)
	}
	var results []SigningImportResult
	for _, info := range infos {
		local, err := m.store.GetCertificate(info.SerialNumber)
		if err != nil {
			res := SigningImportResult{Serial: info.SerialNumber, Refused: true, Reason: "local certificate is unreadable"}
			m.emitMigration(ctx, SigningMigrationEvent{Action: SigningMigrationRefused, Serial: res.Serial, Reason: res.Reason})
			results = append(results, res)
			continue
		}
		if len(local.PrivateKeyPEM) == 0 {
			continue // public half only: nothing to import
		}
		res := SigningImportResult{Serial: local.SerialNumber}
		x509Cert, verr := m.validateSigningMaterial(local.CertificatePEM, local.PrivateKeyPEM)
		if verr == nil && x509Cert.SerialNumber.String() != local.SerialNumber {
			verr = fmt.Errorf("certificate serial does not match its storage entry")
		}
		var fp string
		existed := false
		if verr == nil {
			fp = certFingerprintHex(x509Cert)
			_, gerr := m.signingKeys.GetMigrationSigner(ctx, local.SerialNumber)
			existed = gerr == nil
			verr = m.signingKeys.PutMigrationSigner(ctx, &certinterfaces.SigningKeyMaterial{
				Serial:         local.SerialNumber,
				CertificatePEM: local.CertificatePEM,
				PrivateKeyPEM:  local.PrivateKeyPEM,
				IssuerChainPEM: local.IssuerChainPEM,
			})
		}
		if verr != nil {
			res.Refused = true
			res.Reason = verr.Error()
			if _, seen := m.migrationRefused.LoadOrStore(res.Serial+"|"+res.Reason, struct{}{}); !seen {
				m.emitMigration(ctx, SigningMigrationEvent{Action: SigningMigrationRefused, Serial: res.Serial, Fingerprint: fp, Reason: res.Reason})
			}
		} else {
			res.Imported = true
			if !existed {
				m.emitMigration(ctx, SigningMigrationEvent{Action: SigningMigrationImported, Serial: res.Serial, Fingerprint: fp})
			}
		}
		results = append(results, res)
	}
	return results, nil
}

// PromoteElectedSigner promotes the serial the shared cursor names from the
// migration namespace into the shared namespace (create-if-absent). It reports
// the serial and whether this call performed a promotion; nothing happens when
// the cursor is empty, the serial is already shared, or no node has imported it.
func (m *Manager) PromoteElectedSigner(ctx context.Context) (string, bool, error) {
	if m.signingKeys == nil {
		return "", false, ErrNoSigningKeyStore
	}
	cursor, err := m.cursor.LoadCursor(ctx)
	if err != nil {
		return "", false, fmt.Errorf("load signing cursor: %w", err)
	}
	if cursor == nil || cursor.CurrentSerial == "" {
		return "", false, nil
	}
	promoted, err := m.promoteSerial(ctx, cursor.CurrentSerial)
	return cursor.CurrentSerial, promoted, err
}

// promoteSerial copies serial from the migration namespace to the shared
// namespace when the shared namespace lacks it. The material is validated again:
// the migration namespace is writable by every node, so what it holds is not
// trusted until it passes the same checks as at import.
func (m *Manager) promoteSerial(ctx context.Context, serial string) (bool, error) {
	if _, err := m.signingKeys.GetSigningKey(ctx, serial); err == nil {
		return false, nil
	} else if !errors.Is(err, certinterfaces.ErrSigningKeyNotFound) {
		return false, err
	}
	mat, err := m.signingKeys.GetMigrationSigner(ctx, serial)
	if errors.Is(err, certinterfaces.ErrSigningKeyNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read migration signer: %w", err)
	}
	x509Cert, err := m.validateSigningMaterial(mat.CertificatePEM, mat.PrivateKeyPEM)
	if err == nil && x509Cert.SerialNumber.String() != serial {
		err = fmt.Errorf("certificate serial does not match its migration entry")
	}
	if err != nil {
		m.emitMigration(ctx, SigningMigrationEvent{Action: SigningMigrationRefused, Serial: serial, Reason: "promotion: " + err.Error()})
		return false, fmt.Errorf("refusing to promote signing serial %s: %w", logging.SanitizeLogValue(serial), err)
	}
	if err := m.signingKeys.PutSigningKey(ctx, mat); err != nil {
		return false, fmt.Errorf("promote signing serial %s: %w", logging.SanitizeLogValue(serial), err)
	}
	m.invalidateSigningCache()
	m.emitMigration(ctx, SigningMigrationEvent{Action: SigningMigrationPromoted, Serial: serial, Fingerprint: certFingerprintHex(x509Cert)})
	return true, nil
}

// ElectSharedSigningSerial names serial as the cluster's shared signing
// certificate by creating the cursor, only when no cursor exists. The serial must
// already be in the migration namespace, so an unvalidated serial cannot be
// elected, and must not be revoked (ErrSigningSerialRevoked), so an election
// cannot re-arm a withdrawn certificate. It never overrides an existing cursor: created is false and the
// existing cursor is returned. The cursor is created through SeedCursorIfAbsent,
// never TransitionCursor.
func (m *Manager) ElectSharedSigningSerial(ctx context.Context, serial string) (*SigningCertCursor, bool, error) {
	if m.signingKeys == nil {
		return nil, false, ErrNoSigningKeyStore
	}
	if !signingSerialPattern.MatchString(serial) {
		return nil, false, ErrInvalidSerial
	}
	if _, err := m.signingKeys.GetMigrationSigner(ctx, serial); err != nil {
		if errors.Is(err, certinterfaces.ErrSigningKeyNotFound) {
			return nil, false, ErrSigningSerialNotMigrated
		}
		return nil, false, fmt.Errorf("read migration signer: %w", err)
	}
	if err := m.refuseRevokedSigningSerial(serial); err != nil {
		m.emitMigration(ctx, SigningMigrationEvent{Action: SigningMigrationRefused, Serial: serial, Reason: "election: " + err.Error()})
		if errors.Is(err, ErrSigningSerialRevoked) {
			return nil, false, err
		}
		return nil, false, fmt.Errorf("check signing serial revocation: %w", err)
	}
	cursor, created, err := m.cursor.SeedCursorIfAbsent(ctx, serial)
	if err != nil {
		return nil, false, fmt.Errorf("seed signing cursor: %w", err)
	}
	if created {
		if _, perr := m.promoteSerial(ctx, serial); perr != nil {
			// The election stands; every node retries promotion when it resolves.
			certLog().Warn("Elected signing serial could not be promoted yet", "error", logging.SanitizeLogValue(perr.Error()))
		}
	}
	return cursor, created, nil
}

// RemoveVerifiedLocalSigningKeys deletes this node's local signing key files, but
// only when the node resolves Shared mode and every local signing key it holds
// reads back equal from the shared or migration namespace. It is all or nothing:
// one key it cannot verify keeps every key on disk. The certificate, chain and
// metadata stay. The overwrite before unlink is best effort and does not defeat
// media-level recovery.
func (m *Manager) RemoveVerifiedLocalSigningKeys(ctx context.Context) ([]SigningKeyRemovalResult, error) {
	if m.signingKeys == nil {
		return nil, ErrNoSigningKeyStore
	}
	mode, _, err := m.resolveSigningIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if mode != SigningIdentityShared {
		return nil, nil
	}
	infos, err := m.store.getCertificatesByType(CertificateTypeConfigSigning)
	if err != nil {
		return nil, fmt.Errorf("list local signing certificates: %w", err)
	}
	var withKey []*Certificate
	for _, info := range infos {
		local, err := m.store.GetCertificate(info.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("read local signing certificate %s: %w", logging.SanitizeLogValue(info.SerialNumber), err)
		}
		if len(local.PrivateKeyPEM) > 0 {
			withKey = append(withKey, local)
		}
	}

	results := make([]SigningKeyRemovalResult, 0, len(withKey))
	allVerified := true
	for _, local := range withKey {
		res := SigningKeyRemovalResult{Serial: local.SerialNumber}
		if reason := m.verifyLocalKeyInStore(ctx, local); reason != "" {
			res.Reason = reason
			allVerified = false
		}
		results = append(results, res)
	}
	if !allVerified {
		for i := range results {
			if results[i].Reason == "" {
				results[i].Reason = "another local signing key could not be verified in the shared store"
			}
		}
		return results, nil
	}
	for i, local := range withKey {
		if err := m.store.RemoveSigningKeyFile(local.SerialNumber); err != nil {
			results[i].Reason = err.Error()
			return results, fmt.Errorf("remove local signing key %s: %w", logging.SanitizeLogValue(local.SerialNumber), err)
		}
		results[i].Removed = true
		m.emitMigration(ctx, SigningMigrationEvent{Action: SigningMigrationKeyRemoved, Serial: local.SerialNumber})
	}
	return results, nil
}

// verifyLocalKeyInStore returns "" when local's certificate and key read back
// equal from the shared namespace or, failing that, the migration namespace, and
// otherwise the reason it could not be verified.
func (m *Manager) verifyLocalKeyInStore(ctx context.Context, local *Certificate) string {
	stored, err := m.signingKeys.GetSigningKey(ctx, local.SerialNumber)
	if errors.Is(err, certinterfaces.ErrSigningKeyNotFound) {
		stored, err = m.signingKeys.GetMigrationSigner(ctx, local.SerialNumber)
	}
	if err != nil {
		return "not found in the shared store"
	}
	if sameCertificatePEM(stored.CertificatePEM, local.CertificatePEM) != nil ||
		samePrivateKeyPEM(stored.PrivateKeyPEM, local.PrivateKeyPEM) != nil {
		return "shared store holds different material for this serial"
	}
	return ""
}
