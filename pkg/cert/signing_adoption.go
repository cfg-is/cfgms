// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"errors"
	"fmt"
	"time"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ErrSigningAdoptionUnavailable is returned by AdoptLocalSigningIdentity on a
// Manager that is not a single-node controller with a signing key store.
var ErrSigningAdoptionUnavailable = errors.New("signing identity adoption is only available on a single-node signing key store")

// SigningAdoptionRefusal names a local signing certificate that adoption
// declined to move into the store, and why. Reason never contains key bytes.
type SigningAdoptionRefusal struct {
	Serial string
	Reason string
}

// SigningAdoptionResult is the outcome of AdoptLocalSigningIdentity. It holds
// serials and reasons only; never PEM or key bytes.
type SigningAdoptionResult struct {
	// AdoptedSerials are the serials whose certificate and key are in the store
	// and read back equal to the local material.
	AdoptedSerials []string
	// RefusedSerials are local signing certificates adoption declined. Their local
	// keys are left in place.
	RefusedSerials []SigningAdoptionRefusal
	// RemovedKeySerials are the serials whose local key.pem was removed.
	RemovedKeySerials []string
}

// AdoptLocalSigningIdentity moves a single-node controller's pre-existing signing
// certificate and key into its signing key store under the same serial, so the
// certificate every enrolled steward pins stays valid. It adopts the serial the
// node signs with today and, when a rotation overlap is open, the rotating
// serial; seeds an empty cursor with the current serial; reads each adopted
// serial back and compares it byte for byte with the local material; and only
// then removes the local key.pem of each adopted serial and of every expired
// local signing certificate. cert.pem and metadata stay.
//
// Every step can be repeated, so a stop at any point is completed by the next
// call. A refused certificate is reported in the result with a reason and leaves
// everything unchanged. A store, cursor or read-back failure returns an error
// before any local key is removed. Valid refused certificates keep their local
// key.
func (m *Manager) AdoptLocalSigningIdentity(ctx context.Context) (*SigningAdoptionResult, error) {
	if m.signingKeys == nil || SigningKeyStoreIsClusterAtomic(m.signingKeys) {
		return nil, ErrSigningAdoptionUnavailable
	}
	result := &SigningAdoptionResult{}

	withKey, err := m.localSigningCertsWithKey()
	if err != nil {
		return nil, err
	}
	if len(withKey) == 0 {
		return result, nil // nothing local to adopt or remove
	}

	cursor, err := m.cursor.LoadCursor(ctx)
	if err != nil {
		return nil, fmt.Errorf("load signing cursor: %w", err)
	}
	cursorSet := cursor != nil && cursor.CurrentSerial != ""

	var currentSerial string
	if cursorSet {
		currentSerial = cursor.CurrentSerial
	} else {
		cur, err := m.localCurrentSigningCert()
		if err != nil {
			// Only expired keys remain: they are still removed below, once the
			// node resolves a shared identity, which it cannot without one.
			return result, nil
		}
		currentSerial = cur.SerialNumber
	}

	candidates := []string{currentSerial}
	if cursorSet && cursor.RotatingSerial != "" && cursor.RetiredAt == nil {
		candidates = append(candidates, cursor.RotatingSerial)
	}

	var toAdopt []*Certificate
	adopted := make(map[string]bool)
	for i, serial := range candidates {
		local := withKey[serial]
		if local == nil {
			if _, gerr := m.signingKeys.GetSigningKey(ctx, serial); gerr == nil {
				continue // already stored and no local key left to compare or remove
			} else if !errors.Is(gerr, certinterfaces.ErrSigningKeyNotFound) {
				return nil, fmt.Errorf("read stored signing key %s: %w", logging.SanitizeLogValue(serial), gerr)
			}
			if i == 0 {
				m.refuseAdoption(result, serial, "the current signing serial has no local key and is not in the store")
				return result, nil
			}
			continue // an overlap serial this node never held a key for
		}
		x509Cert, verr := m.validateSigningMaterial(local.CertificatePEM, local.PrivateKeyPEM)
		if verr == nil && x509Cert.SerialNumber.String() != serial {
			verr = fmt.Errorf("certificate serial does not match its storage entry")
		}
		if verr != nil {
			m.refuseAdoption(result, serial, verr.Error())
			if i == 0 {
				return result, nil // the current serial is all or nothing
			}
			continue
		}
		toAdopt = append(toAdopt, local)
		adopted[serial] = true
	}

	for _, local := range toAdopt {
		if err := m.signingKeys.PutSigningKey(ctx, signingMaterialFromCertificate(local)); err != nil {
			return nil, fmt.Errorf("store signing key %s: %w", logging.SanitizeLogValue(local.SerialNumber), err)
		}
	}
	if !cursorSet {
		if _, _, err := m.cursor.SeedCursorIfAbsent(ctx, currentSerial); err != nil {
			return nil, fmt.Errorf("seed signing cursor: %w", err)
		}
	}

	for _, local := range toAdopt {
		stored, err := m.signingKeys.GetSigningKey(ctx, local.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("read back signing key %s: %w", logging.SanitizeLogValue(local.SerialNumber), err)
		}
		record, merr := marshalSigningRecord(stored)
		if merr != nil {
			return nil, fmt.Errorf("read-back of signing key %s is unreadable", logging.SanitizeLogValue(local.SerialNumber))
		}
		if err := sameSigningMaterial(record, signingMaterialFromCertificate(local)); err != nil {
			return nil, fmt.Errorf("read-back of signing key %s does not match the local material", logging.SanitizeLogValue(local.SerialNumber))
		}
	}

	m.invalidateSigningCache()
	mode, _, err := m.resolveSigningIdentity(ctx)
	if err != nil {
		return nil, err
	}
	after, err := m.cursor.LoadCursor(ctx)
	if err != nil {
		return nil, fmt.Errorf("load signing cursor: %w", err)
	}
	if mode != SigningIdentityShared || after == nil || after.CurrentSerial != currentSerial {
		return nil, fmt.Errorf("signing identity is not shared on serial %s after adoption; local keys kept", logging.SanitizeLogValue(currentSerial))
	}

	now := time.Now()
	for serial, local := range withKey {
		expired := false
		if c, perr := ParseCertificateFromPEM(local.CertificatePEM); perr == nil {
			expired = now.After(c.NotAfter)
		}
		if !adopted[serial] && !expired {
			continue
		}
		if err := m.store.RemoveSigningKeyFile(serial); err != nil {
			return result, fmt.Errorf("remove local signing key %s: %w", logging.SanitizeLogValue(serial), err)
		}
		result.RemovedKeySerials = append(result.RemovedKeySerials, serial)
	}
	for _, local := range toAdopt {
		result.AdoptedSerials = append(result.AdoptedSerials, local.SerialNumber)
	}
	m.invalidateSigningCache()
	return result, nil
}

func (m *Manager) refuseAdoption(result *SigningAdoptionResult, serial, reason string) {
	result.RefusedSerials = append(result.RefusedSerials, SigningAdoptionRefusal{Serial: serial, Reason: reason})
	certLog().Warn("Refused to adopt local signing certificate",
		"serial", logging.SanitizeLogValue(serial),
		"reason", logging.SanitizeLogValue(reason))
}

// localSigningCertsWithKey returns the node-local signing certificates that still
// have a private key, keyed by serial.
func (m *Manager) localSigningCertsWithKey() (map[string]*Certificate, error) {
	infos, err := m.store.getCertificatesByType(CertificateTypeConfigSigning)
	if err != nil {
		return nil, fmt.Errorf("list local signing certificates: %w", err)
	}
	out := make(map[string]*Certificate)
	for _, info := range infos {
		c, err := m.store.GetCertificate(info.SerialNumber)
		if err != nil {
			continue
		}
		if len(c.PrivateKeyPEM) > 0 {
			out[c.SerialNumber] = c
		}
	}
	return out, nil
}

func signingMaterialFromCertificate(c *Certificate) *certinterfaces.SigningKeyMaterial {
	return &certinterfaces.SigningKeyMaterial{
		Serial:         c.SerialNumber,
		CertificatePEM: c.CertificatePEM,
		PrivateKeyPEM:  c.PrivateKeyPEM,
		IssuerChainPEM: c.IssuerChainPEM,
	}
}
