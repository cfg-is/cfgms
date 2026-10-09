// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ErrSigningKeyNotFound and ErrSigningMigrationPending re-export the
// pkg/cert/interfaces sentinels so callers need only this package.
var (
	ErrSigningKeyNotFound      = certinterfaces.ErrSigningKeyNotFound
	ErrSigningMigrationPending = certinterfaces.ErrSigningMigrationPending
)

// SigningIdentityMode says where a cluster-mode Manager's signing identity lives.
type SigningIdentityMode string

const (
	// SigningIdentityShared: the shared cursor's current serial resolves in the
	// key store. Every node signs with that one identity and no signing key is
	// written to node-local disk.
	SigningIdentityShared SigningIdentityMode = "shared"
	// SigningIdentityLegacyLocal: no shared entry resolves, but this node holds
	// its own signing certificate and key. Signing continues locally so a rolling
	// upgrade never interrupts it.
	SigningIdentityLegacyLocal SigningIdentityMode = "legacy_local"
	// SigningIdentityUnprovisioned: the cluster has no signing identity yet.
	SigningIdentityUnprovisioned SigningIdentityMode = "unprovisioned"
	// SigningIdentityNodeLocal: the Manager has no SigningKeyStore (single-node).
	SigningIdentityNodeLocal SigningIdentityMode = "node_local"
)

const (
	// signingResolveCacheTTL bounds how long a resolved shared signing identity is
	// reused. signature.DynamicSigner resolves on every Sign, so without it each
	// command would cost a cursor query and a vault read. A rotation by another
	// node is observed within this interval.
	signingResolveCacheTTL = 5 * time.Second

	// signingBootstrapWait bounds how long a node waits for the node that won the
	// bootstrap claim to publish the identity before failing closed.
	signingBootstrapWait = 30 * time.Second

	signingBootstrapPoll = 100 * time.Millisecond
)

type cachedSigningIdentity struct {
	cert      *Certificate
	expiresAt time.Time
}

func certLog() *logging.ModuleLogger { return logging.ForModule("cert") }

// AttachCloser hands the Manager a resource it must keep open for its lifetime and
// that Close releases — in cluster mode, the vault connection the SigningKeyStore
// reads through. Call it once, right after construction.
func (m *Manager) AttachCloser(c io.Closer) {
	m.closer = c
}

// Close releases the resource attached with AttachCloser. It is idempotent and a
// no-op when nothing is attached. Signing through a closed Manager fails closed.
func (m *Manager) Close() error {
	var err error
	m.closeOnce.Do(func() {
		if m.closer != nil {
			err = m.closer.Close()
		}
	})
	return err
}

// SigningIdentityMode reports where this Manager's signing identity lives. It
// reads the cursor and key store; a failed read is an error, never a guess.
func (m *Manager) SigningIdentityMode(ctx context.Context) (SigningIdentityMode, error) {
	if m.signingKeys == nil {
		return SigningIdentityNodeLocal, nil
	}
	mode, _, err := m.resolveSigningIdentity(ctx)
	return mode, err
}

// resolveSigningIdentity returns the mode and, for Shared, the stored material.
func (m *Manager) resolveSigningIdentity(ctx context.Context) (SigningIdentityMode, *certinterfaces.SigningKeyMaterial, error) {
	cursor, err := m.cursor.LoadCursor(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("load signing cursor: %w", err)
	}
	if cursor != nil && cursor.CurrentSerial != "" {
		mat, err := m.signingKeys.GetSigningKey(ctx, cursor.CurrentSerial)
		if err == nil {
			return SigningIdentityShared, mat, nil
		}
		if !errors.Is(err, certinterfaces.ErrSigningKeyNotFound) {
			// An unreadable store is not an absent identity: no fallback.
			return "", nil, fmt.Errorf("resolve shared signing identity: %w", err)
		}
	}
	local, err := m.hasLocalSigningKey()
	if err != nil {
		return "", nil, err
	}
	if local {
		return SigningIdentityLegacyLocal, nil, nil
	}
	return SigningIdentityUnprovisioned, nil, nil
}

// hasLocalSigningKey reports whether the node-local store holds a config-signing
// certificate together with its private key.
func (m *Manager) hasLocalSigningKey() (bool, error) {
	infos, err := m.store.getCertificatesByType(CertificateTypeConfigSigning)
	if err != nil {
		return false, fmt.Errorf("check for local config signing certificates: %w", err)
	}
	for _, info := range infos {
		c, err := m.store.GetCertificate(info.SerialNumber)
		if err != nil {
			continue
		}
		if len(c.PrivateKeyPEM) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func certificateFromSigningMaterial(mat *certinterfaces.SigningKeyMaterial) (*Certificate, error) {
	x509Cert, err := ParseCertificateFromPEM(mat.CertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("parse shared signing certificate: %w", err)
	}
	if x509Cert.SerialNumber.String() != mat.Serial {
		return nil, fmt.Errorf("shared signing material serial does not match its certificate")
	}
	sum := sha256.Sum256(x509Cert.Raw)
	now := time.Now()
	return &Certificate{
		Type:           CertificateTypeConfigSigning,
		CommonName:     x509Cert.Subject.CommonName,
		SerialNumber:   mat.Serial,
		CreatedAt:      x509Cert.NotBefore,
		ExpiresAt:      x509Cert.NotAfter,
		IsValid:        now.After(x509Cert.NotBefore) && now.Before(x509Cert.NotAfter),
		CertificatePEM: mat.CertificatePEM,
		IssuerChainPEM: mat.IssuerChainPEM,
		PrivateKeyPEM:  mat.PrivateKeyPEM,
		Fingerprint:    hex.EncodeToString(sum[:]),
		Issuer:         x509Cert.Issuer.CommonName,
	}, nil
}

// persistSharedCertificate records the public half of a shared signing
// certificate in the node-local store so trust-path listings see it. The private
// key is stripped first: in Shared mode it exists only in process memory.
func (m *Manager) persistSharedCertificate(c *Certificate) error {
	pub := *c
	pub.PrivateKeyPEM = nil
	if err := m.store.StoreCertificate(&pub); err != nil {
		return fmt.Errorf("store shared signing certificate: %w", err)
	}
	return nil
}

// currentClusterSigningCert is GetCurrentCertForPurpose(PurposeSigning) for a
// Manager with a SigningKeyStore.
func (m *Manager) currentClusterSigningCert(ctx context.Context) (*Certificate, error) {
	m.signingCacheMu.Lock()
	defer m.signingCacheMu.Unlock()

	if c := m.signingCache; c != nil && time.Now().Before(c.expiresAt) {
		out := *c.cert
		return &out, nil
	}
	m.signingCache = nil

	mode, mat, err := m.resolveSigningIdentity(ctx)
	if err != nil {
		return nil, err
	}
	switch mode {
	case SigningIdentityShared:
		c, err := certificateFromSigningMaterial(mat)
		if err != nil {
			return nil, err
		}
		if !c.IsValid {
			return nil, fmt.Errorf("shared signing certificate %s is not currently valid", logging.SanitizeLogValue(c.SerialNumber))
		}
		if _, err := m.store.GetCertificate(c.SerialNumber); err != nil {
			if err := m.persistSharedCertificate(c); err != nil {
				return nil, err
			}
		}
		m.signingCache = &cachedSigningIdentity{cert: c, expiresAt: time.Now().Add(m.signingCacheTTL())}
		out := *c
		return &out, nil
	case SigningIdentityLegacyLocal:
		c, err := m.localCurrentSigningCert()
		if err != nil {
			return nil, err
		}
		m.signingCache = &cachedSigningIdentity{cert: c, expiresAt: time.Now().Add(m.signingCacheTTL())}
		out := *c
		return &out, nil
	default:
		return nil, fmt.Errorf("no cluster signing identity has been provisioned")
	}
}

func (m *Manager) signingCacheTTL() time.Duration {
	if m.signingCacheTTLOverride != nil {
		return *m.signingCacheTTLOverride
	}
	return signingResolveCacheTTL
}

func (m *Manager) invalidateSigningCache() {
	m.signingCacheMu.Lock()
	m.signingCache = nil
	m.signingCacheMu.Unlock()
}

// localCurrentSigningCert is the node-local path: newest valid signing
// certificate that still has its key.
func (m *Manager) localCurrentSigningCert() (*Certificate, error) {
	infos, err := m.store.getCertificatesByType(CertificateTypeConfigSigning)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certificates for purpose %s: %w", PurposeSigning, err)
	}
	for _, info := range infos {
		if !info.IsValid {
			continue
		}
		c, err := m.store.GetCertificate(info.SerialNumber)
		if err != nil || len(c.PrivateKeyPEM) == 0 {
			continue
		}
		return c, nil
	}
	return nil, fmt.Errorf("no valid certificate found for purpose %s", PurposeSigning)
}

// ensureClusterSigningIdentity is EnsureSigningCertificate for a Manager with a
// SigningKeyStore.
func (m *Manager) ensureClusterSigningIdentity(signingCfg *SigningCertConfig) error {
	ctx := context.Background()
	mode, mat, err := m.resolveSigningIdentity(ctx)
	if err != nil {
		return err
	}
	switch mode {
	case SigningIdentityShared:
		return m.adoptSharedIdentity(mat)
	case SigningIdentityLegacyLocal:
		certLog().Warn("Cluster signing identity is in legacy node-local mode: signing with this node's own certificate until the shared identity is provisioned")
		return nil
	default:
		return m.bootstrapSharedSigning(ctx, signingCfg)
	}
}

func (m *Manager) adoptSharedIdentity(mat *certinterfaces.SigningKeyMaterial) error {
	c, err := certificateFromSigningMaterial(mat)
	if err != nil {
		return err
	}
	if err := m.persistSharedCertificate(c); err != nil {
		return err
	}
	m.invalidateSigningCache()
	return nil
}

// bootstrapSharedSigning provisions the cluster's first signing identity exactly
// once. Nodes racing on a fresh cluster arbitrate through a TTL-bounded claim in
// the key store: the winner generates, publishes and advances the cursor; losers
// wait for the cursor and resolve from the store, failing closed on timeout.
func (m *Manager) bootstrapSharedSigning(ctx context.Context, signingCfg *SigningCertConfig) error {
	claimer, ok := m.signingKeys.(certinterfaces.SigningBootstrapClaimer)
	if !ok {
		return fmt.Errorf("signing key store cannot arbitrate bootstrap; refusing to provision a signing identity")
	}
	if signingCfg == nil {
		signingCfg = &SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 1095, KeySize: 4096}
	}

	deadline := time.Now().Add(signingBootstrapWait)
	for {
		// A cursor that already names a serial means somebody else owns the
		// identity. Bootstrapping would demote that serial to rotating for every
		// other node, so resolve it or fail.
		if adopted, err := m.adoptCursorIdentity(ctx); err != nil || adopted {
			return err
		}

		won, err := claimer.ClaimSigningBootstrap(ctx)
		if err != nil {
			return err
		}
		if won {
			// Re-check under the claim: the cursor may have moved between the
			// check above and the claim.
			if adopted, err := m.adoptCursorIdentity(ctx); err != nil || adopted {
				return err
			}
			return m.generateSharedIdentity(ctx, signingCfg)
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for another node to provision the cluster signing identity")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(signingBootstrapPoll):
		}
	}
}

// adoptCursorIdentity adopts the identity the cursor names, if it names one.
// It reports false when the cursor is empty, and an error when the cursor names
// a serial the key store cannot resolve.
func (m *Manager) adoptCursorIdentity(ctx context.Context) (bool, error) {
	cursor, err := m.cursor.LoadCursor(ctx)
	if err != nil {
		return false, fmt.Errorf("load signing cursor: %w", err)
	}
	if cursor == nil || cursor.CurrentSerial == "" {
		return false, nil
	}
	mat, err := m.signingKeys.GetSigningKey(ctx, cursor.CurrentSerial)
	if err != nil {
		return false, fmt.Errorf("signing cursor names serial %s which is not resolvable here; not provisioning a new identity: %w",
			logging.SanitizeLogValue(cursor.CurrentSerial), err)
	}
	return true, m.adoptSharedIdentity(mat)
}

func (m *Manager) generateSharedIdentity(ctx context.Context, signingCfg *SigningCertConfig) error {
	c, err := m.ca.GenerateSigningCertificate(signingCfg)
	if err != nil {
		return fmt.Errorf("failed to generate config signing certificate: %w", err)
	}
	if err := m.signingKeys.PutSigningKey(ctx, &certinterfaces.SigningKeyMaterial{
		Serial:         c.SerialNumber,
		CertificatePEM: c.CertificatePEM,
		PrivateKeyPEM:  c.PrivateKeyPEM,
		IssuerChainPEM: c.IssuerChainPEM,
	}); err != nil {
		return fmt.Errorf("publish config signing certificate: %w", err)
	}
	// Last look before moving the cursor: a claim that outlived its TTL could have
	// let another node publish first, and a second transition would demote it.
	if adopted, err := m.adoptCursorIdentity(ctx); err != nil || adopted {
		return err
	}
	if _, err := m.cursor.TransitionCursor(ctx, c.SerialNumber, 0, false); err != nil {
		return fmt.Errorf("transition signing cursor: %w", err)
	}
	certLog().Info("Provisioned cluster signing identity", "serial", logging.SanitizeLogValue(c.SerialNumber))
	if err := m.persistSharedCertificate(c); err != nil {
		return err
	}
	m.invalidateSigningCache()
	return nil
}

// rotateClusterSigningCertificate is rotateSigningCertificate for a Manager with
// a SigningKeyStore. The sequence is: claim the cluster-wide rotation, generate,
// store the key create-if-absent, transition the shared cursor, release the claim.
// The claim precedes generation so concurrent rotations never each generate and
// store a key. A crash between the store write and the cursor transition leaves
// an unreferenced key in the store; it is harmless (the cursor never names it)
// and is not swept.
func (m *Manager) rotateClusterSigningCertificate(ctx context.Context, overlapWindowDays int, force bool) (*Certificate, error) {
	mode, _, err := m.resolveSigningIdentity(ctx)
	if err != nil {
		return nil, err
	}
	switch mode {
	case SigningIdentityShared:
	case SigningIdentityLegacyLocal:
		return nil, fmt.Errorf("%w: signing rotation is unavailable until this cluster moves to the shared signing identity", ErrSigningMigrationPending)
	default:
		return nil, fmt.Errorf("no cluster signing identity has been provisioned; nothing to rotate")
	}

	claimer, ok := m.signingKeys.(certinterfaces.SigningRotationClaimer)
	if !ok {
		return nil, fmt.Errorf("signing key store cannot arbitrate rotation; refusing to rotate")
	}
	won, err := claimer.ClaimSigningRotation(ctx)
	if err != nil {
		return nil, err
	}
	if !won {
		return nil, fmt.Errorf("%w: another node holds the cluster rotation claim", ErrSigningRotationInProgress)
	}
	defer func() {
		// The claim has a TTL, so a failed release only delays the next rotation.
		if rerr := claimer.ReleaseSigningRotation(context.WithoutCancel(ctx)); rerr != nil {
			certLog().Warn("Failed to release signing rotation claim", "error", logging.SanitizeLogValue(rerr.Error()))
		}
	}()

	if !force {
		if err := m.checkRotationNotInProgress(ctx); err != nil {
			return nil, err
		}
	}

	// Seeding is a no-op in Shared mode: the cursor already names the current serial.
	if err := m.seedSigningCursor(ctx); err != nil {
		return nil, err
	}

	newCert, err := m.ca.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		ValidityDays: 1095,
		KeySize:      4096,
	})
	if err != nil {
		return nil, fmt.Errorf("generate signing certificate: %w", err)
	}
	if err := m.signingKeys.PutSigningKey(ctx, &certinterfaces.SigningKeyMaterial{
		Serial:         newCert.SerialNumber,
		CertificatePEM: newCert.CertificatePEM,
		PrivateKeyPEM:  newCert.PrivateKeyPEM,
		IssuerChainPEM: newCert.IssuerChainPEM,
	}); err != nil {
		return nil, fmt.Errorf("publish signing certificate: %w", err)
	}
	if _, err := m.cursor.TransitionCursor(ctx, newCert.SerialNumber, overlapWindowDays, force); err != nil {
		return nil, fmt.Errorf("transition signing cursor: %w", err)
	}
	// The rotation is committed; the node-local public copy is a convenience for
	// trust-path listings and is re-created on the next resolve if this fails.
	if err := m.persistSharedCertificate(newCert); err != nil {
		certLog().Warn("Rotated signing certificate could not be recorded locally", "error", logging.SanitizeLogValue(err.Error()))
	}
	m.invalidateSigningCache()
	return newCert, nil
}

// exportSharedSigningCertificate serves ExportCertificate for a serial held in
// the key store. handled is false when the serial is not a shared signing
// identity and the node-local path should answer.
func (m *Manager) exportSharedSigningCertificate(serial string, includeKey, includeChain bool) (certPEM, keyPEM []byte, handled bool, err error) {
	if local, lerr := m.store.GetCertificate(serial); lerr == nil && local.Type != CertificateTypeConfigSigning {
		return nil, nil, false, nil
	}
	ctx := context.Background()
	mat, gerr := m.signingKeys.GetSigningKey(ctx, serial)
	if gerr != nil {
		if errors.Is(gerr, certinterfaces.ErrSigningKeyNotFound) {
			return nil, nil, false, nil
		}
		if includeKey {
			return nil, nil, true, fmt.Errorf("failed to get certificate: %w", gerr)
		}
		// A certificate-only export needs no secret: the local store keeps cert.pem.
		return nil, nil, false, nil
	}
	certPEM = mat.CertificatePEM
	if includeChain && len(mat.IssuerChainPEM) > 0 {
		certPEM = append(append([]byte{}, certPEM...), mat.IssuerChainPEM...)
	}
	if includeKey {
		keyPEM = mat.PrivateKeyPEM
	}
	return certPEM, keyPEM, true, nil
}

// allValidClusterSigningCertificates is GetAllValidSigningCertificates for a
// Manager with a SigningKeyStore. Serials the cursor names are resolved from the
// key store (public half only) with the local store as a fallback for serials
// that predate the shared identity.
func (m *Manager) allValidClusterSigningCertificates(ctx context.Context) ([]*CertificateInfo, error) {
	cursor, err := m.cursor.LoadCursor(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing cursor: %w", err)
	}
	if cursor == nil || cursor.CurrentSerial == "" {
		return m.GetAllValidCertificatesForPurpose(PurposeSigning)
	}

	allowed := []string{cursor.CurrentSerial}
	if cursor.RotatingSerial != "" {
		overlap := time.Duration(cursor.OverlapWindowDays) * 24 * time.Hour
		if time.Since(cursor.RotatedAt) < overlap {
			allowed = append(allowed, cursor.RotatingSerial)
		}
	}

	local, err := m.GetAllValidCertificatesForPurpose(PurposeSigning)
	if err != nil {
		return nil, err
	}
	localBySerial := make(map[string]*CertificateInfo, len(local))
	for _, info := range local {
		localBySerial[info.SerialNumber] = info
	}

	result := make([]*CertificateInfo, 0, len(allowed))
	for _, serial := range allowed {
		mat, err := m.signingKeys.GetSigningKey(ctx, serial)
		switch {
		case err == nil:
			c, cerr := certificateFromSigningMaterial(mat)
			if cerr != nil {
				return nil, cerr
			}
			if c.IsValid {
				result = append(result, certificateInfoFor(c))
			}
		case errors.Is(err, certinterfaces.ErrSigningKeyNotFound):
			if info, ok := localBySerial[serial]; ok {
				result = append(result, info)
			}
		default:
			return nil, fmt.Errorf("resolve signing certificate %s: %w", logging.SanitizeLogValue(serial), err)
		}
	}
	return result, nil
}

func certificateInfoFor(c *Certificate) *CertificateInfo {
	days := int(time.Until(c.ExpiresAt).Hours() / 24)
	return &CertificateInfo{
		Type:                c.Type,
		CommonName:          c.CommonName,
		SerialNumber:        c.SerialNumber,
		CreatedAt:           c.CreatedAt,
		ExpiresAt:           c.ExpiresAt,
		IsValid:             c.IsValid,
		Fingerprint:         c.Fingerprint,
		Issuer:              c.Issuer,
		DaysUntilExpiration: days,
		NeedsRenewal:        days < 30,
	}
}
