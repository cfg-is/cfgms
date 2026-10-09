// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

const (
	// signingKeySharedDir holds one secret per signing serial, under the
	// SigningKeyStore's tenant. It is a separate path from the CA material so a
	// vault policy can grant nodes read and create on it without touching the CA.
	signingKeySharedDir = "config-signing/shared"

	// signingKeyClaimBootstrapKey is the bootstrap claim record.
	signingKeyClaimBootstrapKey = "config-signing/claims/bootstrap"

	// signingKeyClaimRotationKey is the rotation claim record.
	signingKeyClaimRotationKey = "config-signing/claims/rotation"

	// signingRotationClaimTTL bounds how long a rotation claim blocks other
	// nodes. It must cover RSA-4096 key generation plus the key store write and
	// the cursor transition.
	signingRotationClaimTTL = 2 * time.Minute

	// signingBootstrapClaimTTL bounds how long a bootstrap claim blocks other
	// nodes. It must comfortably exceed RSA-4096 key generation.
	signingBootstrapClaimTTL = 2 * time.Minute

	signingKeyCreatedBy = "cfgms-controller-signing"
)

// signingSerialPattern restricts serials to characters that are safe as a vault
// path component, so a serial can never traverse out of the signing-key prefix.
var signingSerialPattern = regexp.MustCompile(`^[0-9A-Za-z_-]{1,128}$`)

// secretStoreSigningKeyStore is the pkg/secrets-backed SigningKeyStore.
type secretStoreSigningKeyStore struct {
	store    secretsinterfaces.SecretStore
	tenantID string
	prefix   string
}

var (
	_ certinterfaces.SigningKeyStore         = (*secretStoreSigningKeyStore)(nil)
	_ certinterfaces.SigningBootstrapClaimer = (*secretStoreSigningKeyStore)(nil)
	_ certinterfaces.SigningRotationClaimer  = (*secretStoreSigningKeyStore)(nil)
)

// NewSecretStoreSigningKeyStore returns a SigningKeyStore that keeps signing
// material in store under tenantID. prefix is prepended to the fixed key layout
// ("config-signing/shared/<serial>"); pass "" for the default. It fails when
// store's CompareAndSwapSecret is not atomic across controller nodes, because
// create-if-absent is what keeps two nodes from publishing different identities.
func NewSecretStoreSigningKeyStore(store secretsinterfaces.SecretStore, tenantID, prefix string) (certinterfaces.SigningKeyStore, error) {
	if store == nil {
		return nil, fmt.Errorf("secret store is required")
	}
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if !secretsinterfaces.CompareAndSwapIsClusterAtomic(store) {
		return nil, fmt.Errorf("signing key store requires a secret store whose compare-and-swap is atomic across controller nodes")
	}
	return &secretStoreSigningKeyStore{store: store, tenantID: tenantID, prefix: strings.Trim(prefix, "/")}, nil
}

func (s *secretStoreSigningKeyStore) key(parts ...string) string {
	segments := make([]string, 0, len(parts)+1)
	if s.prefix != "" {
		segments = append(segments, s.prefix)
	}
	segments = append(segments, parts...)
	return path.Join(segments...)
}

func (s *secretStoreSigningKeyStore) serialKey(serial string) (string, error) {
	if !signingSerialPattern.MatchString(serial) {
		return "", fmt.Errorf("invalid signing certificate serial %q", logging.SanitizeLogValue(serial))
	}
	return s.key(signingKeySharedDir, serial), nil
}

// signingKeyRecord is the stored form: certificate, key and chain together.
type signingKeyRecord struct {
	Serial         string `json:"serial"`
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	IssuerChainPEM string `json:"issuer_chain_pem,omitempty"`
}

func (s *secretStoreSigningKeyStore) PutSigningKey(ctx context.Context, m *certinterfaces.SigningKeyMaterial) error {
	if m == nil || len(m.CertificatePEM) == 0 || len(m.PrivateKeyPEM) == 0 {
		return fmt.Errorf("signing key material requires a certificate and a private key")
	}
	if err := ValidateKeyPair(m.CertificatePEM, m.PrivateKeyPEM); err != nil {
		return fmt.Errorf("signing certificate and key do not match: %w", err)
	}
	x509Cert, err := ParseCertificateFromPEM(m.CertificatePEM)
	if err != nil {
		return fmt.Errorf("parse signing certificate: %w", err)
	}
	if x509Cert.SerialNumber.String() != m.Serial {
		return fmt.Errorf("signing material serial does not match its certificate")
	}
	key, err := s.serialKey(m.Serial)
	if err != nil {
		return err
	}
	value, err := marshalSigningRecord(m)
	if err != nil {
		return err
	}

	lookup := s.tenantID + "/" + key
	same := func(stored string) error { return sameSigningMaterial(stored, m) }

	if existing, err := s.store.GetSecret(ctx, lookup); err == nil {
		return same(existing.Value)
	}
	_, ok, err := s.store.CompareAndSwapSecret(ctx, lookup, 0, &secretsinterfaces.SecretRequest{
		Key:         key,
		Value:       value,
		TenantID:    s.tenantID,
		CreatedBy:   signingKeyCreatedBy,
		Description: "CFGMS config-signing certificate and key",
		Tags:        []string{"config_signing_key"},
	})
	if err != nil {
		return fmt.Errorf("store signing key: %s", logging.SanitizeLogValue(err.Error()))
	}
	if ok {
		return nil
	}
	existing, getErr := s.store.GetSecret(ctx, lookup)
	if getErr != nil {
		return fmt.Errorf("signing key for serial %s is already claimed but could not be read back: %s",
			logging.SanitizeLogValue(m.Serial), logging.SanitizeLogValue(getErr.Error()))
	}
	return same(existing.Value)
}

func (s *secretStoreSigningKeyStore) GetSigningKey(ctx context.Context, serial string) (*certinterfaces.SigningKeyMaterial, error) {
	key, err := s.serialKey(serial)
	if err != nil {
		return nil, err
	}
	secret, err := s.store.GetSecret(ctx, s.tenantID+"/"+key)
	if err != nil {
		if errors.Is(err, secretsinterfaces.ErrSecretNotFound) {
			return nil, fmt.Errorf("%w: serial %s", certinterfaces.ErrSigningKeyNotFound, logging.SanitizeLogValue(serial))
		}
		return nil, fmt.Errorf("read signing key for serial %s: %s",
			logging.SanitizeLogValue(serial), logging.SanitizeLogValue(err.Error()))
	}
	rec, err := unmarshalSigningRecord(secret.Value)
	if err != nil {
		return nil, fmt.Errorf("signing key record for serial %s is unreadable", logging.SanitizeLogValue(serial))
	}
	if rec.Serial != serial {
		return nil, fmt.Errorf("signing key record for serial %s names a different serial", logging.SanitizeLogValue(serial))
	}
	return &certinterfaces.SigningKeyMaterial{
		Serial:         rec.Serial,
		CertificatePEM: []byte(rec.CertificatePEM),
		PrivateKeyPEM:  []byte(rec.PrivateKeyPEM),
		IssuerChainPEM: []byte(rec.IssuerChainPEM),
	}, nil
}

func (s *secretStoreSigningKeyStore) ListSigningSerials(ctx context.Context) ([]string, error) {
	// The provider lists the direct children of a tenant path, so the shared
	// directory is addressed as a (sub)tenant.
	metas, err := s.store.ListSecrets(ctx, &secretsinterfaces.SecretFilter{
		TenantID: s.tenantID + "/" + s.key(signingKeySharedDir),
	})
	if err != nil {
		return nil, fmt.Errorf("list signing keys: %s", logging.SanitizeLogValue(err.Error()))
	}
	serials := make([]string, 0, len(metas))
	for _, meta := range metas {
		serial := path.Base(meta.Key)
		if signingSerialPattern.MatchString(serial) {
			serials = append(serials, serial)
		}
	}
	return serials, nil
}

// ClaimSigningBootstrap implements certinterfaces.SigningBootstrapClaimer.
func (s *secretStoreSigningKeyStore) ClaimSigningBootstrap(ctx context.Context) (bool, error) {
	key := s.key(signingKeyClaimBootstrapKey)
	_, ok, err := s.store.CompareAndSwapSecret(ctx, s.tenantID+"/"+key, 0, &secretsinterfaces.SecretRequest{
		Key:         key,
		Value:       "",
		TenantID:    s.tenantID,
		CreatedBy:   signingKeyCreatedBy,
		Description: "config-signing bootstrap claim",
		Tags:        []string{"config_signing_claim"},
		TTL:         signingBootstrapClaimTTL,
	})
	if err != nil {
		return false, fmt.Errorf("claim signing bootstrap: %s", logging.SanitizeLogValue(err.Error()))
	}
	return ok, nil
}

// ClaimSigningRotation implements certinterfaces.SigningRotationClaimer.
func (s *secretStoreSigningKeyStore) ClaimSigningRotation(ctx context.Context) (bool, error) {
	key := s.key(signingKeyClaimRotationKey)
	_, ok, err := s.store.CompareAndSwapSecret(ctx, s.tenantID+"/"+key, 0, &secretsinterfaces.SecretRequest{
		Key:         key,
		Value:       "",
		TenantID:    s.tenantID,
		CreatedBy:   signingKeyCreatedBy,
		Description: "config-signing rotation claim",
		Tags:        []string{"config_signing_claim"},
		TTL:         signingRotationClaimTTL,
	})
	if err != nil {
		return false, fmt.Errorf("claim signing rotation: %s", logging.SanitizeLogValue(err.Error()))
	}
	return ok, nil
}

// ReleaseSigningRotation implements certinterfaces.SigningRotationClaimer.
func (s *secretStoreSigningKeyStore) ReleaseSigningRotation(ctx context.Context) error {
	err := s.store.DeleteSecret(ctx, s.tenantID+"/"+s.key(signingKeyClaimRotationKey))
	if err != nil && !errors.Is(err, secretsinterfaces.ErrSecretNotFound) {
		return fmt.Errorf("release signing rotation claim: %s", logging.SanitizeLogValue(err.Error()))
	}
	return nil
}

func marshalSigningRecord(m *certinterfaces.SigningKeyMaterial) (string, error) {
	b, err := json.Marshal(&signingKeyRecord{
		Serial:         m.Serial,
		CertificatePEM: string(m.CertificatePEM),
		PrivateKeyPEM:  string(m.PrivateKeyPEM),
		IssuerChainPEM: string(m.IssuerChainPEM),
	})
	if err != nil {
		return "", fmt.Errorf("encode signing key record")
	}
	return string(b), nil
}

func unmarshalSigningRecord(value string) (*signingKeyRecord, error) {
	var rec signingKeyRecord
	if err := json.Unmarshal([]byte(value), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// sameSigningMaterial reports whether the stored record holds the same
// certificate, key and chain as want. Errors name certificate fingerprints
// only; key bytes never appear.
func sameSigningMaterial(stored string, want *certinterfaces.SigningKeyMaterial) error {
	rec, err := unmarshalSigningRecord(stored)
	if err != nil {
		return fmt.Errorf("signing key already stored for serial %s is unreadable", logging.SanitizeLogValue(want.Serial))
	}
	if err := sameCertificatePEM([]byte(rec.CertificatePEM), want.CertificatePEM); err != nil {
		return fmt.Errorf("refusing to overwrite the signing key already stored for serial %s: %w",
			logging.SanitizeLogValue(want.Serial), err)
	}
	if err := samePrivateKeyPEM([]byte(rec.PrivateKeyPEM), want.PrivateKeyPEM); err != nil {
		return fmt.Errorf("refusing to overwrite the signing key already stored for serial %s: %w",
			logging.SanitizeLogValue(want.Serial), err)
	}
	if (len(rec.IssuerChainPEM) > 0) != (len(want.IssuerChainPEM) > 0) {
		return fmt.Errorf("refusing to overwrite the signing key already stored for serial %s: issuer chain differs",
			logging.SanitizeLogValue(want.Serial))
	}
	if len(want.IssuerChainPEM) > 0 {
		if err := sameCertificateChainPEM([]byte(rec.IssuerChainPEM), want.IssuerChainPEM); err != nil {
			return fmt.Errorf("refusing to overwrite the signing key already stored for serial %s: %w",
				logging.SanitizeLogValue(want.Serial), err)
		}
	}
	return nil
}
