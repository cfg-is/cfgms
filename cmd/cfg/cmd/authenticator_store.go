// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/cfgis/cfgms/pkg/credential"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/softauthn/tpmkey"
)

const (
	// authenticatorCredentialPrefix prefixes the credential-store name of every
	// software authenticator: <prefix><name> -> <prefix><name>.enc.
	authenticatorCredentialPrefix = "authenticator."

	// authenticatorRecordVersion is the only record layout this cfg reads. There is
	// no migration and no fallback to an older layout.
	authenticatorRecordVersion = 1

	// authenticatorProtectionStore means the key is held in the encrypted
	// credential store.
	authenticatorProtectionStore = "store"

	// authenticatorProtectionPlatform means the key is a non-exportable per-user
	// key in a platform key provider (Windows CNG). The record holds only its
	// provider and name, never key bytes.
	authenticatorProtectionPlatform = "platform"

	// authenticatorProtectionTPM means the key lives inside the host TPM. The
	// record holds only the TPM-wrapped key blobs, which are useless on any other
	// TPM, never key bytes. Only this protection can produce the TPM attestation a
	// root agent account requires.
	authenticatorProtectionTPM = "tpm"

	authenticatorCredentialIDLen = 32
)

// authenticatorNameRE bounds an authenticator name to characters that are safe in
// a file name, a terminal and a log line.
var authenticatorNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// authenticatorRecord is the versioned JSON document stored, encrypted, under the
// credential name authenticator.<name>. It deliberately has no AAGUID field: every
// response the authenticator makes carries softauthn.AAGUID.
type authenticatorRecord struct {
	Version      int    `json:"version"`
	Name         string `json:"name"`
	Label        string `json:"label,omitempty"`
	CredentialID []byte `json:"credential_id"`
	// KeyPKCS8 is the private key of a "store" record; empty for "platform" and "tpm".
	KeyPKCS8 []byte `json:"key_pkcs8,omitempty"`
	// KeyProvider and KeyName locate the key of a "platform" record.
	KeyProvider string `json:"key_provider,omitempty"`
	KeyName     string `json:"key_name,omitempty"`
	// KeyPublicBlob and KeyPrivateBlob are the marshalled TPM2B_PUBLIC and
	// TPM2B_PRIVATE of a "tpm" record's key, wrapped by the TPM that made it.
	KeyPublicBlob  []byte `json:"key_public_blob,omitempty"`
	KeyPrivateBlob []byte `json:"key_private_blob,omitempty"`
	RPID           string `json:"rp_id"`
	Origin         string `json:"origin"`
	ControllerURL  string `json:"controller_url"`
	CACertPEM      string `json:"ca_cert_pem,omitempty"`
	// UserHandle is empty until the authenticator is registered with a controller.
	UserHandle []byte `json:"user_handle"`
	Registered bool   `json:"registered"`
	Protection string `json:"protection"`
}

// authenticatorSummary is what list prints. It has no field that can carry key bytes.
type authenticatorSummary struct {
	Name          string `json:"name"`
	Label         string `json:"label,omitempty"`
	RPID          string `json:"rp_id"`
	Origin        string `json:"origin"`
	ControllerURL string `json:"controller_url"`
	CredentialID  string `json:"credential_id"`
	Registered    bool   `json:"registered"`
	Protection    string `json:"protection"`
	KeyProvider   string `json:"key_provider,omitempty"`
}

func (r *authenticatorRecord) summary() authenticatorSummary {
	return authenticatorSummary{
		Name:          r.Name,
		Label:         r.Label,
		RPID:          r.RPID,
		Origin:        r.Origin,
		ControllerURL: r.ControllerURL,
		CredentialID:  base64.RawURLEncoding.EncodeToString(r.CredentialID),
		Registered:    r.Registered,
		Protection:    r.Protection,
		KeyProvider:   r.KeyProvider,
	}
}

// validateAuthenticatorName checks name before it is joined into a credential name.
func validateAuthenticatorName(name string) error {
	if err := credential.ValidateCredentialName(name); err != nil {
		return fmt.Errorf("invalid authenticator name %q: %w", name, err)
	}
	if !authenticatorNameRE.MatchString(name) {
		return fmt.Errorf("invalid authenticator name %q: use 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	return nil
}

func authenticatorCredentialName(name string) string {
	return authenticatorCredentialPrefix + name
}

// newAuthenticatorRecordWithoutKey returns a new record with a fresh credential
// ID and no key yet. setStoreKey or setPlatformKey gives it one.
func newAuthenticatorRecordWithoutKey(name string) (*authenticatorRecord, error) {
	credID := make([]byte, authenticatorCredentialIDLen)
	if _, err := rand.Read(credID); err != nil {
		return nil, fmt.Errorf("failed to generate credential id: %w", err)
	}
	return &authenticatorRecord{
		Version:      authenticatorRecordVersion,
		Name:         name,
		CredentialID: credID,
		UserHandle:   []byte{},
	}, nil
}

// newAuthenticatorRecord generates a fresh credential ID and a P-256 key held in
// the credential store. The record is not valid for storage until its binding
// fields are set and softauthn accepts them (see authenticator()).
func newAuthenticatorRecord(name string) (*authenticatorRecord, error) {
	rec, err := newAuthenticatorRecordWithoutKey(name)
	if err != nil {
		return nil, err
	}
	if err := rec.setStoreKey(); err != nil {
		return nil, err
	}
	return rec, nil
}

// setStoreKey generates a P-256 key and keeps it, PKCS#8-encoded, in the record.
func (r *authenticatorRecord) setStoreKey() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate authenticator key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal authenticator key: %w", err)
	}
	r.KeyPKCS8, r.KeyProvider, r.KeyName = der, "", ""
	r.Protection = authenticatorProtectionStore
	return nil
}

// createUserKey creates the platform key. Tests replace it to make the platform
// providers report ErrUserKeyUnavailable on a host where they work.
var createUserKey = identity.CreateUserKey

// setPlatformKey creates a non-exportable per-user key in the platform key
// provider and records where it is. The error wraps
// identity.ErrUserKeyUnavailable when no provider can hold one.
func (r *authenticatorRecord) setPlatformKey() error {
	s, err := createUserKey()
	if err != nil {
		return fmt.Errorf("failed to create platform key: %w", err)
	}
	r.KeyPKCS8, r.KeyProvider, r.KeyName = nil, s.Provider(), s.KeyName()
	r.Protection = authenticatorProtectionPlatform
	return nil
}

// openAuthenticatorTPM opens the host TPM. Tests replace it to supply a software
// TPM, or a failure on a host that has one.
var openAuthenticatorTPM = tpmkey.OpenDevice

// errTPMKeyRequirement explains why a TPM key was refused. A root agent account
// requires a TPM-held key, so there is no fallback to another protection.
func errTPMKeyRequirement(cause error) error {
	return fmt.Errorf("--key-provider tpm needs a usable TPM 2.0 with an endorsement key certificate in NV storage, "+
		"and this host has none: %w. A root agent account requires a key held in a TPM, so no software key was "+
		"created and nothing was stored", cause)
}

// setTPMKey creates the credential key inside the host TPM and records its
// wrapped blobs. It refuses, creating nothing, when no TPM can be opened or the
// TPM has no readable EK certificate (without one it can never attest).
func (r *authenticatorRecord) setTPMKey() error {
	t, err := openAuthenticatorTPM()
	if err != nil {
		return errTPMKeyRequirement(err)
	}
	defer func() { _ = t.Close() }()
	if err := tpmkey.HasEKCertificate(t); err != nil {
		return errTPMKeyRequirement(err)
	}
	blobs, _, err := tpmkey.Create(t)
	if err != nil {
		return errTPMKeyRequirement(err)
	}
	r.KeyPKCS8, r.KeyProvider, r.KeyName = nil, "", ""
	r.KeyPublicBlob, r.KeyPrivateBlob = blobs.Public, blobs.Private
	r.Protection = authenticatorProtectionTPM
	return nil
}

// tpmKeySigner signs with the record's TPM key. It opens the TPM for each
// signature, so it holds no device handle between uses.
type tpmKeySigner struct {
	name  string
	blobs tpmkey.Blobs
	pub   *ecdsa.PublicKey
}

func (s *tpmKeySigner) Public() crypto.PublicKey { return s.pub }

func (s *tpmKeySigner) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t, err := openAuthenticatorTPM()
	if err != nil {
		return nil, fmt.Errorf("authenticator %q: open TPM: %w", s.name, err)
	}
	defer func() { _ = t.Close() }()
	key, err := tpmkey.Open(t, s.blobs)
	if err != nil {
		return nil, fmt.Errorf("authenticator %q: %w", s.name, err)
	}
	return key.Sign(rnd, digest, opts)
}

// tpmBlobs returns the key blobs of a "tpm" record.
func (r *authenticatorRecord) tpmBlobs() (tpmkey.Blobs, error) {
	if len(r.KeyPublicBlob) == 0 || len(r.KeyPrivateBlob) == 0 {
		return tpmkey.Blobs{}, fmt.Errorf("authenticator %q: the stored TPM key blobs are missing; delete it with "+
			"'cfg authenticator delete %s --force' and create it again", r.Name, r.Name)
	}
	return tpmkey.Blobs{Public: r.KeyPublicBlob, Private: r.KeyPrivateBlob}, nil
}

// deletePlatformKey deletes the platform key of a "platform" record. It does
// nothing for any other record.
func (r *authenticatorRecord) deletePlatformKey() error {
	if r.Protection != authenticatorProtectionPlatform {
		return nil
	}
	if err := identity.DeleteUserKey(r.KeyProvider, r.KeyName); err != nil {
		return fmt.Errorf("authenticator %q: %w", r.Name, err)
	}
	return nil
}

// signer returns the record's credential key as a crypto.Signer.
func (r *authenticatorRecord) signer() (crypto.Signer, error) {
	switch r.Protection {
	case authenticatorProtectionStore:
		key, err := x509.ParsePKCS8PrivateKey(r.KeyPKCS8)
		if err != nil {
			// Deliberately not wrapping err: parser errors are not key material, but
			// the message needs no detail beyond which record is unusable.
			return nil, fmt.Errorf("authenticator %q: stored key is not a valid PKCS#8 private key", r.Name)
		}
		signer, ok := key.(*ecdsa.PrivateKey)
		if !ok || signer.Curve != elliptic.P256() {
			return nil, fmt.Errorf("authenticator %q: stored key is not an ECDSA P-256 key", r.Name)
		}
		return signer, nil
	case authenticatorProtectionPlatform:
		s, err := identity.OpenUserKey(r.KeyProvider, r.KeyName)
		if err != nil {
			return nil, fmt.Errorf("authenticator %q: %w", r.Name, err)
		}
		return s, nil
	case authenticatorProtectionTPM:
		blobs, err := r.tpmBlobs()
		if err != nil {
			return nil, err
		}
		pub, err := tpmkey.PublicKey(blobs.Public)
		if err != nil {
			return nil, fmt.Errorf("authenticator %q: stored TPM key is not a P-256 key: %w", r.Name, err)
		}
		return &tpmKeySigner{name: r.Name, blobs: blobs, pub: pub}, nil
	default:
		return nil, fmt.Errorf("authenticator %q: unknown protection %q; delete it with "+
			"'cfg authenticator delete %s --force' and create it again", r.Name, r.Protection, r.Name)
	}
}

// checkBinding asks softauthn whether the record's RP ID and origin are a valid
// pair, using a throwaway in-memory key, so a bad binding is refused before any
// key is created in a platform provider.
func (r *authenticatorRecord) checkBinding() error {
	probe, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate probe key: %w", err)
	}
	_, err = r.authenticatorWith(probe, nil)
	return err
}

// authenticator builds the softauthn authenticator the record describes. It never
// sets Config.AAGUID: nothing in the record, a flag, the environment or a config
// file can change the AAGUID a response carries.
func (r *authenticatorRecord) authenticator() (*softauthn.Authenticator, error) {
	signer, err := r.signer()
	if err != nil {
		return nil, err
	}
	return r.authenticatorWith(signer, nil)
}

// authenticatorWith builds the authenticator over signer. A non-nil attester
// makes its registration a TPM attestation; every other caller passes nil.
func (r *authenticatorRecord) authenticatorWith(signer crypto.Signer, attester softauthn.Attester) (*softauthn.Authenticator, error) {
	a, err := softauthn.New(softauthn.Config{
		Signer:       signer,
		RPID:         r.RPID,
		Origin:       r.Origin,
		CredentialID: r.CredentialID,
		UserHandle:   r.UserHandle,
		Attester:     attester,
	})
	if err != nil {
		return nil, fmt.Errorf("authenticator %q: %w", r.Name, err)
	}
	return a, nil
}

// errAuthenticatorVersion names the unsupported version and the remedy.
func errAuthenticatorVersion(name string, version int) error {
	return fmt.Errorf("authenticator %q: unsupported record version %d (this cfg reads version %d only; "+
		"there is no migration: run 'cfg authenticator delete %s --force' and create it again)",
		name, version, authenticatorRecordVersion, name)
}

func decodeAuthenticatorRecord(name string, raw []byte) (*authenticatorRecord, error) {
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("authenticator %q: stored record is not valid; delete it with "+
			"'cfg authenticator delete %s --force' and create it again", name, name)
	}
	if header.Version != authenticatorRecordVersion {
		return nil, errAuthenticatorVersion(name, header.Version)
	}
	var rec authenticatorRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("authenticator %q: stored record is not valid; delete it with "+
			"'cfg authenticator delete %s --force' and create it again", name, name)
	}
	if rec.Name != name {
		return nil, fmt.Errorf("authenticator %q: stored record names %q; delete it with "+
			"'cfg authenticator delete %s --force' and create it again", name, rec.Name, name)
	}
	return &rec, nil
}

// loadAuthenticatorRecord loads and decodes the record for name.
func loadAuthenticatorRecord(ctx context.Context, store *CredentialStore, name string) (*authenticatorRecord, error) {
	if err := validateAuthenticatorName(name); err != nil {
		return nil, err
	}
	raw, err := store.Load(ctx, authenticatorCredentialName(name))
	if err != nil {
		return nil, fmt.Errorf("authenticator %q: %w", name, err)
	}
	return decodeAuthenticatorRecord(name, raw)
}

// saveAuthenticatorRecord encrypts rec into the credential store, replacing any
// existing record. Create guards against overwriting; this does not.
func saveAuthenticatorRecord(ctx context.Context, store *CredentialStore, rec *authenticatorRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to encode authenticator record: %w", err)
	}
	if err := store.Store(ctx, authenticatorCredentialName(rec.Name), raw); err != nil {
		return fmt.Errorf("failed to store authenticator: %w", err)
	}
	return nil
}

// listAuthenticatorRecords loads every stored authenticator, sorted by name. One
// record that cannot be read fails the whole listing with that record's error.
func listAuthenticatorRecords(ctx context.Context, store *CredentialStore) ([]*authenticatorRecord, error) {
	names, err := store.List(ctx, authenticatorCredentialPrefix)
	if err != nil {
		return nil, err
	}
	recs := make([]*authenticatorRecord, 0, len(names))
	for _, credName := range names {
		name := credName[len(authenticatorCredentialPrefix):]
		if name == "" {
			continue
		}
		rec, err := loadAuthenticatorRecord(ctx, store, name)
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// authenticatorExists reports whether a record file for name is present, readable
// or not.
func authenticatorExists(ctx context.Context, store *CredentialStore, name string) (bool, error) {
	if err := validateAuthenticatorName(name); err != nil {
		return false, err
	}
	return store.Exists(ctx, authenticatorCredentialName(name))
}

var errAuthenticatorNotFound = errors.New("authenticator not found")

func notFoundAuthenticator(name string) error {
	return fmt.Errorf("%w: %q (see 'cfg authenticator list')", errAuthenticatorNotFound, name)
}
