// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/cfgis/cfgms/pkg/credential"
	"github.com/cfgis/cfgms/pkg/softauthn"
)

const (
	// authenticatorCredentialPrefix prefixes the credential-store name of every
	// software authenticator: <prefix><name> -> <prefix><name>.enc.
	authenticatorCredentialPrefix = "authenticator."

	// authenticatorRecordVersion is the only record layout this cfg reads. There is
	// no migration and no fallback to an older layout.
	authenticatorRecordVersion = 1

	// authenticatorProtectionStore means the key is held in the encrypted
	// credential store. Windows non-exportable keys add "platform" later.
	authenticatorProtectionStore = "store"

	authenticatorCredentialIDLen = 32
)

// authenticatorNameRE bounds an authenticator name to characters that are safe in
// a file name, a terminal and a log line.
var authenticatorNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// authenticatorRecord is the versioned JSON document stored, encrypted, under the
// credential name authenticator.<name>. It deliberately has no AAGUID field: every
// response the authenticator makes carries softauthn.AAGUID.
type authenticatorRecord struct {
	Version       int    `json:"version"`
	Name          string `json:"name"`
	Label         string `json:"label,omitempty"`
	CredentialID  []byte `json:"credential_id"`
	KeyPKCS8      []byte `json:"key_pkcs8"`
	RPID          string `json:"rp_id"`
	Origin        string `json:"origin"`
	ControllerURL string `json:"controller_url"`
	CACertPEM     string `json:"ca_cert_pem,omitempty"`
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

// newAuthenticatorRecord generates a fresh P-256 key and credential ID for a new
// record. The record is not valid for storage until its binding fields are set
// and softauthn accepts them (see authenticator()).
func newAuthenticatorRecord(name string) (*authenticatorRecord, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authenticator key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticator key: %w", err)
	}
	credID := make([]byte, authenticatorCredentialIDLen)
	if _, err := rand.Read(credID); err != nil {
		return nil, fmt.Errorf("failed to generate credential id: %w", err)
	}
	return &authenticatorRecord{
		Version:      authenticatorRecordVersion,
		Name:         name,
		CredentialID: credID,
		KeyPKCS8:     der,
		UserHandle:   []byte{},
		Protection:   authenticatorProtectionStore,
	}, nil
}

// authenticator builds the softauthn authenticator the record describes. It never
// sets Config.AAGUID: nothing in the record, a flag, the environment or a config
// file can change the AAGUID a response carries.
func (r *authenticatorRecord) authenticator() (*softauthn.Authenticator, error) {
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
	a, err := softauthn.New(softauthn.Config{
		Signer:       signer,
		RPID:         r.RPID,
		Origin:       r.Origin,
		CredentialID: r.CredentialID,
		UserHandle:   r.UserHandle,
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
