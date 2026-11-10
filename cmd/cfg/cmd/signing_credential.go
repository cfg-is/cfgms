// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cfgis/cfgms/pkg/credential"
)

// signingCredentialSelector is the --signing-credential flag value, shared by every
// command that signs an operator envelope and by `cfg credential request-signing-cert`.
// Empty means "derive the credential from the active connection".
var signingCredentialSelector string

const (
	// signingCredentialName is the legacy, connection-agnostic CredentialStore entry
	// the signing private key was stored under before credentials were scoped per
	// connection. It still signs when no session is active or when selected with
	// --signing-credential signing-key.
	signingCredentialName = "signing-key"

	// signingKeyPrefix prefixes the key name derived from a connection:
	// signing-key.<connection>.
	signingKeyPrefix = signingCredentialName + "."

	signingCertBase = "signing-cert"
)

// signingCredentialFlagUsage is the --signing-credential help text shared by every command that registers the flag.
const signingCredentialFlagUsage = "Signing credential to use (default: signing-key.<active connection>, or the legacy signing-key when no session is active)"

// signingCredentialRef identifies one signing credential: the CredentialStore entry
// holding the private key and the default location of the matching certificate.
type signingCredentialRef struct {
	// KeyName is the CredentialStore entry for the private key. It is also the value
	// to pass to --signing-credential to select this credential.
	KeyName string
	// CertPath is the default certificate path for KeyName.
	CertPath string
	// Connection is the active connection the name was derived from; empty when the
	// credential was selected explicitly or no session is active.
	Connection string
}

// signingCertFileName maps a key name to its default certificate file name. The
// legacy name keeps signing-cert.pem; signing-key.<x> pairs with signing-cert.<x>.pem
// so the derived and explicitly selected forms of one credential share a certificate;
// any other selector S uses signing-cert.S.pem.
func signingCertFileName(keyName string) string {
	switch {
	case keyName == signingCredentialName:
		return signingCertBase + ".pem"
	case strings.HasPrefix(keyName, signingKeyPrefix):
		return signingCertBase + "." + strings.TrimPrefix(keyName, signingKeyPrefix) + ".pem"
	default:
		return signingCertBase + "." + keyName + ".pem"
	}
}

func newSigningCredentialRef(keyName, connection string) (signingCredentialRef, error) {
	if err := credential.ValidateCredentialName(keyName); err != nil {
		return signingCredentialRef{}, fmt.Errorf("invalid signing credential name: %w", err)
	}
	configDir, err := userConfigDirFn()
	if err != nil {
		return signingCredentialRef{}, fmt.Errorf("cannot determine user config directory: %w", err)
	}
	return signingCredentialRef{
		KeyName:    keyName,
		CertPath:   filepath.Join(configDir, "cfgms", signingCertFileName(keyName)),
		Connection: connection,
	}, nil
}

// resolveSigningCredentialRef picks the signing credential: the explicit
// --signing-credential selector, else signing-key.<active connection> when a live
// session exists, else (no session, e.g. bundle-only use) the legacy signing-key.
func resolveSigningCredentialRef() (signingCredentialRef, error) {
	if signingCredentialSelector != "" {
		return newSigningCredentialRef(signingCredentialSelector, "")
	}
	rec, err := loadSessionToken()
	if err != nil {
		return signingCredentialRef{}, fmt.Errorf("cannot determine the active connection: %w", err)
	}
	if rec == nil || rec.ConnectionName == "" {
		return newSigningCredentialRef(signingCredentialName, "")
	}
	return newSigningCredentialRef(signingKeyPrefix+rec.ConnectionName, rec.ConnectionName)
}

// missingError names the selector (or the derived name) and the
// command that creates the credential. There is never a second lookup under another name.
func (r signingCredentialRef) missingError(cause error) error {
	if r.Connection != "" {
		return fmt.Errorf("no signing credential %q for connection %q: run 'cfg credential request-signing-cert' to create it, "+
			"or select another with --signing-credential <name> (a legacy credential issued for this connection is used with "+
			"--signing-credential %s): %w", r.KeyName, r.Connection, signingCredentialName, cause)
	}
	return fmt.Errorf("no signing credential %q (--signing-credential %s): run 'cfg credential request-signing-cert --signing-credential %s' to create it: %w",
		r.KeyName, r.KeyName, r.KeyName, cause)
}

// certPathOverride returns the explicit certificate path (CFGMS_SIGNING_CERT) or the
// credential's default path.
func (r signingCredentialRef) certPathOverride() string {
	if p, ok := os.LookupEnv("CFGMS_SIGNING_CERT"); ok && p != "" {
		return p
	}
	return r.CertPath
}

// loadSigningCredential loads the private key and certificate PEM of the resolved
// credential and verifies they belong together.
func loadSigningCredential() (crypto.PrivateKey, []byte, error) {
	ref, err := resolveSigningCredentialRef()
	if err != nil {
		return nil, nil, err
	}
	credStore, err := newCredentialStore()
	if err != nil {
		return nil, nil, fmt.Errorf("credential store unavailable: %w", err)
	}
	keyPEM, err := credStore.Load(context.Background(), ref.KeyName)
	if err != nil {
		return nil, nil, ref.missingError(err)
	}
	privKey, err := parsePrivKeyFromPEM(string(keyPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse signing credential %q private key: %w", ref.KeyName, err)
	}
	certPath := ref.certPathOverride()
	certPEM, err := os.ReadFile(certPath) // #nosec G304 -- derived default location or an operator-set CFGMS_SIGNING_CERT path, not user/network input
	if err != nil {
		return nil, nil, fmt.Errorf("no signing certificate for credential %q at %s: run 'cfg credential request-signing-cert --signing-credential %s' to create it: %w",
			ref.KeyName, certPath, ref.KeyName, err)
	}
	if err := verifyCertMatchesKey(certPEM, privKey); err != nil {
		return nil, nil, fmt.Errorf("signing credential %q: certificate %s: %w", ref.KeyName, certPath, err)
	}
	return privKey, certPEM, nil
}

// verifyCertMatchesKey refuses a certificate whose public key is not the public half
// of privKey, so a certificate from another account can never be paired with this key.
func verifyCertMatchesKey(certPEM []byte, privKey crypto.PrivateKey) error {
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key type %T cannot sign", privKey)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("no CERTIFICATE PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(signer.Public()) {
		return fmt.Errorf("certificate public key does not match the private key")
	}
	return nil
}
