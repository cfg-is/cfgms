// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package commands

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

const (
	// MaxSignerChainPEMLen caps the chain attached to a command or repair request.
	MaxSignerChainPEMLen = 64 << 10

	// maxSignerChainCerts caps the number of certificates in a chain: a signing
	// certificate, a few intermediates and the root.
	maxSignerChainCerts = 8
)

// SignerChainSource is the part of the certificate manager the chain builder
// reads. *cert.Manager satisfies it.
type SignerChainSource interface {
	GetAllValidSigningCertificates() ([]*cert.CertificateInfo, error)
	GetCertificate(serialNumber string) (*cert.Certificate, error)
	GetCACertificate() ([]byte, error)
}

// BuildSignerChain returns the PEM chain for the certificate that signed with
// signer: the signing certificate (selected by the signer's key fingerprint, so a
// signer on the older certificate of a rotation overlap yields the older
// certificate), then its issuer chain, then the root as the LAST element. The
// output holds certificates only, never a key, and is capped in size. Any
// failure returns an error; the caller must not send the command unchained.
func BuildSignerChain(src SignerChainSource, signer signature.Signer) ([]byte, error) {
	fingerprint, err := signerFingerprint(src, signer)
	if err != nil {
		return nil, err
	}
	leaf, err := findSigningCertificate(src, fingerprint)
	if err != nil {
		return nil, err
	}
	rootPEM, err := src.GetCACertificate()
	if err != nil {
		return nil, fmt.Errorf("signer chain: root certificate: %w", err)
	}
	certs, err := orderedSignerChain(leaf, rootPEM)
	if err != nil {
		return nil, err
	}
	if err := checkSignerChain(certs); err != nil {
		return nil, err
	}
	return encodeSignerChain(certs)
}

// signerFingerprint returns the signer's upper-case key fingerprint.
func signerFingerprint(src SignerChainSource, signer signature.Signer) (string, error) {
	if src == nil {
		return "", errors.New("signer chain: no certificate source")
	}
	if signer == nil {
		return "", errors.New("signer chain: no signer")
	}
	fingerprint := strings.ToUpper(signer.KeyFingerprint())
	if fingerprint == "" {
		return "", errors.New("signer chain: signer has no key fingerprint")
	}
	return fingerprint, nil
}

// findSigningCertificate returns the valid signing certificate whose SHA-256
// fingerprint is fingerprint.
func findSigningCertificate(src SignerChainSource, fingerprint string) (*cert.Certificate, error) {
	infos, err := src.GetAllValidSigningCertificates()
	if err != nil {
		return nil, fmt.Errorf("signer chain: list signing certificates: %w", err)
	}
	for _, info := range infos {
		if info == nil {
			continue
		}
		c, err := src.GetCertificate(info.SerialNumber)
		if err != nil || c == nil {
			continue
		}
		parsed, err := cert.ParseCertificateFromPEM(c.CertificatePEM)
		if err == nil && fmt.Sprintf("%X", sha256.Sum256(parsed.Raw)) == fingerprint {
			return c, nil
		}
	}
	return nil, errors.New("signer chain: no valid signing certificate matches the signer")
}

// orderedSignerChain parses the leaf, its issuer chain and the root into one
// list, dropping a repeated certificate (an issuer chain that already ends in
// the root).
func orderedSignerChain(leaf *cert.Certificate, rootPEM []byte) ([]*x509.Certificate, error) {
	var raw []byte
	raw = append(raw, leaf.CertificatePEM...)
	raw = append(raw, '\n')
	raw = append(raw, leaf.IssuerChainPEM...)
	raw = append(raw, '\n')
	raw = append(raw, rootPEM...)
	certs, err := cert.ParseCertificateChainFromPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("signer chain: parse: %w", err)
	}
	uniq := certs[:0:0]
	for _, c := range certs {
		if len(uniq) > 0 && uniq[len(uniq)-1].Equal(c) {
			continue
		}
		uniq = append(uniq, c)
	}
	return uniq, nil
}

// checkSignerChain requires 2 to maxSignerChainCerts certificates, each issued
// by the next, ending in a self-signed root.
func checkSignerChain(certs []*x509.Certificate) error {
	if len(certs) < 2 || len(certs) > maxSignerChainCerts {
		return fmt.Errorf("signer chain: %d certificates, want 2 to %d", len(certs), maxSignerChainCerts)
	}
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return errors.New("signer chain: certificates are not an issuer chain")
		}
	}
	root := certs[len(certs)-1]
	if err := root.CheckSignatureFrom(root); err != nil || string(root.RawSubject) != string(root.RawIssuer) {
		return errors.New("signer chain: last certificate is not a self-signed root")
	}
	return nil
}

// encodeSignerChain re-encodes from the parsed certificates so nothing but
// certificates leaves, and enforces the size cap.
func encodeSignerChain(certs []*x509.Certificate) ([]byte, error) {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if len(out) > MaxSignerChainPEMLen {
		return nil, fmt.Errorf("signer chain: %d bytes exceeds the %d byte cap", len(out), MaxSignerChainPEMLen)
	}
	return out, nil
}

// SignerChainBuilder builds signer chains and caches them per signer key
// fingerprint: a certificate and its issuers do not change for a given key.
type SignerChainBuilder struct {
	src SignerChainSource

	mu    sync.Mutex
	cache map[string][]byte
}

// NewSignerChainBuilder returns a builder over src.
func NewSignerChainBuilder(src SignerChainSource) *SignerChainBuilder {
	return &SignerChainBuilder{src: src, cache: make(map[string][]byte)}
}

// Build returns the chain for signer, building it on first use.
func (b *SignerChainBuilder) Build(signer signature.Signer) ([]byte, error) {
	if b == nil {
		return nil, errors.New("signer chain: no builder")
	}
	if signer == nil {
		return nil, errors.New("signer chain: no signer")
	}
	key := strings.ToUpper(signer.KeyFingerprint())
	b.mu.Lock()
	cached, ok := b.cache[key]
	b.mu.Unlock()
	if ok {
		return append([]byte(nil), cached...), nil
	}
	chain, err := BuildSignerChain(b.src, signer)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.cache[key] = chain
	b.mu.Unlock()
	return append([]byte(nil), chain...), nil
}

// SignWithChain signs payload with signer and returns the signature with the
// signer's chain. It is the one signing helper for a request that carries its
// chain (the repair request). The signature is over payload alone; the chain is
// transport metadata the receiver validates itself.
func (b *SignerChainBuilder) SignWithChain(signer signature.Signer, payload []byte) (*signature.ConfigSignature, []byte, error) {
	chain, err := b.Build(signer)
	if err != nil {
		return nil, nil, err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("sign payload: %w", err)
	}
	return sig, chain, nil
}

// Attach sets sc.SignerChainPEM to the chain of signer. A nil builder or nil
// signer leaves sc unchanged (unsigned or chain-less deployments). A chain that
// cannot be built is an error: the caller must not send the command.
func (b *SignerChainBuilder) Attach(sc *controlplaneTypes.SignedCommand, signer signature.Signer) error {
	if b == nil || signer == nil || sc == nil {
		return nil
	}
	chain, err := b.Build(signer)
	if err != nil {
		return err
	}
	sc.SignerChainPEM = chain
	return nil
}
