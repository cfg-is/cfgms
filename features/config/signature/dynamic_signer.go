// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package signature

import "sync"

// SigningKeyExport carries the PEM-encoded certificate and private key for the
// certificate that should currently be used for signing.
type SigningKeyExport struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// CurrentSignerResolver reports the serial of the certificate that should
// currently be used for signing, plus a lazy export callback that loads the
// PEM material for that serial. The export callback is invoked by DynamicSigner
// only when the serial differs from the one it has already built a signer for,
// so the expensive key export + key parse happens once per rotation rather than
// once per signature.
//
// Returning an empty serial with a nil error means "no signing certificate is
// available"; DynamicSigner then surfaces ErrMissingPrivateKey on Sign.
type CurrentSignerResolver func() (serial string, export func() (SigningKeyExport, error), err error)

// DynamicSigner is a Signer that always signs with the controller's current
// signing certificate. The boot-time signer (built once at startup) keeps
// signing with the original certificate even after a rotation, which makes
// stewards that have retired the old certificate reject every config. The
// DynamicSigner resolves the live signing serial on each Sign and rebuilds the
// underlying ConfigSigner only when that serial changes.
type DynamicSigner struct {
	resolve CurrentSignerResolver

	mu           sync.Mutex
	cachedSerial string
	cached       *ConfigSigner
}

// NewDynamicSigner returns a DynamicSigner backed by resolve.
func NewDynamicSigner(resolve CurrentSignerResolver) *DynamicSigner {
	return &DynamicSigner{resolve: resolve}
}

// current returns the ConfigSigner for the current signing serial, rebuilding
// it only when the serial has changed since the last build.
func (d *DynamicSigner) current() (*ConfigSigner, error) {
	serial, export, err := d.resolve()
	if err != nil {
		return nil, err
	}
	if serial == "" || export == nil {
		return nil, ErrMissingPrivateKey
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cached != nil && serial == d.cachedSerial {
		return d.cached, nil
	}

	keys, err := export()
	if err != nil {
		return nil, err
	}
	signer, err := NewSigner(&SignerConfig{
		PrivateKeyPEM:  keys.PrivateKeyPEM,
		CertificatePEM: keys.CertificatePEM,
	})
	if err != nil {
		return nil, err
	}
	d.cached = signer
	d.cachedSerial = serial
	return signer, nil
}

// cachedSigner returns the last-built signer without re-resolving. Used by the
// metadata accessors (Algorithm/KeyFingerprint), which controller logging calls
// between two Sign calls that have already refreshed the cache.
func (d *DynamicSigner) cachedSigner() *ConfigSigner {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cached
}

// Sign signs data with the current signing certificate.
func (d *DynamicSigner) Sign(data []byte) (*ConfigSignature, error) {
	signer, err := d.current()
	if err != nil {
		return nil, err
	}
	return signer.Sign(data)
}

// Algorithm returns the signing algorithm of the current signer. It reuses the
// cached signer when available and only resolves when no signer has been built
// yet, so logging accessors do not add resolver traffic on the hot path.
func (d *DynamicSigner) Algorithm() Algorithm {
	if s := d.cachedSigner(); s != nil {
		return s.Algorithm()
	}
	s, err := d.current()
	if err != nil {
		return AlgorithmRSASHA256
	}
	return s.Algorithm()
}

// KeyFingerprint returns the fingerprint of the current signing key, or "" when
// no signing certificate is available.
func (d *DynamicSigner) KeyFingerprint() string {
	if s := d.cachedSigner(); s != nil {
		return s.KeyFingerprint()
	}
	s, err := d.current()
	if err != nil {
		return ""
	}
	return s.KeyFingerprint()
}
