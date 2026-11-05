// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

func newChainTestManager(t *testing.T) *cert.Manager {
	t.Helper()
	m, err := cert.NewManager(&cert.ManagerConfig{
		CAConfig:    &cert.CAConfig{Organization: "CFGMS Test", Country: "US", ValidityDays: 30, KeySize: 2048},
		StoragePath: t.TempDir(),
	})
	require.NoError(t, err)
	require.NoError(t, m.EnsureSigningCertificate(&cert.SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 30, KeySize: 2048}))
	return m
}

func signerForSerial(t *testing.T, m *cert.Manager, serial string) signature.Signer {
	t.Helper()
	certPEM, keyPEM, err := m.ExportCertificate(serial, true, false)
	require.NoError(t, err)
	s, err := signature.NewSigner(&signature.SignerConfig{PrivateKeyPEM: keyPEM, CertificatePEM: certPEM})
	require.NoError(t, err)
	return s
}

func currentSigner(t *testing.T, m *cert.Manager) signature.Signer {
	t.Helper()
	c, err := m.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	return signerForSerial(t, m, c.SerialNumber)
}

func parseChain(t *testing.T, chainPEM []byte) []*x509.Certificate {
	t.Helper()
	certs, err := cert.ParseCertificateChainFromPEM(chainPEM)
	require.NoError(t, err)
	return certs
}

func fingerprintOf(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return strings.ToUpper(string(hexEncode(h[:])))
}

func hexEncode(b []byte) []byte {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0xf])
	}
	return out
}

func assertCertificatesOnly(t *testing.T, chainPEM []byte) {
	t.Helper()
	rest := chainPEM
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		n++
		assert.Equal(t, "CERTIFICATE", b.Type)
	}
	assert.Positive(t, n)
	assert.NotContains(t, string(chainPEM), "PRIVATE KEY")
}

func TestBuildSignerChain_LeafSignsAndRootIsCA(t *testing.T) {
	m := newChainTestManager(t)
	signer := currentSigner(t, m)

	chain, err := BuildSignerChain(m, signer)
	require.NoError(t, err)
	assertCertificatesOnly(t, chain)

	certs := parseChain(t, chain)
	require.Len(t, certs, 2, "self-signed CA: signing certificate then CA certificate")
	assert.Equal(t, signer.KeyFingerprint(), fingerprintOf(certs[0]))

	caPEM, err := m.GetCACertificate()
	require.NoError(t, err)
	ca := parseChain(t, caPEM)[0]
	last := certs[len(certs)-1]
	assert.Equal(t, fingerprintOf(ca), fingerprintOf(last))
	require.NoError(t, last.CheckSignatureFrom(last), "last element is self-signed")

	sig, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)
	v, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: pemOf(certs[0])})
	require.NoError(t, err)
	require.NoError(t, v.Verify([]byte("payload"), sig))
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func TestBuildSignerChain_RotationOverlapFollowsSigner(t *testing.T) {
	m := newChainTestManager(t)
	older := currentSigner(t, m)
	_, err := m.RotateSigningCertificate(7)
	require.NoError(t, err)
	newer := currentSigner(t, m)
	require.NotEqual(t, older.KeyFingerprint(), newer.KeyFingerprint())

	oldChain, err := BuildSignerChain(m, older)
	require.NoError(t, err)
	newChain, err := BuildSignerChain(m, newer)
	require.NoError(t, err)

	assert.Equal(t, older.KeyFingerprint(), fingerprintOf(parseChain(t, oldChain)[0]))
	assert.Equal(t, newer.KeyFingerprint(), fingerprintOf(parseChain(t, newChain)[0]))
}

func TestBuildSignerChain_SubordinateCAEndsInOfflineRoot(t *testing.T) {
	rootCfg := &cert.CAConfig{Organization: "Offline Root", Country: "US", ValidityDays: 3650, PathLength: 1, PathLengthSet: true, KeySize: 2048}
	root, err := cert.NewCA(rootCfg)
	require.NoError(t, err)
	require.NoError(t, root.Initialize(rootCfg))
	rootPEM, err := root.GetCACertificate()
	require.NoError(t, err)

	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sub, err := root.SignSubordinateCA(&subKey.PublicKey, &cert.SubordinateCAConfig{
		CommonName: "Regional Intermediate", Organization: "Test", ValidityDays: 3650, PathLength: 0,
	})
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(subKey)})

	m, err := cert.NewManagerFromCAMaterial(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
	}, sub.CertificatePEM, keyPEM, rootPEM)
	require.NoError(t, err)
	require.NoError(t, m.EnsureSigningCertificate(&cert.SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 30, KeySize: 2048}))

	signer := currentSigner(t, m)
	chain, err := BuildSignerChain(m, signer)
	require.NoError(t, err)
	certs := parseChain(t, chain)
	require.Len(t, certs, 3, "signing certificate, intermediate, root")
	assert.Equal(t, signer.KeyFingerprint(), fingerprintOf(certs[0]))
	assert.Equal(t, "Regional Intermediate", certs[1].Subject.CommonName)
	assert.Equal(t, fingerprintOf(parseChain(t, rootPEM)[0]), fingerprintOf(certs[2]))
	require.NoError(t, certs[2].CheckSignatureFrom(certs[2]))
}

type fakeSource struct {
	SignerChainSource
	rootPEM []byte
	rootErr error
}

func (f fakeSource) GetCACertificate() ([]byte, error) { return f.rootPEM, f.rootErr }

func TestBuildSignerChain_FailsClosed(t *testing.T) {
	m := newChainTestManager(t)
	signer := currentSigner(t, m)

	t.Run("root unavailable", func(t *testing.T) {
		_, err := BuildSignerChain(fakeSource{SignerChainSource: m, rootErr: errors.New("boom")}, signer)
		require.Error(t, err)
	})
	t.Run("unparsable root", func(t *testing.T) {
		_, err := BuildSignerChain(fakeSource{SignerChainSource: m, rootPEM: []byte("not pem")}, signer)
		require.Error(t, err)
	})
	t.Run("root does not issue the signer", func(t *testing.T) {
		other := newChainTestManager(t)
		otherRoot, err := other.GetCACertificate()
		require.NoError(t, err)
		_, err = BuildSignerChain(fakeSource{SignerChainSource: m, rootPEM: otherRoot}, signer)
		require.Error(t, err)
	})
	t.Run("signer certificate unknown", func(t *testing.T) {
		other := newChainTestManager(t)
		_, err := BuildSignerChain(m, currentSigner(t, other))
		require.Error(t, err)
	})
	t.Run("nil signer and source", func(t *testing.T) {
		_, err := BuildSignerChain(m, nil)
		require.Error(t, err)
		_, err = BuildSignerChain(nil, signer)
		require.Error(t, err)
	})
}

type oversizeSource struct {
	SignerChainSource
	extra []byte
}

func (o oversizeSource) GetCertificate(serial string) (*cert.Certificate, error) {
	c, err := o.SignerChainSource.GetCertificate(serial)
	if err != nil {
		return nil, err
	}
	dup := *c
	dup.IssuerChainPEM = o.extra
	return &dup, nil
}

func TestBuildSignerChain_OversizedChainRefused(t *testing.T) {
	m := newChainTestManager(t)
	// An issuer chain of distinct certificates past the certificate-count cap.
	var extra []byte
	for i := 0; i <= maxSignerChainCerts; i++ {
		pemBytes, err := newChainTestManager(t).GetCACertificate()
		require.NoError(t, err)
		extra = append(extra, pemBytes...)
	}
	_, err := BuildSignerChain(oversizeSource{SignerChainSource: m, extra: extra}, currentSigner(t, m))
	require.Error(t, err)
}

func TestSignerChainBuilder_SignWithChain_VerifiesUnderFirstCertificate(t *testing.T) {
	m := newChainTestManager(t)
	signer := currentSigner(t, m)
	b := NewSignerChainBuilder(m)

	payload := []byte("repair-request-payload")
	sig, chain, err := b.SignWithChain(signer, payload)
	require.NoError(t, err)
	assertCertificatesOnly(t, chain)

	first := parseChain(t, chain)[0]
	v, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: pemOf(first)})
	require.NoError(t, err)
	require.NoError(t, v.Verify(payload, sig))
	assert.Error(t, v.Verify([]byte("other"), sig))
}

func TestSignerChainBuilder_CachesPerFingerprint(t *testing.T) {
	m := newChainTestManager(t)
	signer := currentSigner(t, m)
	b := NewSignerChainBuilder(m)
	first, err := b.Build(signer)
	require.NoError(t, err)
	first[0] ^= 0xff // mutating a returned chain must not corrupt the cache
	second, err := b.Build(signer)
	require.NoError(t, err)
	assert.NotEqual(t, first, second)
	parseChain(t, second)
}

func TestSignerChainBuilder_AttachFailsClosedAndNilIsNoop(t *testing.T) {
	m := newChainTestManager(t)
	signer := currentSigner(t, m)

	sc := &controlplaneTypes.SignedCommand{}
	require.NoError(t, (*SignerChainBuilder)(nil).Attach(sc, signer))
	assert.Empty(t, sc.SignerChainPEM)

	bad := NewSignerChainBuilder(fakeSource{SignerChainSource: m, rootErr: errors.New("boom")})
	require.Error(t, bad.Attach(sc, signer))
	assert.Empty(t, sc.SignerChainPEM)

	require.NoError(t, NewSignerChainBuilder(m).Attach(sc, signer))
	assert.NotEmpty(t, sc.SignerChainPEM)
}

func TestPublisher_SignCommand_AttachesChainAndFailsClosed(t *testing.T) {
	m := newChainTestManager(t)
	signer := currentSigner(t, m)
	cmd := &controlplaneTypes.Command{ID: "c1", Type: controlplaneTypes.CommandSyncDNA, StewardID: "s1"}

	p := &Publisher{signer: signer, signerChains: NewSignerChainBuilder(m), logger: logging.NewNoopLogger()}
	sc, err := p.signCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, sc.Signature)
	certs := parseChain(t, sc.SignerChainPEM)
	assert.Equal(t, signer.KeyFingerprint(), fingerprintOf(certs[0]))

	failing := &Publisher{
		signer:       signer,
		signerChains: NewSignerChainBuilder(fakeSource{SignerChainSource: m, rootErr: errors.New("boom")}),
		logger:       logging.NewNoopLogger(),
	}
	sc, err = failing.signCommand(cmd)
	require.Error(t, err)
	assert.Nil(t, sc)
}

func TestPublisher_ExplicitSignerChainIgnoresOverlapWindowButDefaultFailsClosed(t *testing.T) {
	m := newChainTestManager(t)
	outgoing := currentSigner(t, m)
	_, err := m.RotateSigningCertificate(0)
	require.NoError(t, err)
	incoming := currentSigner(t, m)
	require.NotEqual(t, outgoing.KeyFingerprint(), incoming.KeyFingerprint())
	cmd := &controlplaneTypes.Command{ID: "c1", Type: controlplaneTypes.CommandPushSigningCert, StewardID: "s1"}

	// The default signer path still requires a certificate in the valid set.
	defaultPath := &Publisher{signer: outgoing, signerChains: NewSignerChainBuilder(m), logger: logging.NewNoopLogger()}
	sc, err := defaultPath.signCommand(cmd)
	require.Error(t, err, "a default signer outside the valid signing set must fail closed")
	assert.Nil(t, sc)

	// An explicit signer resolves its own stored certificate, window closed or not.
	explicitPath := &Publisher{signer: incoming, signerChains: NewSignerChainBuilder(m), logger: logging.NewNoopLogger()}
	sc, err = explicitPath.signCommandWith(cmd, outgoing, true)
	require.NoError(t, err)
	certs := parseChain(t, sc.SignerChainPEM)
	assert.Equal(t, outgoing.KeyFingerprint(), fingerprintOf(certs[0]))
	require.NoError(t, certs[len(certs)-1].CheckSignatureFrom(certs[len(certs)-1]))

	// The explicit chain never satisfies the default path afterwards.
	_, err = explicitPath.signCommandWith(cmd, outgoing, false)
	require.Error(t, err)

	// An explicit signer with no stored certificate still fails closed.
	other := newChainTestManager(t)
	_, err = explicitPath.signCommandWith(cmd, currentSigner(t, other), true)
	require.Error(t, err)
}
