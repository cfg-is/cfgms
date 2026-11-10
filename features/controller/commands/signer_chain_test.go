// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package commands

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/signerchain"
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

func currentSigner(t *testing.T, m *cert.Manager) signature.Signer {
	t.Helper()
	c, err := m.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	certPEM, keyPEM, err := m.ExportCertificate(c.SerialNumber, true, false)
	require.NoError(t, err)
	s, err := signature.NewSigner(&signature.SignerConfig{PrivateKeyPEM: keyPEM, CertificatePEM: certPEM})
	require.NoError(t, err)
	return s
}

func parseChain(t *testing.T, chainPEM []byte) []*x509.Certificate {
	t.Helper()
	certs, err := cert.ParseCertificateChainFromPEM(chainPEM)
	require.NoError(t, err)
	return certs
}

// fingerprintOf is the signer's key fingerprint form: upper-case hex SHA-256
// of the certificate DER.
func fingerprintOf(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// chainFailingSource makes the root certificate unavailable so chain building
// fails closed.
type chainFailingSource struct {
	signerchain.SignerChainSource
	rootErr error
}

func (f chainFailingSource) GetCACertificate() ([]byte, error) { return nil, f.rootErr }

func TestPublisher_SignCommand_AttachesChainAndFailsClosed(t *testing.T) {
	m := newChainTestManager(t)
	signer := currentSigner(t, m)
	cmd := &controlplaneTypes.Command{ID: "c1", Type: controlplaneTypes.CommandSyncDNA, StewardID: "s1"}

	p := &Publisher{signer: signer, signerChains: signerchain.NewSignerChainBuilder(m), logger: logging.NewNoopLogger()}
	sc, err := p.signCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, sc.Signature)
	certs := parseChain(t, sc.SignerChainPEM)
	assert.Equal(t, signer.KeyFingerprint(), fingerprintOf(certs[0]))

	failing := &Publisher{
		signer:       signer,
		signerChains: signerchain.NewSignerChainBuilder(chainFailingSource{SignerChainSource: m, rootErr: errors.New("boom")}),
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
	defaultPath := &Publisher{signer: outgoing, signerChains: signerchain.NewSignerChainBuilder(m), logger: logging.NewNoopLogger()}
	sc, err := defaultPath.signCommand(cmd)
	require.Error(t, err, "a default signer outside the valid signing set must fail closed")
	assert.Nil(t, sc)

	// An explicit signer resolves its own stored certificate, window closed or not.
	explicitPath := &Publisher{signer: incoming, signerChains: signerchain.NewSignerChainBuilder(m), logger: logging.NewNoopLogger()}
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
