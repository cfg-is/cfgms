// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package operatorroster

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/cert"
)

// rosterTestControllerManifest is the test's own statement of the manifest shape the controller
// signs (features/controller/api.RevocationManifest), including the X.509 signer roster, declared
// independently of the production mirror so a field dropped from the mirror fails strict-mode
// verification here instead of cancelling out on both sides.
type rosterTestControllerManifest struct {
	Kind                  string                       `json:"kind"`
	Version               int64                        `json:"version"`
	IssuedAt              time.Time                    `json:"issued_at"`
	RevokedSerials        []string                     `json:"revoked_serials"`
	AuthorizedX509Signers []rosterTestControllerSigner `json:"authorized_x509_signers,omitempty"`
}

type rosterTestControllerSigner struct {
	Kind             string   `json:"kind"`
	Serial           string   `json:"serial"`
	AccountID        string   `json:"account_id"`
	TenantID         string   `json:"tenant_id"`
	RootScope        bool     `json:"root_scope"`
	Grants           []string `json:"grants"`
	CoveredTenantIDs []string `json:"covered_tenant_ids,omitempty"`
}

func rosterTestSigner(serial, account string) rosterTestControllerSigner {
	return rosterTestControllerSigner{
		Kind: AuthorizedX509SignerKind, Serial: serial, AccountID: account, TenantID: "tenant-a",
		Grants: []string{"operator-payload:sign"}, CoveredTenantIDs: []string{"tenant-a-child"},
	}
}

func rosterTestSign(t *testing.T, signingCert *cert.Certificate, version int64, issuedAt time.Time, signers ...rosterTestControllerSigner) []byte {
	t.Helper()
	manifest := rosterTestControllerManifest{
		Kind: revocationManifestKind, Version: version, IssuedAt: issuedAt.UTC().Truncate(time.Second),
		RevokedSerials: []string{}, AuthorizedX509Signers: signers,
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: signingCert.CertificatePEM, PrivateKeyPEM: signingCert.PrivateKeyPEM,
	})
	require.NoError(t, err)
	sig, err := signer.Sign(data)
	require.NoError(t, err)
	out, err := json.Marshal(struct {
		Manifest             rosterTestControllerManifest `json:"manifest"`
		Signature            *signature.ConfigSignature   `json:"signature"`
		SignerCertificatePEM string                       `json:"signer_certificate_pem"`
	}{manifest, sig, string(signingCert.CertificatePEM)})
	require.NoError(t, err)
	return out
}

func TestX509SignerRoster_NoManifest_NoRoster(t *testing.T) {
	_, pool := revTestCA(t)
	roster, ok := NewRevocationVerifier(pool).X509SignerRoster()
	assert.False(t, ok, "a verifier that has accepted no manifest holds no roster")
	assert.Nil(t, roster)
}

func TestX509SignerRoster_StrictManifest_RosterRoundTripsAndIsServed(t *testing.T) {
	ca, pool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	issued := time.Now()
	v := NewRevocationVerifier(pool)

	// Strict-mode verification re-marshals the manifest through the production mirror; the
	// roster surviving that round trip is what makes the controller's signature verify.
	require.NoError(t, v.VerifyManifest(rosterTestSign(t, signingCert, 1, issued, rosterTestSigner("101", "acct-1")), stewardtypes.ModuleTrustModeStrict))

	roster, ok := v.X509SignerRoster()
	require.True(t, ok)
	assert.WithinDuration(t, issued, roster.IssuedAt(), 2*time.Second)
	entries := roster.SignersForSerial("101")
	require.Len(t, entries, 1)
	assert.Equal(t, "acct-1", entries[0].AccountID)
	assert.Equal(t, "tenant-a", entries[0].TenantID)
	assert.Equal(t, []string{"operator-payload:sign"}, entries[0].Grants)
	assert.Equal(t, []string{"tenant-a-child"}, entries[0].CoveredTenantIDs)
	assert.Empty(t, roster.SignersForSerial("999"), "a serial the roster never listed has no entry")
}

func TestX509SignerRoster_UnsignedOrUntrustedManifestNeverYieldsARoster(t *testing.T) {
	ca, pool := revTestCA(t)
	otherCA, _ := revTestCA(t)
	untrusted := revTestSigningCert(t, otherCA)
	_ = ca

	t.Run("strict mode rejects an untrusted signer outright", func(t *testing.T) {
		v := NewRevocationVerifier(pool)
		err := v.VerifyManifest(rosterTestSign(t, untrusted, 1, time.Now(), rosterTestSigner("101", "acct-1")), stewardtypes.ModuleTrustModeStrict)
		require.Error(t, err)
		_, ok := v.X509SignerRoster()
		assert.False(t, ok)
	})
	t.Run("controller mode applies revocation but takes no roster from an unverifiable manifest", func(t *testing.T) {
		v := NewRevocationVerifier(pool)
		require.NoError(t, v.VerifyManifest(rosterTestSign(t, untrusted, 1, time.Now(), rosterTestSigner("101", "acct-1")), stewardtypes.ModuleTrustModeController))
		_, ok := v.X509SignerRoster()
		assert.False(t, ok, "the roster is authority and must not be taken on the controller's word")
	})
	t.Run("controller mode with a chain-valid signature does yield the roster", func(t *testing.T) {
		signingCert := revTestSigningCert(t, ca)
		v := NewRevocationVerifier(pool)
		require.NoError(t, v.VerifyManifest(rosterTestSign(t, signingCert, 1, time.Now(), rosterTestSigner("101", "acct-1")), stewardtypes.ModuleTrustModeController))
		roster, ok := v.X509SignerRoster()
		require.True(t, ok)
		assert.Len(t, roster.SignersForSerial("101"), 1)
	})
	t.Run("controller mode without pinned roots yields no roster", func(t *testing.T) {
		v := NewRevocationVerifier(nil)
		require.NoError(t, v.VerifyManifest(rosterTestSign(t, revTestSigningCert(t, ca), 1, time.Now(), rosterTestSigner("101", "acct-1")), stewardtypes.ModuleTrustModeController))
		_, ok := v.X509SignerRoster()
		assert.False(t, ok)
	})
}

func TestX509SignerRoster_NewerManifestReplacesRoster_DroppedSignerIsForgotten(t *testing.T) {
	ca, pool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	v := NewRevocationVerifier(pool)
	now := time.Now()

	require.NoError(t, v.VerifyManifest(rosterTestSign(t, signingCert, 1, now.Add(-time.Minute), rosterTestSigner("101", "acct-1"), rosterTestSigner("102", "acct-2")), stewardtypes.ModuleTrustModeStrict))
	require.NoError(t, v.VerifyManifest(rosterTestSign(t, signingCert, 1, now, rosterTestSigner("102", "acct-2")), stewardtypes.ModuleTrustModeStrict))

	roster, ok := v.X509SignerRoster()
	require.True(t, ok)
	assert.Empty(t, roster.SignersForSerial("101"), "a signer the controller dropped must stop being accepted")
	assert.Len(t, roster.SignersForSerial("102"), 1)

	// An empty roster in a newer manifest is a real state: every signer was dropped.
	require.NoError(t, v.VerifyManifest(rosterTestSign(t, signingCert, 1, now.Add(time.Minute)), stewardtypes.ModuleTrustModeStrict))
	roster, ok = v.X509SignerRoster()
	require.True(t, ok)
	assert.Empty(t, roster.SignersForSerial("102"))
}

func TestX509SignerRoster_OlderManifestCannotRollTheRosterBack(t *testing.T) {
	ca, pool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	v := NewRevocationVerifier(pool)
	now := time.Now()

	older := rosterTestSign(t, signingCert, 2, now.Add(-5*time.Minute), rosterTestSigner("101", "acct-1"))
	newer := rosterTestSign(t, signingCert, 2, now, rosterTestSigner("102", "acct-2"))
	require.NoError(t, v.VerifyManifest(newer, stewardtypes.ModuleTrustModeStrict))
	// Same version, so the anti-rollback version check admits it; its roster must still be ignored.
	require.NoError(t, v.VerifyManifest(older, stewardtypes.ModuleTrustModeStrict))

	roster, ok := v.X509SignerRoster()
	require.True(t, ok)
	assert.Empty(t, roster.SignersForSerial("101"), "a replayed older roster must not resurrect a removed signer")
	assert.Len(t, roster.SignersForSerial("102"), 1)
	assert.WithinDuration(t, now, roster.IssuedAt(), 2*time.Second)
}

func TestX509SignerRoster_FutureIssuedManifestDoesNotPinTheFloor(t *testing.T) {
	ca, pool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	v := NewRevocationVerifier(pool)

	require.NoError(t, v.VerifyManifest(rosterTestSign(t, signingCert, 1, time.Now().Add(time.Hour), rosterTestSigner("101", "acct-1")), stewardtypes.ModuleTrustModeStrict))
	_, ok := v.X509SignerRoster()
	assert.False(t, ok, "a roster issued far in the future must not be adopted")

	require.NoError(t, v.VerifyManifest(rosterTestSign(t, signingCert, 1, time.Now(), rosterTestSigner("102", "acct-2")), stewardtypes.ModuleTrustModeStrict))
	roster, ok := v.X509SignerRoster()
	require.True(t, ok, "a legitimate manifest must still be accepted afterwards")
	assert.Len(t, roster.SignersForSerial("102"), 1)
}

func TestX509SignerRoster_EntriesOfAnotherKindOrWithoutSerialAreIgnored(t *testing.T) {
	ca, pool := revTestCA(t)
	signingCert := revTestSigningCert(t, ca)
	v := NewRevocationVerifier(pool)

	foreign := rosterTestSigner("101", "acct-1")
	foreign.Kind = "something-else"
	noSerial := rosterTestSigner("", "acct-2")
	require.NoError(t, v.VerifyManifest(rosterTestSign(t, signingCert, 1, time.Now(), foreign, noSerial, rosterTestSigner("103", "acct-3")), stewardtypes.ModuleTrustModeStrict))

	roster, ok := v.X509SignerRoster()
	require.True(t, ok)
	assert.Empty(t, roster.SignersForSerial("101"))
	assert.Empty(t, roster.SignersForSerial(""))
	assert.Len(t, roster.SignersForSerial("103"), 1)
}
