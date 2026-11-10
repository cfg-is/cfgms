// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/signerchain"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

// signedChainedCommand signs a command with a real controller signing
// certificate and attaches the chain the way the dispatcher and publisher do.
func signedChainedCommand(t *testing.T, steward string) (*types.SignedCommand, *cert.Manager) {
	t.Helper()
	m, err := cert.NewManager(&cert.ManagerConfig{
		CAConfig:    &cert.CAConfig{Organization: "CFGMS Test", Country: "US", ValidityDays: 30, KeySize: 2048},
		StoragePath: t.TempDir(),
	})
	require.NoError(t, err)
	require.NoError(t, m.EnsureSigningCertificate(&cert.SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 30, KeySize: 2048}))
	cur, err := m.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	certPEM, keyPEM, err := m.ExportCertificate(cur.SerialNumber, true, false)
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{PrivateKeyPEM: keyPEM, CertificatePEM: certPEM})
	require.NoError(t, err)

	cmd := &types.Command{ID: "chain-1", Type: types.CommandExecuteScript, StewardID: steward, Timestamp: time.Now(),
		Params: map[string]interface{}{"k": "v"}}
	sc, err := types.SignCommand(cmd, signer)
	require.NoError(t, err)
	require.NoError(t, signerchain.NewSignerChainBuilder(m).Attach(sc, signer))
	require.NotEmpty(t, sc.SignerChainPEM, "set at signing")
	return sc, m
}

func recv(t *testing.T, env *gateEnv, id string) *types.SignedCommand {
	t.Helper()
	select {
	case got := <-env.received[id]:
		return got
	case <-time.After(5 * time.Second):
		t.Fatalf("steward %s received nothing", id)
		return nil
	}
}

func TestSendCommand_SignerChain_OnlyForLockedDownSteward(t *testing.T) {
	env := newGateEnv(t, "s-normal", "s-locked")
	env.pred.lock("s-locked")
	ctx := interfaces.WithOperatorOrigin(context.Background(), "operator-1")

	scLocked, m := signedChainedCommand(t, "s-locked")
	require.NoError(t, env.server.SendCommand(ctx, scLocked))
	got := recv(t, env, "s-locked")

	certs, err := cert.ParseCertificateChainFromPEM(got.SignerChainPEM)
	require.NoError(t, err)
	require.Len(t, certs, 2)
	assert.NotContains(t, string(got.SignerChainPEM), "PRIVATE KEY")

	// The first certificate verifies the command signature received over the wire.
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: pemCert(certs[0].Raw)})
	require.NoError(t, err)
	signed, err := types.CommandSigningBytesVersion(&got.Command, got.RawParams, got.Command.SigningPayloadVersion)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(signed, got.Signature))
	assert.Equal(t, got.Signature.KeyFingerprint, fmt.Sprintf("%X", sha256.Sum256(certs[0].Raw)))

	// The last is the self-signed root whose fingerprint is the controller CA's.
	caPEM, err := m.GetCACertificate()
	require.NoError(t, err)
	ca, err := cert.ParseCertificateFromPEM(caPEM)
	require.NoError(t, err)
	last := certs[len(certs)-1]
	assert.Equal(t, sha256.Sum256(ca.Raw), sha256.Sum256(last.Raw))
	require.NoError(t, last.CheckSignatureFrom(last))

	// A non-locked steward gets the same signed command with no chain, though the
	// chain was set at signing.
	scNormal := *scLocked
	scNormal.Command.StewardID = "s-normal"
	require.NotEmpty(t, scNormal.SignerChainPEM)
	require.NoError(t, env.server.SendCommand(context.Background(), &scNormal))
	gotNormal := recv(t, env, "s-normal")
	assert.Empty(t, gotNormal.SignerChainPEM)
	assert.Empty(t, gotNormal.Command.SignerChainPEM)
	assert.NotEmpty(t, scNormal.SignerChainPEM, "the caller's command is not modified")
}

func TestFanOutCommand_SignerChain_OnlyForLockedDownSteward(t *testing.T) {
	env := newGateEnv(t, "s-normal", "s-locked")
	env.pred.lock("s-locked")
	ctx := interfaces.WithOperatorOrigin(context.Background(), "operator-1")

	sc, _ := signedChainedCommand(t, "")
	res, err := env.server.FanOutCommand(ctx, sc, []string{"s-normal", "s-locked"})
	require.NoError(t, err)
	require.Empty(t, res.Failed)

	assert.NotEmpty(t, recv(t, env, "s-locked").SignerChainPEM)
	assert.Empty(t, recv(t, env, "s-normal").SignerChainPEM)
}

func TestConvert_SignedCommandSignerChain_RoundTrips(t *testing.T) {
	sc := &types.SignedCommand{
		Command:        types.Command{ID: "c", Type: types.CommandSyncDNA, StewardID: "s", Timestamp: time.Now()},
		SignerChainPEM: []byte("-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n"),
	}
	pb := signedCommandToProto(sc)
	assert.Equal(t, sc.SignerChainPEM, pb.GetSignerChainPem())
	back := signedCommandFromProto(pb)
	require.NotNil(t, back)
	assert.Equal(t, sc.SignerChainPEM, back.SignerChainPEM)

	empty := signedCommandToProto(&types.SignedCommand{Command: sc.Command})
	assert.Empty(t, empty.GetSignerChainPem())
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
