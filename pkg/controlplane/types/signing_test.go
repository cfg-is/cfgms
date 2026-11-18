// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
)

func newTestSigner(t *testing.T) (signature.Signer, signature.Verifier) {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{Organization: "CFGMS Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	sc, err := ca.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "controller.test", DNSNames: []string{"controller.test"}, ValidityDays: 1, KeySize: 2048,
	})
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{PrivateKeyPEM: sc.PrivateKeyPEM, CertificatePEM: sc.CertificatePEM})
	require.NoError(t, err)
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: sc.CertificatePEM})
	require.NoError(t, err)
	return signer, verifier
}

func TestSignCommand_AlwaysSignsOverV2(t *testing.T) {
	signer, verifier := newTestSigner(t)

	cmd := &Command{ID: "c-never-seen", Type: CommandSyncConfig, StewardID: "never-seen",
		Timestamp: time.Now(), Term: 4}
	sc, err := SignCommand(cmd, signer)
	require.NoError(t, err)
	require.NotNil(t, sc.Signature)
	assert.Equal(t, SigningPayloadV2, sc.Command.SigningPayloadVersion)
	assert.Zero(t, cmd.SigningPayloadVersion, "input command is not mutated")

	b, err := CommandSigningBytesVersion(&sc.Command, InterfaceParamsToStringMap(sc.Command.Params), SigningPayloadV2)
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(b, sc.Signature))

	// The term is covered: changing it after signing breaks the signature.
	tampered := sc.Command
	tampered.Term = 9_000_000
	b, err = CommandSigningBytesVersion(&tampered, InterfaceParamsToStringMap(tampered.Params), SigningPayloadV2)
	require.NoError(t, err)
	assert.Error(t, verifier.Verify(b, sc.Signature))
}

func TestSignCommand_NilSignerLeavesUnsignedButV2(t *testing.T) {
	sc, err := SignCommand(&Command{ID: "c", StewardID: "s"}, nil)
	require.NoError(t, err)
	assert.Nil(t, sc.Signature)
	assert.Equal(t, SigningPayloadV2, sc.Command.SigningPayloadVersion)
}

// v0105GoldenV1 is the canonical signing payload v0.10.5's CommandSigningBytes
// produced for v0105GoldenCommand. It is the committed canonical JSON only: no
// key and no signature. A v1-signed command must verify on a v0.10.5 steward, so
// these bytes may never change. The term is not in it.
const v0105GoldenV1 = `{"id":"cmd-golden-0105","type":"push_signing_cert","steward_id":"steward-1","tenant_id":"tenant-1","timestamp":"2026-01-02T03:04:05Z","params":{"a":"1","b":"two"}}`

func v0105GoldenCommand() *Command {
	return &Command{
		ID:        "cmd-golden-0105",
		Type:      CommandPushSigningCert,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Date(2026, 1, 2, 4, 4, 5, 0, time.FixedZone("x", 3600)),
		Params:    map[string]interface{}{"a": "1", "b": "two"},
		Term:      41,
	}
}

func TestCommandSigningBytesVersion_V1MatchesV0105Golden(t *testing.T) {
	cmd := v0105GoldenCommand()
	raw := InterfaceParamsToStringMap(cmd.Params)

	got, err := CommandSigningBytesVersion(cmd, raw, SigningPayloadV1)
	require.NoError(t, err)
	assert.Equal(t, v0105GoldenV1, string(got))

	legacy, err := CommandSigningBytes(cmd, raw)
	require.NoError(t, err)
	assert.Equal(t, v0105GoldenV1, string(legacy))
}

func TestSignCommandVersion_V1LeavesVersionUnsetAndVerifiesOverGoldenBytes(t *testing.T) {
	signer, verifier := newTestSigner(t)
	cmd := v0105GoldenCommand()

	sc, err := SignCommandVersion(cmd, signer, SigningPayloadV1)
	require.NoError(t, err)
	require.NotNil(t, sc.Signature)
	assert.Zero(t, sc.Command.SigningPayloadVersion, "a v1 command carries the pre-#5285 wire form")
	assert.Equal(t, uint64(41), sc.Command.Term, "the stamped term stays on a v1 command")

	// What a v0.10.5 steward verifies: the golden bytes.
	assert.NoError(t, verifier.Verify([]byte(v0105GoldenV1), sc.Signature))
}

func TestSignCommandVersion_V2MatchesSignCommand(t *testing.T) {
	signer, verifier := newTestSigner(t)
	cmd := v0105GoldenCommand()

	sc, err := SignCommandVersion(cmd, signer, SigningPayloadV2)
	require.NoError(t, err)
	assert.Equal(t, SigningPayloadV2, sc.Command.SigningPayloadVersion)
	b, err := CommandSigningBytesVersion(&sc.Command, InterfaceParamsToStringMap(sc.Command.Params), SigningPayloadV2)
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(b, sc.Signature))
	assert.Zero(t, cmd.SigningPayloadVersion, "input command is not modified")
}

func TestSignCommandVersion_RefusesOtherVersions(t *testing.T) {
	signer, _ := newTestSigner(t)
	for _, v := range []uint32{0, 3, 77} {
		sc, err := SignCommandVersion(v0105GoldenCommand(), signer, v)
		require.ErrorIs(t, err, ErrUnknownSigningPayloadVersion, "version %d", v)
		assert.Nil(t, sc)
	}
	// An unsigned command validates the version too.
	_, err := SignCommandVersion(v0105GoldenCommand(), nil, 5)
	require.ErrorIs(t, err, ErrUnknownSigningPayloadVersion)
}

func TestSignCommandVersion_ForgedInputVersionIsOverwritten(t *testing.T) {
	signer, verifier := newTestSigner(t)
	cmd := v0105GoldenCommand()
	cmd.SigningPayloadVersion = SigningPayloadV2 // forged by a caller or a replayed record

	sc, err := SignCommandVersion(cmd, signer, SigningPayloadV1)
	require.NoError(t, err)
	assert.Zero(t, sc.Command.SigningPayloadVersion)
	assert.NoError(t, verifier.Verify([]byte(v0105GoldenV1), sc.Signature))
}

type fixedVersionSource uint32

func (f fixedVersionSource) SigningVersionFor(context.Context, string) uint32 { return uint32(f) }

func TestSignCommandForSteward_FollowsTheSourceOnly(t *testing.T) {
	signer, _ := newTestSigner(t)

	// No source: current.
	sc, err := SignCommandForSteward(context.Background(), nil, v0105GoldenCommand(), signer)
	require.NoError(t, err)
	assert.Equal(t, SigningPayloadV2, sc.Command.SigningPayloadVersion)

	// Source says v1, command forges v2 and capability-looking params.
	cmd := v0105GoldenCommand()
	cmd.SigningPayloadVersion = SigningPayloadV2
	cmd.Params = map[string]interface{}{
		"signing_payload_versions": []uint32{1, 2},
		"signing_payload_version":  "2",
		"command_types":            []int32{14},
	}
	sc, err = SignCommandForSteward(context.Background(), fixedVersionSource(SigningPayloadV1), cmd, signer)
	require.NoError(t, err)
	assert.Zero(t, sc.Command.SigningPayloadVersion)

	// Source says v2 and the command forges nothing: v2.
	sc, err = SignCommandForSteward(context.Background(), fixedVersionSource(SigningPayloadV2), v0105GoldenCommand(), signer)
	require.NoError(t, err)
	assert.Equal(t, SigningPayloadV2, sc.Command.SigningPayloadVersion)

	// A source that returns a version this build cannot sign fails the command.
	_, err = SignCommandForSteward(context.Background(), fixedVersionSource(9), v0105GoldenCommand(), signer)
	require.ErrorIs(t, err, ErrUnknownSigningPayloadVersion)
}
