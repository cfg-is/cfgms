// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// devPublicKey is the well-known zero-seed dev publisher identity. It is not a secret:
// it is documented in the command header and trusted only by dev/lab controllers. If
// this constant ever changes, every dev/lab controller trust store silently stops
// verifying binaries this tool signs, so it is asserted explicitly.
const devPublicKey = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="

// writeBinary creates a stand-in "steward binary" and returns its path.
func writeBinary(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfgms-steward.exe")
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

// parseOutput turns the key=value report into a map so assertions do not depend on
// line ordering.
func parseOutput(t *testing.T, out string) map[string]string {
	t.Helper()
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if key, value, found := strings.Cut(line, "="); found {
			fields[key] = value
		}
	}
	return fields
}

func TestPublisherKey_DefaultsToZeroSeedDevKey(t *testing.T) {
	// An empty value is how the program sees an unset variable.
	t.Setenv(publisherSeedEnv, "")

	priv, err := publisherKey()
	require.NoError(t, err)

	pub := priv.Public().(ed25519.PublicKey)
	assert.Equal(t, devPublicKey, base64.StdEncoding.EncodeToString(pub),
		"default signing identity must remain the documented zero-seed dev key")
}

func TestPublisherKey_UsesSuppliedSeed(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	t.Setenv(publisherSeedEnv, base64.StdEncoding.EncodeToString(seed))

	priv, err := publisherKey()
	require.NoError(t, err)

	assert.Equal(t, ed25519.NewKeyFromSeed(seed), priv)
	assert.NotEqual(t, devPublicKey,
		base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		"a supplied seed must not silently fall back to the dev key")
}

func TestPublisherKey_RejectsMalformedSeed(t *testing.T) {
	tests := []struct {
		name        string
		seed        string
		wantMessage string
	}{
		{
			name:        "not base64",
			seed:        "this is not base64!!",
			wantMessage: "decode " + publisherSeedEnv,
		},
		{
			name:        "too short",
			seed:        base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize-1)),
			wantMessage: "must decode to 32 bytes, got 31",
		},
		{
			name:        "too long",
			seed:        base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize+1)),
			wantMessage: "must decode to 32 bytes, got 33",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(publisherSeedEnv, tc.seed)

			priv, err := publisherKey()
			require.Error(t, err, "malformed seed must not yield a signing key")
			assert.Nil(t, priv)
			assert.Contains(t, err.Error(), tc.wantMessage)
		})
	}
}

func TestRun_SignsWithCanonicalMessage(t *testing.T) {
	t.Setenv(publisherSeedEnv, "")

	content := []byte("steward binary bytes")
	path := writeBinary(t, content)

	var out bytes.Buffer
	require.NoError(t, run([]string{path, "v0.9.41", "windows", "amd64"}, &out))

	fields := parseOutput(t, out.String())

	sum := sha256.Sum256(content)
	wantHash := hex.EncodeToString(sum[:])
	assert.Equal(t, wantHash, fields["sha256"])

	wantMessage, err := trust.StewardBinaryMessage(wantHash, "v0.9.41", "windows", "amd64")
	require.NoError(t, err)
	assert.Equal(t, wantMessage, fields["message"],
		"signed message must come from the shared canonical helper so signer and verifier cannot drift")

	assert.Equal(t, devPublicKey, fields["pub"])

	// The reported signature is URL-safe base64 because that is what
	// `cfg installer publish --signature` accepts.
	sig, err := base64.RawURLEncoding.DecodeString(fields["signature"])
	require.NoError(t, err, "signature must be raw URL-safe base64")

	pub, err := base64.StdEncoding.DecodeString(fields["pub"])
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(ed25519.PublicKey(pub), []byte(wantMessage), sig),
		"emitted signature must verify against the emitted public key and canonical message")

	// The detached .sig file must hold the same raw signature bytes.
	onDisk, err := os.ReadFile(path + ".sig")
	require.NoError(t, err)
	assert.Equal(t, sig, onDisk)

	assert.Contains(t, out.String(), "wrote "+path+".sig")
}

func TestRun_NormalizesVersionPrefix(t *testing.T) {
	t.Setenv(publisherSeedEnv, "")

	path := writeBinary(t, []byte("steward binary bytes"))

	var withPrefix, withoutPrefix bytes.Buffer
	require.NoError(t, run([]string{path, "v0.9.41", "linux", "arm64"}, &withPrefix))
	require.NoError(t, run([]string{path, "0.9.41", "linux", "arm64"}, &withoutPrefix))

	assert.Equal(t, parseOutput(t, withPrefix.String())["signature"],
		parseOutput(t, withoutPrefix.String())["signature"],
		"only the leading v is normalized, so both spellings must sign identical bytes")
}

func TestRun_RejectsWrongArgumentCount(t *testing.T) {
	path := writeBinary(t, []byte("steward binary bytes"))

	tests := map[string][]string{
		"none":     {},
		"too few":  {path, "v0.9.41", "windows"},
		"too many": {path, "v0.9.41", "windows", "amd64", "extra"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(args, &out)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "usage: sign-steward-binary")
			assert.Empty(t, out.String(), "usage failures must not emit a report")
			assert.NoFileExists(t, path+".sig")
		})
	}
}

func TestRun_ReportsUnreadableBinary(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.exe")

	var out bytes.Buffer
	err := run([]string{missing, "v0.9.41", "windows", "amd64"}, &out)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "read binary")
	assert.Empty(t, out.String())
	assert.NoFileExists(t, missing+".sig")
}

func TestRun_RejectsUnsignableCoordinates(t *testing.T) {
	t.Setenv(publisherSeedEnv, "")

	tests := map[string][]string{
		"empty version":         {"", "windows", "amd64"},
		"empty platform":        {"v0.9.41", "", "amd64"},
		"empty arch":            {"v0.9.41", "windows", ""},
		"separator in version":  {"v0.9.41|v0.9.40", "windows", "amd64"},
		"separator in platform": {"v0.9.41", "windows|linux", "amd64"},
	}

	for name, coords := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeBinary(t, []byte("steward binary bytes"))

			var out bytes.Buffer
			err := run(append([]string{path}, coords...), &out)

			require.Error(t, err)
			assert.ErrorIs(t, err, trust.ErrInvalidSignatureMessage)
			assert.Empty(t, out.String())
			assert.NoFileExists(t, path+".sig",
				"no signature may be written for coordinates that cannot form a canonical message")
		})
	}
}

func TestRun_MalformedSeedDoesNotWriteSignature(t *testing.T) {
	t.Setenv(publisherSeedEnv, "not base64!!")

	path := writeBinary(t, []byte("steward binary bytes"))

	var out bytes.Buffer
	err := run([]string{path, "v0.9.41", "windows", "amd64"}, &out)

	require.Error(t, err)
	assert.Empty(t, out.String())
	assert.NoFileExists(t, path+".sig")
}

func TestRun_NeverEchoesSeed(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0xA0 + i)
	}
	encoded := base64.StdEncoding.EncodeToString(seed)
	t.Setenv(publisherSeedEnv, encoded)

	path := writeBinary(t, []byte("steward binary bytes"))

	var out bytes.Buffer
	require.NoError(t, run([]string{path, "v0.9.41", "windows", "amd64"}, &out))

	assert.NotContains(t, out.String(), encoded, "the private seed must never reach stdout")
	assert.False(t, bytes.Contains(out.Bytes(), seed))

	sigBytes, err := os.ReadFile(path + ".sig")
	require.NoError(t, err)
	assert.False(t, bytes.Contains(sigBytes, seed), "the private seed must never reach disk")
}

func TestRun_ErrInvalidSignatureMessageIsSentinel(t *testing.T) {
	// Guards the wrapping in run(): callers (and this test suite) rely on errors.Is
	// rather than string matching to identify unsignable coordinates.
	_, err := trust.StewardBinaryMessage("hash", "", "windows", "amd64")
	require.Error(t, err)
	assert.True(t, errors.Is(err, trust.ErrInvalidSignatureMessage))
}
