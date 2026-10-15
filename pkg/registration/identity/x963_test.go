// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseX963P256_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	point, err := priv.PublicKey.Bytes()
	require.NoError(t, err)

	pub, err := parseX963P256(point)
	require.NoError(t, err)
	assert.True(t, pub.Equal(&priv.PublicKey))
}

func TestParseX963P256_Rejects(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	point, err := priv.PublicKey.Bytes()
	require.NoError(t, err)

	offCurve := append([]byte(nil), point...)
	offCurve[64] ^= 0x01

	for name, in := range map[string][]byte{
		"empty":       nil,
		"truncated":   point[:64],
		"compressed":  append([]byte{0x02}, point[1:33]...),
		"wrong tag":   append([]byte{0x03}, point[1:]...),
		"off curve":   offCurve,
		"extra bytes": append(append([]byte(nil), point...), 0),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseX963P256(in)
			assert.Error(t, err)
		})
	}
}
