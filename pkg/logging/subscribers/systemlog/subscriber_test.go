// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package systemlog

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

func TestSanitizeRedactsSecrets(t *testing.T) {
	cases := map[string]string{
		"password=hunter2 failed":                                      "hunter2",
		"registration token: abcd1234":                                 "abcd1234",
		"api_key=sk-live-123":                                          "sk-live-123",
		"Authorization: Bearer eyJhbGciOi.payload.sig":                 "eyJhbGciOi",
		"blob " + strings.Repeat("A1b2", 12):                           strings.Repeat("A1b2", 12),
		"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----": "MIIE",
	}
	for in, secret := range cases {
		out := Sanitize(in)
		assert.NotContains(t, out, secret, in)
		assert.Contains(t, out, redacted, in)
	}
}

func TestSanitizeKeepsPlainTextAndStripsControl(t *testing.T) {
	out := Sanitize("no usable identity: certificate expired\nforged line")
	assert.Equal(t, "no usable identity: certificate expired_forged line", out)
	assert.LessOrEqual(t, len(Sanitize(strings.Repeat("x y ", 1000))), maxMessageLength+3)
}

func TestInitializeFailureReportsUnavailable(t *testing.T) {
	s := NewSubscriber()
	ok, err := s.Available()
	assert.False(t, ok)
	require.Error(t, err)

	require.Error(t, s.Initialize(map[string]interface{}{"collapse_window": "bogus"}))
	ok, err = s.Available()
	assert.False(t, ok)
	require.Error(t, err)
	assert.Error(t, s.WriteOnce(LevelError, "k", "m"))
	assert.False(t, s.ShouldHandle(interfaces.LogEntry{Level: "ERROR"}))
}

func TestInitializeRejectsRemoteNetworkAndBadTag(t *testing.T) {
	require.Error(t, NewSubscriber().Initialize(map[string]interface{}{"network": "udp", "address": "127.0.0.1:514"}))
	require.Error(t, NewSubscriber().Initialize(map[string]interface{}{"tag": `a\b`}))
}
