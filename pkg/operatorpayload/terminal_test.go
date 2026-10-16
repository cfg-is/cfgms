// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package operatorpayload

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalConstants(t *testing.T) {
	assert.Equal(t, "terminal-open", TerminalShell)
	assert.Equal(t, "terminal.open", TerminalVerb)
	assert.NotEqual(t, ActionShell, TerminalShell)
	for _, s := range []string{"bash", "sh", "zsh", "powershell", "pwsh", "cmd", "python"} {
		assert.NotEqual(t, s, TerminalShell)
	}
	assert.Equal(t, 5*time.Minute, TerminalEnvelopeMaxTTL)
	assert.Equal(t, ActionEnvelopeMaxTTL, TerminalEnvelopeMaxTTL)
}

func TestTerminalContentBindsStewardAndShell(t *testing.T) {
	a, err := TerminalContent("steward-a", "bash")
	require.NoError(t, err)
	again, err := TerminalContent("steward-a", "bash")
	require.NoError(t, err)
	assert.Equal(t, a, again, "deterministic")

	b, err := TerminalContent("steward-b", "bash")
	require.NoError(t, err)
	assert.NotEqual(t, a, b)

	otherShell, err := TerminalContent("steward-a", "zsh")
	require.NoError(t, err)
	assert.NotEqual(t, a, otherShell)

	action, err := ActionContent(Action{Verb: "restart", TargetKind: "steward", TargetName: "steward-a"})
	require.NoError(t, err)
	assert.NotEqual(t, a, action)

	assert.Equal(t, `{"v":1,"verb":"terminal.open","target_kind":"steward","target_name":"steward-a","parameters":{"shell":"bash"}}`, string(a))
}

func TestTerminalPurposeSeparatesEnvelopes(t *testing.T) {
	content, err := TerminalContent("steward-a", "bash")
	require.NoError(t, err)
	mk := func(shell string) Envelope {
		return Envelope{Content: content, Shell: shell, Targets: []string{"steward-a"}, Nonce: "n1", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	}
	tc, err := CanonicalBytes(mk(TerminalShell))
	require.NoError(t, err)
	ac, err := CanonicalBytes(mk(ActionShell))
	require.NoError(t, err)
	assert.False(t, bytes.Equal(tc, ac))

	th, err := ChallengeHash(mk(TerminalShell))
	require.NoError(t, err)
	ah, err := ChallengeHash(mk(ActionShell))
	require.NoError(t, err)
	assert.NotEqual(t, th, ah)
}

func TestTerminalContentRejectsInvalid(t *testing.T) {
	cases := map[string][2]string{
		"empty steward":   {"", "bash"},
		"empty shell":     {"steward-a", ""},
		"control steward": {"steward\n-a", "bash"},
		"control shell":   {"steward-a", "ba\x00sh"},
		"tab shell":       {"steward-a", "ba\tsh"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := TerminalContent(c[0], c[1])
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidEnvelope))
			assert.Nil(t, out)
		})
	}
}
