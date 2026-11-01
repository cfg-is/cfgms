// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package operatorpayload

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionContent_GoldenBytes(t *testing.T) {
	got, err := ActionContent(Action{
		Verb:       "restart",
		TargetKind: "service",
		TargetName: "nginx",
		Parameters: map[string]string{"zeta": "1", "alpha": "a<b>&c", "mid": "ü"},
	})
	require.NoError(t, err)

	want, err := os.ReadFile("testdata/action_content.golden")
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))
}

func TestActionContent_Deterministic(t *testing.T) {
	first := map[string]string{}
	second := map[string]string{}
	keys := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for _, k := range keys {
		first[k] = "v-" + k
	}
	for i := len(keys) - 1; i >= 0; i-- {
		second[keys[i]] = "v-" + keys[i]
	}
	for i := 0; i < 20; i++ {
		a, err := ActionContent(Action{Verb: "v", TargetKind: "k", TargetName: "n", Parameters: first})
		require.NoError(t, err)
		b, err := ActionContent(Action{Verb: "v", TargetKind: "k", TargetName: "n", Parameters: second})
		require.NoError(t, err)
		assert.Equal(t, a, b)
	}
}

func TestActionContent_NilAndEmptyParametersMatch(t *testing.T) {
	a, err := ActionContent(Action{Verb: "v", TargetKind: "k", TargetName: "n"})
	require.NoError(t, err)
	b, err := ActionContent(Action{Verb: "v", TargetKind: "k", TargetName: "n", Parameters: map[string]string{}})
	require.NoError(t, err)
	assert.Equal(t, a, b)
	assert.Equal(t, `{"v":1,"verb":"v","target_kind":"k","target_name":"n","parameters":{}}`, string(a))
}

func TestActionContent_Rejects(t *testing.T) {
	ok := Action{Verb: "v", TargetKind: "k", TargetName: "n", Parameters: map[string]string{"p": "x"}}
	cases := map[string]func(*Action){
		"empty verb":        func(a *Action) { a.Verb = "" },
		"empty target kind": func(a *Action) { a.TargetKind = "" },
		"empty target name": func(a *Action) { a.TargetName = "" },
		"empty param key":   func(a *Action) { a.Parameters = map[string]string{"": "x"} },
		"control in verb":   func(a *Action) { a.Verb = "re\nstart" },
		"control in kind":   func(a *Action) { a.TargetKind = "k\x00" },
		"control in name":   func(a *Action) { a.TargetName = "n\t" },
		"control in key":    func(a *Action) { a.Parameters = map[string]string{"p\r": "x"} },
		"invalid utf8":      func(a *Action) { a.TargetName = "n\xff" },
		"control in value":  func(a *Action) { a.Parameters = map[string]string{"p": "x\x7f"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := ok
			mutate(&a)
			_, err := ActionContent(a)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidEnvelope))
		})
	}
}

func TestActionShell_FeedsCanonicalBytes(t *testing.T) {
	content, err := ActionContent(Action{Verb: "v", TargetKind: "k", TargetName: "n"})
	require.NoError(t, err)
	_, err = CanonicalBytes(Envelope{
		Content: content, Shell: ActionShell, Targets: []string{"s1"}, Nonce: "n1",
		ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err)
}
