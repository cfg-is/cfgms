// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEffectiveSigningPolicy(t *testing.T) {
	tests := []struct {
		name            string
		scriptPolicy    SigningPolicy
		stewardMinimum  SigningPolicy
		expectedPolicy  SigningPolicy
	}{
		{
			name:           "script none, steward none — returns none",
			scriptPolicy:   SigningPolicyNone,
			stewardMinimum: SigningPolicyNone,
			expectedPolicy: SigningPolicyNone,
		},
		{
			name:           "script required, steward none — script wins (more restrictive)",
			scriptPolicy:   SigningPolicyRequired,
			stewardMinimum: SigningPolicyNone,
			expectedPolicy: SigningPolicyRequired,
		},
		{
			name:           "script none, steward required — steward wins (floor enforced)",
			scriptPolicy:   SigningPolicyNone,
			stewardMinimum: SigningPolicyRequired,
			expectedPolicy: SigningPolicyRequired,
		},
		{
			name:           "script optional, steward required — steward wins",
			scriptPolicy:   SigningPolicyOptional,
			stewardMinimum: SigningPolicyRequired,
			expectedPolicy: SigningPolicyRequired,
		},
		{
			name:           "script required, steward optional — script wins",
			scriptPolicy:   SigningPolicyRequired,
			stewardMinimum: SigningPolicyOptional,
			expectedPolicy: SigningPolicyRequired,
		},
		{
			name:           "script optional, steward optional — returns optional",
			scriptPolicy:   SigningPolicyOptional,
			stewardMinimum: SigningPolicyOptional,
			expectedPolicy: SigningPolicyOptional,
		},
		{
			name:           "script none, steward optional — steward floor applied",
			scriptPolicy:   SigningPolicyNone,
			stewardMinimum: SigningPolicyOptional,
			expectedPolicy: SigningPolicyOptional,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ScriptConfig{
				SigningPolicy: tt.scriptPolicy,
			}
			result := cfg.EffectiveSigningPolicy(tt.stewardMinimum)
			assert.Equal(t, tt.expectedPolicy, result)
		})
	}
}
