// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package graph

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGraphPasswordProfile_JSONTagUnchanged(t *testing.T) {
	data, err := json.Marshal(PasswordProfile{ForceResetAtNextSignIn: true})
	require.NoError(t, err)
	require.Contains(t, string(data), `"forceChangePasswordNextSignIn":true`)
}
