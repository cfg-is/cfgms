// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRedactCredentialPath guards Issue #4520: bearer credentials carried in a
// URL path must never reach the request log or the authorization audit.
func TestRedactCredentialPath(t *testing.T) {
	const token = "277090d80e09bccc559079e27bdbec0ad59662ce"
	cases := map[string]string{
		"/enroll/" + token:                                  "/enroll/[REDACTED]",
		"/api/v1/registration/tokens/" + token:              "/api/v1/registration/tokens/[REDACTED]",
		"/api/v1/registration/tokens/" + token + "/revoke":  "/api/v1/registration/tokens/[REDACTED]/revoke",
		"/api/v1/registration/tokens/infra-hyperv/rotate":   "/api/v1/registration/tokens/infra-hyperv/rotate",
		"/api/v1/registration/tokens":                       "/api/v1/registration/tokens",
		"/enroll":                                           "/enroll",
		"/api/v1/runs/45455a28-a53e-415a-9736-7d6f57f03445": "/api/v1/runs/45455a28-a53e-415a-9736-7d6f57f03445",
		"/api/v1/web/passkey/enroll/begin":                  "/api/v1/web/passkey/enroll/begin",
	}
	for in, want := range cases {
		got := redactCredentialPath(in)
		assert.Equal(t, want, got, "redactCredentialPath(%q)", in)
		if want != in {
			assert.NotContains(t, got, token, "the credential must not survive redaction")
		}
	}
}
