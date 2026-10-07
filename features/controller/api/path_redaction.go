// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import "strings"

// redactedPathSegment replaces a credential carried in a URL path segment.
const redactedPathSegment = "[REDACTED]"

// registrationTokensPrefix is the route prefix whose next segment is a steward
// registration token (routes_registration_tokens.go) — a bearer credential.
const registrationTokensPrefix = "/api/v1/registration/tokens/"

// redactCredentialPath returns path with any credential-bearing segment
// replaced, for logging (Issue #4520). Two routes carry a bearer credential in
// the path:
//
//   - /enroll/{token}: the SPA's first-passkey enrollment link, a single-use
//     token that enrolls a passkey for its account.
//   - /api/v1/registration/tokens/{token}[/revoke]: a steward registration token.
//     /api/v1/registration/tokens/{tenant_id}/rotate carries a tenant ID, not a
//     credential, and is left as is.
//
// Every other path is returned unchanged.
func redactCredentialPath(path string) string {
	if rest, ok := strings.CutPrefix(path, "/enroll/"); ok && rest != "" {
		return "/enroll/" + redactedPathSegment
	}
	if rest, ok := strings.CutPrefix(path, registrationTokensPrefix); ok && rest != "" {
		segment, tail, _ := strings.Cut(rest, "/")
		if segment != "" && tail != "rotate" {
			if tail != "" {
				return registrationTokensPrefix + redactedPathSegment + "/" + tail
			}
			return registrationTokensPrefix + redactedPathSegment
		}
	}
	return path
}
