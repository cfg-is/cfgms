// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle

import "regexp"

// maxVersionLen bounds the length of a version string before the pattern runs.
const maxVersionLen = 256

// exactSemver is semver.org's own grammar for a version with no `v` prefix:
// MAJOR.MINOR.PATCH, an optional dot-separated pre-release and optional build
// metadata. Numeric identifiers carry no leading zeros.
var exactSemver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
	`(-((0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
	`(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$`)

// IsExactSemver reports whether v is exactly one semantic version,
// MAJOR.MINOR.PATCH with optional pre-release and build metadata and no `v`
// prefix. Constraints (^1.0.0, >=1.0.0), aliases (latest) and the empty string
// are not exact versions. A bundle's manifest version names one immutable
// release, so anything but an exact version is refused.
func IsExactSemver(v string) bool {
	if v == "" || len(v) > maxVersionLen {
		return false
	}
	return exactSemver.MatchString(v)
}
