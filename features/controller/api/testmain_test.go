// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2591: reduce argon2id cost for the test suite so the package does not
// hit the 5-minute wall on 2–3 vCPU GitHub-hosted macOS/Windows runners.
//
// Root cause: features/controller/api grew to 89 files / ~25k LOC with repeated
// argon2id KDF calls across ~400 test cases (account creation + every login
// attempt). TestWebLogin_RateLimited alone drives up to 100 consecutive KDF calls
// for timing-uniformity on the locked-account path. At OWASP production cost
// (19 MiB, t=2) each call takes ~22 ms on a 16-core dev container; on a 2-vCPU
// hosted runner with -race instrumentation the per-call overhead is 10–15×,
// pushing the full suite past the 5-minute timeout.
//
// Fix: TestMain (runs once before the first Test* function) overrides the active
// cost vars to the minimum functional values. The full argon2id code path —
// hash derivation, PHC encoding, constant-time comparison — is still exercised.
// The OWASP production values are pinned separately by
// TestWebAccounts_HashParametersEncodedInPHCString, which calls
// encodeArgon2idHash with the *Default constants directly.
package api

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Minimal argon2id cost: functional but fast. Each KDF call drops from ~22 ms
	// (production, 19 MiB) to < 1 ms (64 KiB), eliminating the timeout risk on
	// contended 2-vCPU hosted runners without skipping any code path.
	webArgon2Time = 1
	webArgon2Memory = 64 // 64 KiB — lowest memory that still exercises the KDF
	webArgon2Threads = 1
	os.Exit(m.Run())
}
