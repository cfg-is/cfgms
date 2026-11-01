// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Export bridges for package audit_test — compiled exclusively by go test.

// GenerateChecksum exposes (*Manager).generateChecksum for integrity verification tests.
var GenerateChecksum = (*Manager).generateChecksum

// BuildEntry exposes (*AuditEventBuilder).build for builder unit tests.
var BuildEntry = (*AuditEventBuilder).build

// GenerateChecksumWithFormat computes an HMAC-SHA256 over an explicit,
// caller-supplied hash input using m's HMAC key. It exists solely so
// TestVerifyChain_PreChangeChecksumFormulaIsRejected can reconstruct a
// pre-#4098 (11-field formula) checksum without exposing hmacKey directly,
// to prove that widening the checksum in generateChecksum is a hard break
// (AC2): an entry checksummed under the old formula must be reported as a
// mismatch by VerifyChain, not silently accepted.
func GenerateChecksumWithFormat(m *Manager, hashInput string) string {
	mac := hmac.New(sha256.New, m.hmacKey)
	_, _ = mac.Write([]byte(hashInput))
	return hex.EncodeToString(mac.Sum(nil))
}
