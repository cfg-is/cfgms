// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"strings"
	"testing"
)

func TestRegistrationTokenLookupKeyIsDeterministicAndNonPlaintext(t *testing.T) {
	const raw = "abcdefghijklmnopqrstuvwxyz"
	first := RegistrationTokenLookupKey(raw)
	second := RegistrationTokenLookupKey(raw)
	if first != second {
		t.Fatal("token lookup key is not deterministic")
	}
	if first == raw || strings.Contains(first, raw) {
		t.Fatal("token lookup key contains the raw credential")
	}
	if RegistrationTokenLookupKey(first) != first {
		t.Fatal("lookup key hashing is not idempotent")
	}
	if got := RegistrationTokenDisplayPrefix(first); got != "abcdef" {
		t.Fatalf("display prefix = %q, want abcdef", got)
	}
}
