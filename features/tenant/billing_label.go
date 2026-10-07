// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

const (
	billingLabelPrefix = "bl-"
	billingLabelBytes  = 10 // 80 random bits
	// billingLabelMinBody is the minimum label body length accepted by
	// ValidBillingLabel. Labels written by the database migration are lowercase
	// hex rather than base32, so the validator accepts [a-z0-9].
	billingLabelMinBody = 16
)

var billingLabelEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateBillingLabel returns a random, opaque billing label: a fixed prefix
// plus 80 random bits from crypto/rand, lowercase base32 (URL-safe). It is
// generated once at tenant creation and is never derived from the tenant name,
// ID or any other field (ADR-025 Amendment 6, A6.2).
func GenerateBillingLabel() (string, error) {
	b := make([]byte, billingLabelBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate billing label: %w", err)
	}
	return billingLabelPrefix + strings.ToLower(billingLabelEncoding.EncodeToString(b)), nil
}

// ValidBillingLabel reports whether s has the billing label shape: the fixed
// prefix followed by at least 16 lowercase alphanumeric characters.
func ValidBillingLabel(s string) bool {
	body, ok := strings.CutPrefix(s, billingLabelPrefix)
	if !ok || len(body) < billingLabelMinBody {
		return false
	}
	for _, c := range body {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
