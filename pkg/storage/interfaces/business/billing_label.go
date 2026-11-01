// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

const (
	billingLabelPrefix = "bl-"
	billingLabelBytes  = 10 // 80 random bits
)

var billingLabelEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewBillingLabel returns a random opaque tenant billing label read from
// crypto/rand. Tenant stores use it to fill a label that a caller left empty
// (rows that predate the column, or direct store writes); Manager.CreateTenant
// generates its own. The value is never derived from any tenant field.
func NewBillingLabel() (string, error) {
	b := make([]byte, billingLabelBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return billingLabelPrefix + strings.ToLower(billingLabelEncoding.EncodeToString(b)), nil
}
