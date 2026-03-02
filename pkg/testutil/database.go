// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package testutil

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

// GenerateSecurePassword creates a cryptographically secure random password for testing.
// Generates 32 bytes of random data, base64-encodes, and truncates to 25 characters.
func GenerateSecurePassword() string {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return fmt.Sprintf("test-password-%d", time.Now().Unix())
	}

	password := base64.StdEncoding.EncodeToString(randomBytes)
	password = strings.ReplaceAll(password, "=", "")
	password = strings.ReplaceAll(password, "+", "")
	password = strings.ReplaceAll(password, "/", "")

	if len(password) > 25 {
		password = password[:25]
	}

	return password
}

// GetTestDBPassword returns the test database password from CFGMS_TEST_DB_PASSWORD,
// or generates a secure random one if not set.
func GetTestDBPassword() string {
	if pw := os.Getenv("CFGMS_TEST_DB_PASSWORD"); pw != "" {
		return pw
	}
	return GenerateSecurePassword()
}

// GetTestTimescalePassword returns the test TimescaleDB password from
// CFGMS_TEST_TIMESCALEDB_PASSWORD, or generates a secure random one if not set.
func GetTestTimescalePassword() string {
	if pw := os.Getenv("CFGMS_TEST_TIMESCALEDB_PASSWORD"); pw != "" {
		return pw
	}
	return GenerateSecurePassword()
}
