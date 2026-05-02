// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"fmt"
	"os"
)

// newClientFromFlags creates an APIClient from resolved flag values.
// Reads the CA cert from disk if caCertPath is non-empty, then delegates to NewAPIClient.
// Env var resolution is the responsibility of each command's get*Client() function.
func newClientFromFlags(url, apiKey, caCertPath string, insecure bool) (*APIClient, error) {
	var caCertPEM []byte
	if caCertPath != "" {
		var err error
		// #nosec G304 - CA certificate path is intentionally provided by user via CLI flag or env var
		caCertPEM, err = os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
	}

	cfg := &APIClientConfig{
		BaseURL:     url,
		APIKey:      apiKey,
		CACertPEM:   caCertPEM,
		TLSInsecure: insecure,
	}

	return NewAPIClient(cfg)
}
