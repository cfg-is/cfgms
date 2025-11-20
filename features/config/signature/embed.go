// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors

package signature

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// SignAndEmbed signs configuration data and embeds the signature into the YAML.
// The configuration is first canonicalized (parsed and re-marshaled) to ensure
// consistent signature verification regardless of original formatting.
func SignAndEmbed(signer Signer, configData []byte) ([]byte, error) {
	// Parse the config as generic YAML
	var config map[string]interface{}
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration YAML: %w", err)
	}

	// Marshal to canonical form for signing
	canonicalData, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal canonical configuration: %w", err)
	}

	// Sign the canonical form
	sig, err := signer.Sign(canonicalData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign configuration: %w", err)
	}

	// Add signature to config
	config[SignatureMetadataKey] = map[string]interface{}{
		"algorithm":       string(sig.Algorithm),
		"signature":       sig.Signature,
		"timestamp":       sig.Timestamp,
		"key_fingerprint": sig.KeyFingerprint,
	}

	// Marshal back to YAML with signature
	signedData, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed configuration: %w", err)
	}

	return signedData, nil
}

// ExtractAndVerify extracts the signature from signed YAML data and verifies it.
// Returns the original unsigned configuration data if verification succeeds.
func ExtractAndVerify(verifier Verifier, signedData []byte) ([]byte, error) {
	// Parse the signed config
	var config map[string]interface{}
	if err := yaml.Unmarshal(signedData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse signed configuration: %w", err)
	}

	// Extract signature
	sigData, ok := config[SignatureMetadataKey]
	if !ok {
		return nil, ErrMissingSignature
	}

	// Parse signature struct
	sig, err := parseSignatureFromMap(sigData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	// Remove signature from config to get original data
	delete(config, SignatureMetadataKey)

	// Marshal back to YAML to get original data for verification
	originalData, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal original configuration: %w", err)
	}

	// Verify signature
	if err := verifier.Verify(originalData, sig); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return originalData, nil
}

// ExtractSignature extracts the signature from signed YAML data without verification.
// Returns the signature and the original unsigned configuration data.
func ExtractSignature(signedData []byte) (*ConfigSignature, []byte, error) {
	// Parse the signed config
	var config map[string]interface{}
	if err := yaml.Unmarshal(signedData, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to parse signed configuration: %w", err)
	}

	// Extract signature
	sigData, ok := config[SignatureMetadataKey]
	if !ok {
		return nil, nil, ErrMissingSignature
	}

	// Parse signature struct
	sig, err := parseSignatureFromMap(sigData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	// Remove signature from config to get original data
	delete(config, SignatureMetadataKey)

	// Marshal back to YAML
	originalData, err := yaml.Marshal(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal original configuration: %w", err)
	}

	return sig, originalData, nil
}

// HasSignature checks if the configuration data contains an embedded signature.
func HasSignature(data []byte) bool {
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return false
	}
	_, ok := config[SignatureMetadataKey]
	return ok
}

// parseSignatureFromMap converts a map to a ConfigSignature struct.
func parseSignatureFromMap(data interface{}) (*ConfigSignature, error) {
	m, ok := data.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("signature must be a map")
	}

	sig := &ConfigSignature{}

	// Algorithm
	if alg, ok := m["algorithm"].(string); ok {
		sig.Algorithm = Algorithm(alg)
	} else {
		return nil, fmt.Errorf("missing or invalid algorithm")
	}

	// Signature
	if s, ok := m["signature"].(string); ok {
		sig.Signature = s
	} else {
		return nil, fmt.Errorf("missing or invalid signature")
	}

	// Timestamp
	switch t := m["timestamp"].(type) {
	case int:
		sig.Timestamp = int64(t)
	case int64:
		sig.Timestamp = t
	case float64:
		sig.Timestamp = int64(t)
	default:
		// Timestamp is optional
	}

	// Key fingerprint
	if fp, ok := m["key_fingerprint"].(string); ok {
		sig.KeyFingerprint = fp
	}

	return sig, nil
}
