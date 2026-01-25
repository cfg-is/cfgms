// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package signature

import (
	"fmt"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"google.golang.org/protobuf/proto"
)

// SignProtoConfig signs a protobuf StewardConfig and returns a SignedConfig
func SignProtoConfig(signer Signer, config *controller.StewardConfig) (*controller.SignedConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	// Marshal to deterministic protobuf bytes for signing
	configBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	// Sign the canonical bytes
	sig, err := signer.Sign(configBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign configuration: %w", err)
	}

	// Create signed config with signature
	signedConfig := &controller.SignedConfig{
		Config: config,
		Signature: &controller.ConfigSignature{
			Algorithm:      string(sig.Algorithm),
			Signature:      sig.Signature,
			Timestamp:      sig.Timestamp,
			KeyFingerprint: sig.KeyFingerprint,
		},
	}

	return signedConfig, nil
}

// VerifyProtoConfig verifies a signed protobuf config and returns the unsigned config
func VerifyProtoConfig(verifier Verifier, signedConfig *controller.SignedConfig) (*controller.StewardConfig, error) {
	if signedConfig == nil {
		return nil, fmt.Errorf("signed config is nil")
	}

	if signedConfig.Config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	if signedConfig.Signature == nil {
		return nil, ErrMissingSignature
	}

	// Marshal config to deterministic bytes for verification
	configBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signedConfig.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	// Convert protobuf signature to internal signature type
	sig := &ConfigSignature{
		Algorithm:      Algorithm(signedConfig.Signature.Algorithm),
		Signature:      signedConfig.Signature.Signature,
		Timestamp:      signedConfig.Signature.Timestamp,
		KeyFingerprint: signedConfig.Signature.KeyFingerprint,
	}

	// Verify signature
	if err := verifier.Verify(configBytes, sig); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return signedConfig.Config, nil
}
