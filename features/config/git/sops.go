// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2025 CFGMS Contributors
package git

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SOPSManager handles SOPS encryption and decryption operations
//
// #nosec G304 - SOPS configuration management requires file access for:
// - Loading encrypted configuration files from controlled git repositories
// - Reading SOPS configuration and keys from designated paths
// - Processing encrypted secrets for configuration management
// All file operations are within controlled repository contexts
type SOPSManager struct {
	sopsPath string                              // Path to SOPS binary
	onChmod  func(path string, mode os.FileMode) // test-only hook; nil in production
}

// NewSOPSManager creates a new SOPS manager
func NewSOPSManager() *SOPSManager {
	// Try to find SOPS binary in PATH
	sopsPath, err := exec.LookPath("sops")
	if err != nil {
		// Default to "sops" and let exec.Command fail later if not found
		sopsPath = "sops"
	}

	return &SOPSManager{
		sopsPath: sopsPath,
	}
}

// IsSOPSAvailable checks if SOPS is available on the system
func (s *SOPSManager) IsSOPSAvailable(ctx context.Context) bool {
	// #nosec G204 - SOPS encryption management requires SOPS binary execution
	cmd := exec.CommandContext(ctx, s.sopsPath, "--version")
	return cmd.Run() == nil
}

// IsSOPSEncrypted checks if content is SOPS encrypted
func (s *SOPSManager) IsSOPSEncrypted(content []byte) bool {
	// Check for SOPS metadata section
	contentStr := string(content)
	return strings.Contains(contentStr, "sops:") &&
		strings.Contains(contentStr, "ENC[")
}

// EncryptContent encrypts content using SOPS.
// The plaintext temp file is chmod-0000 immediately after write, before SOPS is invoked,
// to minimize the window during which plaintext is readable on disk.
func (s *SOPSManager) EncryptContent(ctx context.Context, content []byte, config *SOPSConfig, filePath string) ([]byte, error) {
	if !config.Enabled {
		return content, nil
	}

	// Preserve file extension for SOPS to detect format
	ext := filepath.Ext(filePath)
	if ext == "" {
		ext = ".yaml"
	}

	// Write plaintext to temp file
	plainTmpFile, err := os.CreateTemp("", fmt.Sprintf("cfgms-sops-plain-*%s", ext))
	if err != nil {
		return nil, fmt.Errorf("failed to create plaintext temp file: %w", err)
	}
	plainTmpPath := plainTmpFile.Name()

	if _, err := plainTmpFile.Write(content); err != nil {
		_ = plainTmpFile.Close()
		_ = os.Remove(plainTmpPath)
		return nil, fmt.Errorf("failed to write plaintext temp file: %w", err)
	}
	if err := plainTmpFile.Close(); err != nil {
		_ = os.Remove(plainTmpPath)
		return nil, fmt.Errorf("failed to close plaintext temp file: %w", err)
	}

	// Minimize read window: remove all access immediately after write, before SOPS exec.
	// There is a small race between WriteFile and Chmod that cannot be closed without
	// O_TMPFILE / /proc/self/fd tricks that are unreliable with SOPS --in-place.
	if err := os.Chmod(plainTmpPath, 0000); err != nil {
		_ = os.Remove(plainTmpPath)
		return nil, fmt.Errorf("failed to chmod plaintext temp file: %w", err)
	}
	if s.onChmod != nil {
		s.onChmod(plainTmpPath, 0000)
	}
	defer func() { _ = os.Remove(plainTmpPath) }()

	// Create output temp file for ciphertext (empty; SOPS writes into it via --output)
	encTmpFile, err := os.CreateTemp("", fmt.Sprintf("cfgms-sops-enc-*%s", ext))
	if err != nil {
		return nil, fmt.Errorf("failed to create ciphertext temp file: %w", err)
	}
	encTmpPath := encTmpFile.Name()
	if err := encTmpFile.Close(); err != nil {
		_ = os.Remove(encTmpPath)
		return nil, fmt.Errorf("failed to close ciphertext temp file: %w", err)
	}
	defer func() { _ = os.Remove(encTmpPath) }()

	// Determine KMS key to use
	kmsKey, err := s.selectKMSKey(filePath, config)
	if err != nil {
		return nil, fmt.Errorf("failed to select KMS key: %w", err)
	}

	// Build SOPS encrypt command; write ciphertext to separate output file
	args := []string{"--encrypt", "--output", encTmpPath}

	// Add KMS configuration
	if kmsKey != "" {
		provider := s.getKMSProvider(kmsKey, config)
		if provider != nil {
			switch provider.Type {
			case "aws":
				args = append(args, "--kms", kmsKey)
			case "gcp":
				args = append(args, "--gcp-kms", kmsKey)
			case "azure":
				args = append(args, "--azure-kv", kmsKey)
			case "pgp":
				args = append(args, "--pgp", provider.KeyID)
			}
		}
	}

	// Add encrypted field regex if auto-encrypt is enabled
	if config.AutoEncrypt && len(config.SensitiveFieldPatterns) > 0 {
		encryptedRegex := strings.Join(config.SensitiveFieldPatterns, "|")
		args = append(args, "--encrypted-regex", fmt.Sprintf("^(%s)$", encryptedRegex))
	}

	args = append(args, plainTmpPath)

	// Execute SOPS encryption with separate stdout/stderr buffers
	var stdout, stderr bytes.Buffer
	// #nosec G204 - SOPS encryption management requires SOPS binary execution
	cmd := exec.CommandContext(ctx, s.sopsPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sops encrypt: %w (stderr: %s)", err, stderr.String())
	}

	// Read encrypted content from the output temp file
	// #nosec G304 - SOPS operation requires reading temporary encrypted files
	encryptedContent, err := os.ReadFile(encTmpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted content: %w", err)
	}

	return encryptedContent, nil
}

// DecryptContent decrypts SOPS encrypted content.
// Encrypted content is piped to sops via stdin; no plaintext temp file is written.
func (s *SOPSManager) DecryptContent(ctx context.Context, content []byte) ([]byte, error) {
	if !s.IsSOPSEncrypted(content) {
		return content, nil
	}

	var stdout, stderr bytes.Buffer
	// #nosec G204 - SOPS encryption management requires SOPS binary execution
	cmd := exec.CommandContext(ctx, s.sopsPath, "--decrypt", "--input-type", "yaml", "--output-type", "yaml", "/dev/stdin")
	cmd.Stdin = bytes.NewReader(content)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sops decrypt: %w (stderr: %s)", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// ShouldEncryptFile determines if a file should be encrypted based on rules
func (s *SOPSManager) ShouldEncryptFile(filePath string, config *SOPSConfig) (bool, string) {
	if !config.Enabled {
		return false, ""
	}

	// Check encryption rules
	for _, rule := range config.EncryptionRules {
		matched, err := regexp.MatchString(rule.PathRegex, filePath)
		if err != nil {
			continue
		}
		if matched {
			return true, rule.KMSKey
		}
	}

	// Check for sensitive fields if auto-encrypt is enabled
	if config.AutoEncrypt {
		// Sensitive-field detection uses file naming conventions; content parsing is deferred.
		lowerPath := strings.ToLower(filePath)
		if strings.Contains(lowerPath, "secret") ||
			strings.Contains(lowerPath, "password") ||
			strings.Contains(lowerPath, "credential") ||
			strings.HasSuffix(lowerPath, ".sops.yaml") ||
			strings.HasSuffix(lowerPath, ".sops.yml") {
			// Use first available KMS key
			for _, provider := range config.KMSProviders {
				return true, provider.KeyID
			}
		}
	}

	return false, ""
}

// ValidateSOPSConfig validates SOPS configuration
func (s *SOPSManager) ValidateSOPSConfig(ctx context.Context, config *SOPSConfig) error {
	if !config.Enabled {
		return nil
	}

	// Check if SOPS is available
	if !s.IsSOPSAvailable(ctx) {
		return fmt.Errorf("SOPS binary not found - please install SOPS")
	}

	// Validate KMS providers
	for name, provider := range config.KMSProviders {
		if err := s.validateKMSProvider(name, provider); err != nil {
			return fmt.Errorf("invalid KMS provider %s: %w", name, err)
		}
	}

	// Validate encryption rules
	for i, rule := range config.EncryptionRules {
		if _, err := regexp.Compile(rule.PathRegex); err != nil {
			return fmt.Errorf("invalid regex in rule %d: %w", i, err)
		}

		if rule.KMSKey == "" {
			return fmt.Errorf("missing KMS key in rule %d", i)
		}
	}

	return nil
}

// GenerateSOPSConfig generates a .sops.yaml configuration file
func (s *SOPSManager) GenerateSOPSConfig(config *SOPSConfig, repoPath string) error {
	if !config.Enabled {
		return nil
	}

	sopsConfig := map[string]interface{}{
		"creation_rules": s.buildCreationRules(config),
	}

	// Marshal to YAML
	content, err := yaml.Marshal(sopsConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal SOPS config: %w", err)
	}

	// Write .sops.yaml file
	sopsPath := filepath.Join(repoPath, ".sops.yaml")
	if err := os.WriteFile(sopsPath, content, 0600); err != nil {
		return fmt.Errorf("failed to write .sops.yaml: %w", err)
	}

	return nil
}

// Helper methods

func (s *SOPSManager) selectKMSKey(filePath string, config *SOPSConfig) (string, error) {
	// Check encryption rules first
	for _, rule := range config.EncryptionRules {
		matched, err := regexp.MatchString(rule.PathRegex, filePath)
		if err != nil {
			continue
		}
		if matched {
			return rule.KMSKey, nil
		}
	}

	// Fall back to first available provider
	for _, provider := range config.KMSProviders {
		return provider.KeyID, nil
	}

	return "", fmt.Errorf("no KMS key found for file: %s", filePath)
}

func (s *SOPSManager) getKMSProvider(keyID string, config *SOPSConfig) *KMSProvider {
	for _, provider := range config.KMSProviders {
		if provider.KeyID == keyID {
			return &provider
		}
	}
	return nil
}

func (s *SOPSManager) validateKMSProvider(name string, provider KMSProvider) error {
	switch provider.Type {
	case "aws":
		if provider.KeyID == "" {
			return fmt.Errorf("AWS KMS provider requires key_id")
		}
		// Validate ARN format
		if !strings.HasPrefix(provider.KeyID, "arn:aws:kms:") {
			return fmt.Errorf("AWS KMS key_id must be a valid ARN")
		}
	case "gcp":
		if provider.KeyID == "" {
			return fmt.Errorf("GCP KMS provider requires key_id")
		}
		// Validate resource ID format
		if !strings.Contains(provider.KeyID, "projects/") {
			return fmt.Errorf("GCP KMS key_id must be a valid resource ID")
		}
	case "azure":
		if provider.KeyID == "" {
			return fmt.Errorf("azure Key Vault provider requires key_id")
		}
		// Validate vault URL format
		if !strings.Contains(provider.KeyID, "vault.azure.net") {
			return fmt.Errorf("azure Key Vault key_id must be a valid vault URL")
		}
	case "pgp":
		if provider.KeyID == "" {
			return fmt.Errorf("PGP provider requires key_id (fingerprint)")
		}
		// Validate fingerprint format (basic check)
		if len(provider.KeyID) != 40 && len(provider.KeyID) != 16 {
			return fmt.Errorf("PGP key_id must be a valid fingerprint")
		}
	default:
		return fmt.Errorf("unsupported provider type: %s", provider.Type)
	}

	return nil
}

func (s *SOPSManager) buildCreationRules(config *SOPSConfig) []map[string]interface{} {
	var rules []map[string]interface{}

	for _, rule := range config.EncryptionRules {
		ruleMap := map[string]interface{}{
			"path_regex": rule.PathRegex,
		}

		// Find the provider for this key
		provider := s.getKMSProvider(rule.KMSKey, config)
		if provider != nil {
			switch provider.Type {
			case "aws":
				ruleMap["kms"] = rule.KMSKey
				if provider.Profile != "" {
					ruleMap["aws_profile"] = provider.Profile
				}
			case "gcp":
				ruleMap["gcp_kms"] = rule.KMSKey
			case "azure":
				ruleMap["azure_kv"] = rule.KMSKey
			case "pgp":
				ruleMap["pgp"] = provider.KeyID
			}
		}

		// Add field patterns if specified
		if len(rule.FieldPatterns) > 0 {
			encryptedRegex := strings.Join(rule.FieldPatterns, "|")
			ruleMap["encrypted_regex"] = fmt.Sprintf("^(%s)$", encryptedRegex)
		}

		rules = append(rules, ruleMap)
	}

	return rules
}

// PreCommitSOPSCheck validates SOPS encrypted files before commit
func (s *SOPSManager) PreCommitSOPSCheck(ctx context.Context, files []string, repoPath string) error {
	for _, file := range files {
		fullPath := filepath.Join(repoPath, file)
		// #nosec G304 - SOPS pre-commit check requires reading files within repository
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue // Skip files that can't be read
		}

		// Check if file should be encrypted but isn't
		if s.shouldBeEncrypted(file, content) && !s.IsSOPSEncrypted(content) {
			return fmt.Errorf("file %s contains sensitive data but is not SOPS encrypted", file)
		}

		// Check if encrypted file can be decrypted (validation)
		if s.IsSOPSEncrypted(content) {
			if _, err := s.DecryptContent(ctx, content); err != nil {
				return fmt.Errorf("SOPS encrypted file %s cannot be decrypted: %w", file, err)
			}
		}
	}

	return nil
}

func (s *SOPSManager) shouldBeEncrypted(filePath string, content []byte) bool {
	// Check file name patterns
	lowerPath := strings.ToLower(filePath)
	if strings.Contains(lowerPath, "secret") ||
		strings.Contains(lowerPath, "password") ||
		strings.Contains(lowerPath, "credential") {
		return true
	}

	// Check content for sensitive patterns
	contentStr := strings.ToLower(string(content))
	sensitivePatterns := []string{
		"password:",
		"secret:",
		"private_key:",
		"api_key:",
		"token:",
		"credential:",
		"client_secret:",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(contentStr, pattern) {
			return true
		}
	}

	return false
}

// GetSOPSMetadata extracts SOPS metadata from encrypted content
func (s *SOPSManager) GetSOPSMetadata(content []byte) (*SOPSMetadata, error) {
	if !s.IsSOPSEncrypted(content) {
		return nil, fmt.Errorf("content is not SOPS encrypted")
	}

	var data map[string]interface{}
	if err := yaml.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	sopsData, exists := data["sops"]
	if !exists {
		return nil, fmt.Errorf("no SOPS metadata found")
	}

	sopsMap, ok := sopsData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid SOPS metadata format")
	}

	metadata := &SOPSMetadata{
		Version: getString(sopsMap, "version"),
	}

	// Extract KMS information
	if kms, exists := sopsMap["kms"]; exists {
		if kmsList, ok := kms.([]interface{}); ok {
			for _, item := range kmsList {
				if kmsItem, ok := item.(map[string]interface{}); ok {
					metadata.KMSKeys = append(metadata.KMSKeys, getString(kmsItem, "arn"))
				}
			}
		}
	}

	// Extract encrypted regex
	metadata.EncryptedRegex = getString(sopsMap, "encrypted_regex")

	return metadata, nil
}

// SOPSMetadata contains SOPS metadata extracted from encrypted files
type SOPSMetadata struct {
	Version        string   `json:"version"`
	KMSKeys        []string `json:"kms_keys"`
	EncryptedRegex string   `json:"encrypted_regex"`
	CreatedAt      string   `json:"created_at"`
	LastModified   string   `json:"last_modified"`
}

func getString(m map[string]interface{}, key string) string {
	if val, exists := m[key]; exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}
