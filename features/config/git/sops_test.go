package git

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSOPSManager_NewSOPSManager(t *testing.T) {
	manager := NewSOPSManager()
	assert.NotNil(t, manager)
	assert.Equal(t, "sops", manager.sopsPath)
}

func TestSOPSManager_IsSOPSEncrypted(t *testing.T) {
	manager := NewSOPSManager()
	
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "SOPS encrypted content",
			content: `test: value
sops:
    kms:
        - arn: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
          created_at: "2024-01-01T00:00:00Z"
          enc: ENC[AES256_GCM,data:abc123,iv:def456,tag:ghi789,type:str]`,
			expected: true,
		},
		{
			name: "Regular YAML content",
			content: `test: value
config:
    key: plain_value`,
			expected: false,
		},
		{
			name: "Content with sops keyword but not encrypted",
			content: `test: value
description: "This talks about sops but isn't encrypted"`,
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.IsSOPSEncrypted([]byte(tt.content))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSOPSManager_ShouldEncryptFile(t *testing.T) {
	manager := NewSOPSManager()
	
	config := &SOPSConfig{
		Enabled: true,
		KMSProviders: map[string]KMSProvider{
			"aws": {
				Type:  "aws",
				KeyID: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			},
		},
		EncryptionRules: []EncryptionRule{
			{
				PathRegex: `.*secret.*\.yaml$`,
				KMSKey:    "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			},
		},
		AutoEncrypt: true,
	}
	
	tests := []struct {
		name         string
		filePath     string
		expectEncrypt bool
		expectKey    string
	}{
		{
			name:         "Secret file matching rule",
			filePath:     "config/secret-config.yaml",
			expectEncrypt: true,
			expectKey:    "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		},
		{
			name:         "Regular config file",
			filePath:     "config/app-config.yaml",
			expectEncrypt: false,
			expectKey:    "",
		},
		{
			name:         "File with password in name (auto-encrypt)",
			filePath:     "config/password-config.yaml",
			expectEncrypt: true,
			expectKey:    "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		},
		{
			name:         "SOPS file extension",
			filePath:     "config/app.sops.yaml",
			expectEncrypt: true,
			expectKey:    "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldEncrypt, key := manager.ShouldEncryptFile(tt.filePath, config)
			assert.Equal(t, tt.expectEncrypt, shouldEncrypt)
			assert.Equal(t, tt.expectKey, key)
		})
	}
}

func TestSOPSManager_ValidateSOPSConfig(t *testing.T) {
	manager := NewSOPSManager()
	ctx := context.Background()
	
	tests := []struct {
		name      string
		config    *SOPSConfig
		expectErr bool
	}{
		{
			name: "Valid AWS KMS config",
			config: &SOPSConfig{
				Enabled: true,
				KMSProviders: map[string]KMSProvider{
					"aws": {
						Type:  "aws",
						KeyID: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				},
				EncryptionRules: []EncryptionRule{
					{
						PathRegex: `.*\.yaml$`,
						KMSKey:    "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				},
			},
			expectErr: true, // SOPS binary not available in test environment
		},
		{
			name: "Invalid regex in encryption rule",
			config: &SOPSConfig{
				Enabled: true,
				KMSProviders: map[string]KMSProvider{
					"aws": {
						Type:  "aws",
						KeyID: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				},
				EncryptionRules: []EncryptionRule{
					{
						PathRegex: `[invalid regex`,
						KMSKey:    "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				},
			},
			expectErr: true,
		},
		{
			name: "Missing KMS key in rule",
			config: &SOPSConfig{
				Enabled: true,
				KMSProviders: map[string]KMSProvider{
					"aws": {
						Type:  "aws",
						KeyID: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				},
				EncryptionRules: []EncryptionRule{
					{
						PathRegex: `.*\.yaml$`,
						KMSKey:    "", // Missing key
					},
				},
			},
			expectErr: true,
		},
		{
			name: "Disabled config should not error",
			config: &SOPSConfig{
				Enabled: false,
				// Invalid config but disabled
				EncryptionRules: []EncryptionRule{
					{
						PathRegex: `[invalid`,
						KMSKey:    "",
					},
				},
			},
			expectErr: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.ValidateSOPSConfig(ctx, tt.config)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSOPSManager_PreCommitSOPSCheck(t *testing.T) {
	manager := NewSOPSManager()
	ctx := context.Background()
	
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "sops-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Test file with sensitive content
	sensitiveContent := `
password: secret123
api_key: abcd1234
database:
  host: localhost
  user: admin
`
	
	// Test file without sensitive content
	normalContent := `
app:
  name: test-app
  port: 8080
  debug: false
`
	
	// Create test files
	sensitiveFile := "sensitive-config.yaml"
	normalFile := "app-config.yaml"
	
	err = os.WriteFile(tmpDir+"/"+sensitiveFile, []byte(sensitiveContent), 0644)
	require.NoError(t, err)
	
	err = os.WriteFile(tmpDir+"/"+normalFile, []byte(normalContent), 0644)
	require.NoError(t, err)
	
	tests := []struct {
		name      string
		files     []string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "Normal file should pass",
			files:     []string{normalFile},
			expectErr: false,
		},
		{
			name:      "Sensitive file should fail if not encrypted",
			files:     []string{sensitiveFile},
			expectErr: true,
			errMsg:    "contains sensitive data but is not SOPS encrypted",
		},
		{
			name:      "Mixed files should fail due to sensitive file",
			files:     []string{normalFile, sensitiveFile},
			expectErr: true,
			errMsg:    "contains sensitive data but is not SOPS encrypted",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.PreCommitSOPSCheck(ctx, tt.files, tmpDir)
			if tt.expectErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSOPSManager_shouldBeEncrypted(t *testing.T) {
	manager := NewSOPSManager()
	
	tests := []struct {
		name     string
		filePath string
		content  string
		expected bool
	}{
		{
			name:     "File with secret in name",
			filePath: "config/secret-config.yaml",
			content:  "normal: content",
			expected: true,
		},
		{
			name:     "File with password content",
			filePath: "config.yaml",
			content:  "password: secret123",
			expected: true,
		},
		{
			name:     "File with API key content",
			filePath: "config.yaml",
			content:  "api_key: abcd1234",
			expected: true,
		},
		{
			name:     "File with private key content",
			filePath: "config.yaml",
			content:  "private_key: -----BEGIN PRIVATE KEY-----",
			expected: true,
		},
		{
			name:     "Normal configuration file",
			filePath: "app-config.yaml",
			content:  "app: name: test\nport: 8080",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.shouldBeEncrypted(tt.filePath, []byte(tt.content))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSOPSManager_GetSOPSMetadata(t *testing.T) {
	manager := NewSOPSManager()
	
	// Sample SOPS encrypted content
	sopsContent := `test: value
sops:
    kms:
        - arn: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
          created_at: "2024-01-01T00:00:00Z"
          enc: ENC[AES256_GCM,data:abc123,iv:def456,tag:ghi789,type:str]
    gcp_kms: []
    azure_kv: []
    hc_vault: []
    age: []
    lastmodified: "2024-01-01T00:00:00Z"
    mac: ENC[AES256_GCM,data:hmac123,iv:hmac456,tag:hmac789,type:str]
    pgp: []
    encrypted_regex: ^(password|api_key|secret)$
    version: 3.7.3`
	
	tests := []struct {
		name      string
		content   string
		expectErr bool
		checkMeta func(*testing.T, *SOPSMetadata)
	}{
		{
			name:      "Valid SOPS content",
			content:   sopsContent,
			expectErr: false,
			checkMeta: func(t *testing.T, meta *SOPSMetadata) {
				assert.Equal(t, "3.7.3", meta.Version)
				assert.Len(t, meta.KMSKeys, 1)
				assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", meta.KMSKeys[0])
				assert.Equal(t, "^(password|api_key|secret)$", meta.EncryptedRegex)
			},
		},
		{
			name:      "Non-SOPS content",
			content:   "normal: yaml\nconfig: value",
			expectErr: true,
		},
		{
			name:      "Invalid YAML",
			content:   "invalid: yaml: content: [",
			expectErr: true,
		},
		{
			name:      "YAML without SOPS section",
			content:   "normal: yaml\nvalid: true",
			expectErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata, err := manager.GetSOPSMetadata([]byte(tt.content))
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, metadata)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, metadata)
				if tt.checkMeta != nil {
					tt.checkMeta(t, metadata)
				}
			}
		})
	}
}

func TestSOPSManager_createTempFile(t *testing.T) {
	manager := NewSOPSManager()
	
	content := []byte("test: configuration\nvalue: 123")
	
	tests := []struct {
		name     string
		filePath string
		expected string
	}{
		{
			name:     "YAML file",
			filePath: "config.yaml",
			expected: ".yaml",
		},
		{
			name:     "YML file",
			filePath: "config.yml",
			expected: ".yml",
		},
		{
			name:     "JSON file",
			filePath: "config.json",
			expected: ".json",
		},
		{
			name:     "No extension",
			filePath: "config",
			expected: ".yaml",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := manager.createTempFile(content, tt.filePath)
			assert.NoError(t, err)
			assert.True(t, strings.HasSuffix(tmpFile, tt.expected))
			
			// Verify content was written correctly
			fileContent, err := os.ReadFile(tmpFile)
			assert.NoError(t, err)
			assert.Equal(t, content, fileContent)
			
			// Clean up
			os.Remove(tmpFile)
		})
	}
}

func TestSOPSManager_selectKMSKey(t *testing.T) {
	manager := NewSOPSManager()
	
	config := &SOPSConfig{
		KMSProviders: map[string]KMSProvider{
			"aws-prod": {
				Type:  "aws",
				KeyID: "arn:aws:kms:us-east-1:123456789012:key/prod-key",
			},
			"aws-dev": {
				Type:  "aws",
				KeyID: "arn:aws:kms:us-east-1:123456789012:key/dev-key",
			},
		},
		EncryptionRules: []EncryptionRule{
			{
				PathRegex: `production/.*\.yaml$`,
				KMSKey:    "arn:aws:kms:us-east-1:123456789012:key/prod-key",
			},
			{
				PathRegex: `development/.*\.yaml$`,
				KMSKey:    "arn:aws:kms:us-east-1:123456789012:key/dev-key",
			},
		},
	}
	
	tests := []struct {
		name        string
		filePath    string
		expectedKey string
		expectErr   bool
	}{
		{
			name:        "Production file matches rule",
			filePath:    "production/app-config.yaml",
			expectedKey: "arn:aws:kms:us-east-1:123456789012:key/prod-key",
			expectErr:   false,
		},
		{
			name:        "Development file matches rule",
			filePath:    "development/app-config.yaml",
			expectedKey: "arn:aws:kms:us-east-1:123456789012:key/dev-key",
			expectErr:   false,
		},
		{
			name:        "File doesn't match any rule, falls back to first provider",
			filePath:    "staging/app-config.yaml",
			expectedKey: "arn:aws:kms:us-east-1:123456789012:key/prod-key", // First in map (order may vary)
			expectErr:   false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := manager.selectKMSKey(tt.filePath, config)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// For fallback case, just verify we got a key from the providers
				if tt.filePath == "staging/app-config.yaml" {
					found := false
					for _, provider := range config.KMSProviders {
						if key == provider.KeyID {
							found = true
							break
						}
					}
					assert.True(t, found, "Key should be from one of the providers")
				} else {
					assert.Equal(t, tt.expectedKey, key)
				}
			}
		})
	}
}

// Test empty config (no providers)
func TestSOPSManager_selectKMSKey_NoProviders(t *testing.T) {
	manager := NewSOPSManager()
	
	config := &SOPSConfig{
		KMSProviders:    map[string]KMSProvider{},
		EncryptionRules: []EncryptionRule{},
	}
	
	_, err := manager.selectKMSKey("test.yaml", config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no KMS key found")
}