package script

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// ScriptConfig represents the configuration for a script resource
type ScriptConfig struct {
	Content       string                 `yaml:"content"`               // Script content
	Shell         ShellType              `yaml:"shell"`                 // Required shell type
	Timeout       time.Duration          `yaml:"timeout"`               // Execution timeout
	Environment   map[string]string      `yaml:"environment,omitempty"` // Environment variables
	WorkingDir    string                 `yaml:"working_dir,omitempty"` // Working directory
	Signature     *ScriptSignature       `yaml:"signature,omitempty"`   // Script signature
	SigningPolicy SigningPolicy          `yaml:"signing_policy"`        // Signing policy
	Description   string                 `yaml:"description,omitempty"` // Script description
	Metadata      map[string]interface{} `yaml:"metadata,omitempty"`    // Additional metadata
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *ScriptConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"content":        c.Content,
		"shell":          string(c.Shell),
		"timeout":        c.Timeout.String(),
		"signing_policy": string(c.SigningPolicy),
	}

	if len(c.Environment) > 0 {
		result["environment"] = c.Environment
	}
	if c.WorkingDir != "" {
		result["working_dir"] = c.WorkingDir
	}
	if c.Signature != nil {
		result["signature"] = c.Signature
	}
	if c.Description != "" {
		result["description"] = c.Description
	}
	if len(c.Metadata) > 0 {
		result["metadata"] = c.Metadata
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *ScriptConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *ScriptConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *ScriptConfig) Validate() error {
	if c.Content == "" {
		return fmt.Errorf("%w: script content cannot be empty", modules.ErrInvalidInput)
	}

	if c.Shell == "" {
		return fmt.Errorf("%w: shell type is required", modules.ErrInvalidInput)
	}

	// Validate shell type is supported on current platform
	if !c.isShellSupported() {
		return fmt.Errorf("%w: shell %s is not supported on %s", modules.ErrInvalidInput, c.Shell, runtime.GOOS)
	}

	// Validate timeout
	if c.Timeout < 0 {
		return fmt.Errorf("%w: timeout cannot be negative", modules.ErrInvalidInput)
	}

	// Set default timeout if not specified
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Minute // Default 5 minute timeout
	}

	// Validate signing policy
	switch c.SigningPolicy {
	case SigningPolicyNone, SigningPolicyOptional, SigningPolicyRequired:
		// Valid policies
	case "":
		c.SigningPolicy = SigningPolicyNone // Default to no signing required
	default:
		return fmt.Errorf("%w: invalid signing policy: %s", modules.ErrInvalidInput, c.SigningPolicy)
	}

	// If signing is required, signature must be present
	if c.SigningPolicy == SigningPolicyRequired && c.Signature == nil {
		return fmt.Errorf("%w: signature is required when signing policy is 'required'", modules.ErrInvalidInput)
	}

	// Validate signature if present
	if c.Signature != nil {
		if err := c.validateSignature(); err != nil {
			return err
		}
	}

	return nil
}

// GetManagedFields returns the list of fields this configuration manages
func (c *ScriptConfig) GetManagedFields() []string {
	fields := []string{"content", "shell", "timeout", "signing_policy"}

	if len(c.Environment) > 0 {
		fields = append(fields, "environment")
	}
	if c.WorkingDir != "" {
		fields = append(fields, "working_dir")
	}
	if c.Signature != nil {
		fields = append(fields, "signature")
	}
	if c.Description != "" {
		fields = append(fields, "description")
	}
	if len(c.Metadata) > 0 {
		fields = append(fields, "metadata")
	}

	return fields
}

// isShellSupported checks if the specified shell is supported on the current platform
func (c *ScriptConfig) isShellSupported() bool {
	switch runtime.GOOS {
	case "windows":
		return c.Shell == ShellPowerShell || c.Shell == ShellCmd || c.Shell == ShellPython || c.Shell == ShellPython3
	case "linux", "darwin":
		return c.Shell == ShellBash || c.Shell == ShellZsh || c.Shell == ShellSh || c.Shell == ShellPython || c.Shell == ShellPython3
	default:
		return false
	}
}

// validateSignature validates the script signature structure
func (c *ScriptConfig) validateSignature() error {
	if c.Signature.Algorithm == "" {
		return fmt.Errorf("%w: signature algorithm is required", modules.ErrInvalidInput)
	}
	if c.Signature.Signature == "" {
		return fmt.Errorf("%w: signature value is required", modules.ErrInvalidInput)
	}
	if c.Signature.PublicKey == "" && c.Signature.Thumbprint == "" {
		return fmt.Errorf("%w: either public key or certificate thumbprint is required", modules.ErrInvalidInput)
	}

	// Validate algorithm format
	supportedAlgorithms := []string{"rsa-sha256", "rsa-sha512", "ecdsa-sha256", "ecdsa-sha384"}
	algorithm := strings.ToLower(c.Signature.Algorithm)
	isSupported := false
	for _, supported := range supportedAlgorithms {
		if algorithm == supported {
			isSupported = true
			break
		}
	}
	if !isSupported {
		return fmt.Errorf("%w: unsupported signature algorithm: %s", modules.ErrInvalidInput, c.Signature.Algorithm)
	}

	return nil
}
