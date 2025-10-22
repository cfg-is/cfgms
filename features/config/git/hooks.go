package git

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultHookManager implements the HookManager interface
type DefaultHookManager struct {
	validators map[string]ConfigValidator
}

// ConfigValidator validates configuration files
type ConfigValidator interface {
	Validate(ctx context.Context, config *Configuration) error
}

// NewHookManager creates a new hook manager
func NewHookManager() HookManager {
	return &DefaultHookManager{
		validators: make(map[string]ConfigValidator),
	}
}

// InstallHooks installs Git hooks in a repository
func (m *DefaultHookManager) InstallHooks(ctx context.Context, repoPath string) error {
	hooksDir := filepath.Join(repoPath, ".git", "hooks")

	// Create hooks directory if it doesn't exist
	if err := os.MkdirAll(hooksDir, 0750); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	// Install pre-commit hook
	preCommitHook := m.generatePreCommitHook()
	preCommitPath := filepath.Join(hooksDir, "pre-commit")
	// #nosec G306 - Git hooks must be executable (0700) to function properly
	if err := os.WriteFile(preCommitPath, []byte(preCommitHook), 0700); err != nil {
		return fmt.Errorf("failed to install pre-commit hook: %w", err)
	}

	// Install pre-push hook
	prePushHook := m.generatePrePushHook()
	prePushPath := filepath.Join(hooksDir, "pre-push")
	// #nosec G306 - Git hooks must be executable (0700) to function properly
	if err := os.WriteFile(prePushPath, []byte(prePushHook), 0700); err != nil {
		return fmt.Errorf("failed to install pre-push hook: %w", err)
	}

	return nil
}

// RunPreCommitHooks runs pre-commit hooks on the specified files
func (m *DefaultHookManager) RunPreCommitHooks(ctx context.Context, repoPath string, files []string) error {
	// Validate each configuration file
	for _, file := range files {
		if m.isConfigurationFile(file) {
			// Read the file
			fullPath := filepath.Join(repoPath, file)
			// #nosec G304 - Git hook validation requires reading committed files within repository
			content, err := os.ReadFile(fullPath)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", file, err)
			}

			config := &Configuration{
				Path:    file,
				Content: content,
				Format:  m.getConfigFormat(file),
			}

			// Validate the configuration
			if err := m.ValidateConfiguration(ctx, config); err != nil {
				return fmt.Errorf("validation failed for %s: %w", file, err)
			}
		}
	}

	// Run custom pre-commit script if it exists
	customHookPath := filepath.Join(repoPath, ".cfgms", "hooks", "pre-commit")
	if _, err := os.Stat(customHookPath); err == nil {
		// #nosec G204 - Git hook execution required for repository management
		cmd := exec.CommandContext(ctx, customHookPath, files...)
		cmd.Dir = repoPath
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("custom pre-commit hook failed: %s", string(output))
		}
	}

	return nil
}

// RunPreReceiveHooks runs pre-receive hooks (server-side)
func (m *DefaultHookManager) RunPreReceiveHooks(ctx context.Context, repoPath string, commits []string) error {
	// This would be implemented on the Git server side
	// For now, we'll validate all changed files in the commits

	for _, commit := range commits {
		// Get files changed in this commit
		// #nosec G204 - Git repository management requires git command execution
		cmd := exec.CommandContext(ctx, "git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit)
		cmd.Dir = repoPath
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get changed files: %w", err)
		}

		files := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, file := range files {
			if file == "" {
				continue
			}

			if m.isConfigurationFile(file) {
				// Get file content at this commit
				// #nosec G204 - Git repository management requires git command execution
				cmd := exec.CommandContext(ctx, "git", "show", fmt.Sprintf("%s:%s", commit, file))
				cmd.Dir = repoPath
				content, err := cmd.Output()
				if err != nil {
					// File might be deleted, skip
					continue
				}

				config := &Configuration{
					Path:    file,
					Content: content,
					Format:  m.getConfigFormat(file),
				}

				// Validate the configuration
				if err := m.ValidateConfiguration(ctx, config); err != nil {
					return fmt.Errorf("validation failed for %s in commit %s: %w", file, commit, err)
				}
			}
		}
	}

	return nil
}

// ValidateConfiguration validates a configuration file
func (m *DefaultHookManager) ValidateConfiguration(ctx context.Context, config *Configuration) error {
	// Check if we have a specific validator for this format
	if validator, exists := m.validators[config.Format]; exists {
		return validator.Validate(ctx, config)
	}

	// Basic validation based on format
	switch config.Format {
	case "yaml":
		return m.validateYAML(config)
	case "json":
		return m.validateJSON(config)
	case "toml":
		return m.validateTOML(config)
	default:
		// Unknown format - skip validation
		return nil
	}
}

// RegisterValidator registers a custom validator for a format
func (m *DefaultHookManager) RegisterValidator(format string, validator ConfigValidator) {
	m.validators[format] = validator
}

// Helper methods

func (m *DefaultHookManager) generatePreCommitHook() string {
	return `#!/bin/bash
# CFGMS Pre-commit Hook
# Validates configuration files before commit

# Get list of staged files
FILES=$(git diff --cached --name-only --diff-filter=ACM)

# Validate configuration files
for FILE in $FILES; do
    case "$FILE" in
        *.yaml|*.yml|*.json|*.toml)
            echo "Validating $FILE..."
            # Basic syntax check
            case "$FILE" in
                *.yaml|*.yml)
                    python -c "import yaml; yaml.safe_load(open('$FILE'))" 2>/dev/null || {
                        echo "ERROR: Invalid YAML syntax in $FILE"
                        exit 1
                    }
                    ;;
                *.json)
                    python -c "import json; json.load(open('$FILE'))" 2>/dev/null || {
                        echo "ERROR: Invalid JSON syntax in $FILE"
                        exit 1
                    }
                    ;;
            esac
            ;;
    esac
done

# Run custom pre-commit hook if exists
if [ -f .cfgms/hooks/pre-commit ]; then
    .cfgms/hooks/pre-commit $FILES || exit 1
fi

exit 0
`
}

func (m *DefaultHookManager) generatePrePushHook() string {
	return `#!/bin/bash
# CFGMS Pre-push Hook
# Validates changes before pushing to remote

# Get remote and branch info
REMOTE="$1"
URL="$2"

# Check if pushing to protected branches
while read LOCAL_REF LOCAL_SHA REMOTE_REF REMOTE_SHA; do
    case "$REMOTE_REF" in
        refs/heads/main|refs/heads/master|refs/heads/production)
            echo "Validating push to protected branch ${REMOTE_REF#refs/heads/}..."
            
            # Ensure all tests pass
            if [ -f Makefile ] && grep -q "^test:" Makefile; then
                make test || {
                    echo "ERROR: Tests must pass before pushing to protected branch"
                    exit 1
                }
            fi
            
            # Check for TODO or FIXME comments
            if git diff "$REMOTE_SHA" "$LOCAL_SHA" | grep -E "(TODO|FIXME)" > /dev/null; then
                echo "WARNING: Found TODO/FIXME comments in changes"
                read -p "Continue with push? (y/n) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    exit 1
                fi
            fi
            ;;
    esac
done

# Run custom pre-push hook if exists
if [ -f .cfgms/hooks/pre-push ]; then
    .cfgms/hooks/pre-push "$@" || exit 1
fi

exit 0
`
}

func (m *DefaultHookManager) isConfigurationFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml", ".json", ".toml":
		return true
	default:
		return false
	}
}

func (m *DefaultHookManager) getConfigFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".toml":
		return "toml"
	default:
		return "unknown"
	}
}

func (m *DefaultHookManager) validateYAML(config *Configuration) error {
	// Basic YAML validation using the yaml package
	var data interface{}
	if err := yaml.Unmarshal(config.Content, &data); err != nil {
		return fmt.Errorf("invalid YAML syntax: %w", err)
	}

	// Additional CFGMS-specific validation
	if err := m.validateCFGMSStructure(config.Path, data); err != nil {
		return err
	}

	return nil
}

func (m *DefaultHookManager) validateJSON(config *Configuration) error {
	// JSON validation is handled by json.Unmarshal
	var data interface{}
	if err := json.Unmarshal(config.Content, &data); err != nil {
		return fmt.Errorf("invalid JSON syntax: %w", err)
	}

	// Additional CFGMS-specific validation
	if err := m.validateCFGMSStructure(config.Path, data); err != nil {
		return err
	}

	return nil
}

func (m *DefaultHookManager) validateTOML(config *Configuration) error {
	// For TOML, we'd use a TOML parser
	// This is a placeholder - in production you'd use github.com/BurntSushi/toml
	return nil
}

func (m *DefaultHookManager) validateCFGMSStructure(path string, data interface{}) error {
	// Validate based on file path patterns
	switch {
	case strings.HasPrefix(path, "groups/") && strings.HasSuffix(path, "/config.yaml"):
		return m.validateGroupConfig(data)

	case strings.HasPrefix(path, "templates/"):
		return m.validateTemplate(data)

	case strings.HasPrefix(path, "policies/"):
		return m.validatePolicy(data)

	case path == "config.yaml":
		return m.validateRootConfig(data)

	default:
		// No specific validation rules
		return nil
	}
}

func (m *DefaultHookManager) validateGroupConfig(data interface{}) error {
	// Validate group configuration structure
	config, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("group config must be a map")
	}

	// Check required fields
	if _, exists := config["version"]; !exists {
		return fmt.Errorf("group config missing required field: version")
	}

	return nil
}

func (m *DefaultHookManager) validateTemplate(data interface{}) error {
	// Validate template structure
	template, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("template must be a map")
	}

	// Check for template metadata
	if _, exists := template["metadata"]; !exists {
		return fmt.Errorf("template missing metadata section")
	}

	return nil
}

func (m *DefaultHookManager) validatePolicy(data interface{}) error {
	// Validate policy structure
	policy, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("policy must be a map")
	}

	// Check required policy fields
	required := []string{"name", "description", "rules"}
	for _, field := range required {
		if _, exists := policy[field]; !exists {
			return fmt.Errorf("policy missing required field: %s", field)
		}
	}

	return nil
}

func (m *DefaultHookManager) validateRootConfig(data interface{}) error {
	// Validate root configuration structure
	config, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("root config must be a map")
	}

	// Check version compatibility
	if version, exists := config["version"]; exists {
		if v, ok := version.(string); ok {
			if !m.isVersionCompatible(v) {
				return fmt.Errorf("incompatible config version: %s", v)
			}
		}
	}

	return nil
}

func (m *DefaultHookManager) isVersionCompatible(version string) bool {
	// Simple version check - in production this would be more sophisticated
	supportedVersions := []string{"1.0", "1.1", "1.2"}
	for _, v := range supportedVersions {
		if strings.HasPrefix(version, v) {
			return true
		}
	}
	return false
}
