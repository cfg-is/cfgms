// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package templates_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/templates"
)

func TestTemplateEngine_BasicVariableSubstitution(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	dnaProvider := templates.NewMockDNAProvider()
	configService := templates.NewMockConfigService()
	resolver := templates.NewVariableResolver(dnaProvider, configService)
	engine := templates.NewTemplateEngine(store, dnaProvider)

	// Set up DNA data
	dnaProvider.SetDNA("device", "test-device", map[string]interface{}{
		"System": map[string]interface{}{
			"Hostname": "test-server-01",
			"OS":       "linux",
		},
		"Network": map[string]interface{}{
			"PrimaryInterface": "eth0",
			"IPv4Address":      "192.168.1.100",
		},
	})

	// Create template with variables
	templateContent := `variables:
  client_name: "acme-corp"
  environment: "production" 
  enable_monitoring: true

# Basic variable substitution
hostname: "$client_name-$environment-server"

# DNA property usage
network:
  interface: "$DNA.Network.PrimaryInterface"
  current_ip: "$DNA.Network.IPv4Address"
  hostname: "$DNA.System.Hostname"

# Conditional based on variable
$if $enable_monitoring
monitoring:
  enabled: true
  agent: "prometheus"
$endif

# Conditional based on DNA
$if "$DNA.System.OS" == "linux"
linux_config:
  selinux: enforcing
$endif`

	// Parse template
	template, err := engine.Parse(context.Background(), []byte(templateContent), templates.ParseOptions{})
	require.NoError(t, err)
	assert.Equal(t, "acme-corp", template.Variables["client_name"])
	assert.Equal(t, "production", template.Variables["environment"])
	assert.Equal(t, true, template.Variables["enable_monitoring"])

	// Resolve variables
	templateContext, err := resolver.Resolve(context.Background(), template, "device", "test-device")
	require.NoError(t, err)
	assert.Equal(t, "acme-corp", templateContext.Variables["client_name"])
	assert.Equal(t, "test-server-01", templateContext.DNA["System"].(map[string]interface{})["Hostname"])

	// Render template
	result, err := engine.Render(context.Background(), template, templateContext, templates.RenderOptions{
		Timeout: 10 * time.Second,
	})
	require.NoError(t, err)

	// Verify rendered content
	rendered := string(result.Content)
	assert.Contains(t, rendered, "hostname: \"acme-corp-production-server\"")
	assert.Contains(t, rendered, "interface: \"eth0\"")
	assert.Contains(t, rendered, "current_ip: \"192.168.1.100\"")
	assert.Contains(t, rendered, "hostname: \"test-server-01\"")
	assert.Contains(t, rendered, "monitoring:")
	assert.Contains(t, rendered, "enabled: true")
	assert.Contains(t, rendered, "linux_config:")
	assert.Contains(t, rendered, "selinux: enforcing")
}

func TestTemplateEngine_VariablePrecedence(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	dnaProvider := templates.NewMockDNAProvider()
	configService := templates.NewMockConfigService()
	resolver := templates.NewVariableResolver(dnaProvider, configService)
	engine := templates.NewTemplateEngine(store, dnaProvider)

	// Set up data sources with conflicting values
	dnaProvider.SetDNA("device", "test-device", map[string]interface{}{
		"hostname": "dna-hostname",
	})

	configService.SetInheritedVariables("device", "test-device", map[string]interface{}{
		"hostname": "inherited-hostname",
	})

	// Create template with local variable (should win)
	templateContent := `variables:
  hostname: "local-hostname"

system:
  name: "$hostname"
  dna_hostname: "$DNA.hostname"`

	// Parse and render
	template, err := engine.Parse(context.Background(), []byte(templateContent), templates.ParseOptions{})
	require.NoError(t, err)

	templateContext, err := resolver.Resolve(context.Background(), template, "device", "test-device")
	require.NoError(t, err)

	result, err := engine.Render(context.Background(), template, templateContext, templates.RenderOptions{})
	require.NoError(t, err)

	// Verify precedence: local > inherited > DNA
	rendered := string(result.Content)
	assert.Contains(t, rendered, "name: \"local-hostname\"")
	assert.Contains(t, rendered, "dna_hostname: \"dna-hostname\"")
}

func TestTemplateEngine_ConditionalLogic(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	dnaProvider := templates.NewMockDNAProvider()
	configService := templates.NewMockConfigService()
	resolver := templates.NewVariableResolver(dnaProvider, configService)
	engine := templates.NewTemplateEngine(store, dnaProvider)

	// Set up DNA
	dnaProvider.SetDNA("device", "windows-device", map[string]interface{}{
		"System": map[string]interface{}{
			"OS": "windows",
		},
	})

	// Create template with conditionals
	templateContent := `variables:
  enable_firewall: true
  environment: "production"

# Boolean conditional
$if $enable_firewall
firewall:
  enabled: true
$endif

# String comparison conditional  
$if "$DNA.System.OS" == "windows"
windows_config:
  defender: enabled
$elif "$DNA.System.OS" == "linux"
linux_config:
  selinux: enforcing
$endif

# Environment-based conditional
$if "$environment" == "production"
security:
  strict_mode: true
$else
security:
  strict_mode: false
$endif`

	// Parse and render
	template, err := engine.Parse(context.Background(), []byte(templateContent), templates.ParseOptions{})
	require.NoError(t, err)

	templateContext, err := resolver.Resolve(context.Background(), template, "device", "windows-device")
	require.NoError(t, err)

	result, err := engine.Render(context.Background(), template, templateContext, templates.RenderOptions{})
	require.NoError(t, err)

	// Verify conditionals worked correctly
	rendered := string(result.Content)
	assert.Contains(t, rendered, "firewall:")
	assert.Contains(t, rendered, "enabled: true")
	assert.Contains(t, rendered, "windows_config:")
	assert.Contains(t, rendered, "defender: enabled")
	assert.NotContains(t, rendered, "linux_config:")
	assert.Contains(t, rendered, "strict_mode: true")
}

func TestTemplateEngine_Validation(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	dnaProvider := templates.NewMockDNAProvider()
	engine := templates.NewTemplateEngine(store, dnaProvider)

	tests := []struct {
		name          string
		content       string
		expectValid   bool
		expectErrors  int
		errorContains string
	}{
		{
			name: "Valid template",
			content: `variables:
  name: "test"
  
hostname: "$name"`,
			expectValid:  true,
			expectErrors: 0,
		},
		{
			name: "Unclosed if block",
			content: `$if $some_var
config: value`,
			expectValid:   false,
			expectErrors:  1,
			errorContains: "Unclosed if block",
		},
		{
			name: "Invalid elif without if",
			content: `$elif $some_var
config: value`,
			expectValid:   false,
			expectErrors:  1,
			errorContains: "$elif without matching $if",
		},
		{
			name: "Invalid endif without if",
			content: `config: value
$endif`,
			expectValid:   false,
			expectErrors:  1,
			errorContains: "$endif without matching $if",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template, err := engine.Parse(context.Background(), []byte(tt.content), templates.ParseOptions{})

			if !tt.expectValid && tt.errorContains != "" {
				// For syntax errors, Parse itself should fail
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				return
			}

			require.NoError(t, err)

			result, err := engine.Validate(context.Background(), template)
			require.NoError(t, err)

			assert.Equal(t, tt.expectValid, result.Valid)
			assert.Equal(t, tt.expectErrors, len(result.Errors))

			if tt.errorContains != "" && len(result.Errors) > 0 {
				assert.Contains(t, result.Errors[0].Message, tt.errorContains)
			}
		})
	}
}

func TestTemplateEngine_UndefinedVariables(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	dnaProvider := templates.NewMockDNAProvider()
	configService := templates.NewMockConfigService()
	resolver := templates.NewVariableResolver(dnaProvider, configService)
	engine := templates.NewTemplateEngine(store, dnaProvider)

	// Template with undefined variable
	templateContent := `variables:
  defined_var: "defined"

config:
  defined: "$defined_var"
  undefined: "$undefined_var"
  dna_undefined: "$DNA.NonExistent.Property"`

	template, err := engine.Parse(context.Background(), []byte(templateContent), templates.ParseOptions{})
	require.NoError(t, err)

	templateContext, err := resolver.Resolve(context.Background(), template, "device", "test-device")
	require.NoError(t, err)

	result, err := engine.Render(context.Background(), template, templateContext, templates.RenderOptions{})
	require.NoError(t, err)

	// Should have warnings about undefined variables
	assert.Greater(t, len(result.Warnings), 0)

	// Should contain the undefined variable references as-is
	rendered := string(result.Content)
	assert.Contains(t, rendered, "defined: \"defined\"")
	assert.Contains(t, rendered, "undefined: \"$undefined_var\"")
	assert.Contains(t, rendered, "dna_undefined: \"$DNA.NonExistent.Property\"")
}

func TestTemplateEngine_ComplexExample(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	dnaProvider := templates.NewMockDNAProvider()
	configService := templates.NewMockConfigService()
	resolver := templates.NewVariableResolver(dnaProvider, configService)
	engine := templates.NewTemplateEngine(store, dnaProvider)

	// Set up rich DNA data
	dnaProvider.SetDNA("device", "web-server-01", map[string]interface{}{
		"System": map[string]interface{}{
			"Hostname":     "web-server-01",
			"OS":           "linux",
			"Architecture": "x86_64",
		},
		"Memory": map[string]interface{}{
			"TotalMB":     8192,
			"AvailableMB": 6000,
		},
		"CPU": map[string]interface{}{
			"Cores": 4,
			"Model": "Intel Xeon",
		},
		"Network": map[string]interface{}{
			"PrimaryInterface": "eth0",
			"IPv4Address":      "10.1.1.50",
		},
	})

	// Set up inherited variables (from client template)
	configService.SetInheritedVariables("device", "web-server-01", map[string]interface{}{
		"client_name":      "acme-corp",
		"client_office_ip": "203.0.113.0/24",
		"requires_pci":     true,
	})

	// Create complex template
	templateContent := `variables:
  environment: "production"
  ssh_port: 2222
  auto_update: false
  enable_monitoring: true

# System identification
hostname: "$client_name-$environment-$DNA.System.Hostname"

# SSH configuration  
ssh:
  port: $ssh_port
  bind_interface: "$DNA.Network.PrimaryInterface"
  allow_from: "$client_office_ip"

# Conditional security based on environment
$if "$environment" == "production"
security:
  strict_mode: true
  audit_enabled: true
  
  # PCI compliance if required
  $if $requires_pci
  pci_compliance:
    enabled: true
    audit_retention_days: 365
  $endif
$else
security:
  strict_mode: false
  audit_enabled: false
$endif

# OS-specific configuration
$if "$DNA.System.OS" == "linux"
linux:
  selinux: enforcing
  kernel_hardening: true
$elif "$DNA.System.OS" == "windows"
windows:
  defender: enabled
  firewall: enabled
$endif

# Resource allocation based on DNA
resources:
  # Allocate 80% of available memory  
  memory_limit_mb: $DNA.Memory.AvailableMB
  # Use all but one CPU core
  cpu_cores: $DNA.CPU.Cores
  
# Monitoring configuration
$if $enable_monitoring
monitoring:
  enabled: true
  agent: "prometheus"
  hostname: "$DNA.System.Hostname"
  interface: "$DNA.Network.PrimaryInterface"
$endif

# Updates
updates:
  auto_apply: $auto_update
  schedule: "Sun 02:00"`

	// Parse, resolve, and render
	template, err := engine.Parse(context.Background(), []byte(templateContent), templates.ParseOptions{})
	require.NoError(t, err)

	templateContext, err := resolver.Resolve(context.Background(), template, "device", "web-server-01")
	require.NoError(t, err)

	result, err := engine.Render(context.Background(), template, templateContext, templates.RenderOptions{})
	require.NoError(t, err)

	// Verify complex rendering
	rendered := string(result.Content)

	// Check variable substitution
	assert.Contains(t, rendered, "hostname: \"acme-corp-production-web-server-01\"")
	assert.Contains(t, rendered, "port: 2222")
	assert.Contains(t, rendered, "bind_interface: \"eth0\"")
	assert.Contains(t, rendered, "allow_from: \"203.0.113.0/24\"")

	// Check conditionals
	assert.Contains(t, rendered, "strict_mode: true")
	assert.Contains(t, rendered, "pci_compliance:")
	assert.Contains(t, rendered, "enabled: true")
	assert.Contains(t, rendered, "linux:")
	assert.Contains(t, rendered, "selinux: enforcing")
	assert.NotContains(t, rendered, "windows:")

	// Check DNA-based values
	assert.Contains(t, rendered, "memory_limit_mb: 6000")
	assert.Contains(t, rendered, "cpu_cores: 4")
	assert.Contains(t, rendered, "agent: \"prometheus\"")
	assert.Contains(t, rendered, "auto_apply: false")

	// Print warnings for debugging
	if len(result.Warnings) > 0 {
		t.Logf("Warnings: %+v", result.Warnings)
	}

	// Should have no warnings for this valid template
	assert.Equal(t, 0, len(result.Warnings))
}
