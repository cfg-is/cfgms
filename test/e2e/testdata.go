package e2e

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	common "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/steward/config"
)

// TestDataGenerator provides lightweight test data generation optimized for CI environments
type TestDataGenerator struct {
	config *E2EConfig
}

// NewTestDataGenerator creates a new test data generator
func NewTestDataGenerator(config *E2EConfig) *TestDataGenerator {
	return &TestDataGenerator{
		config: config,
	}
}

// cryptoRandInt generates a cryptographically secure random integer in range [0, max)
func (g *TestDataGenerator) cryptoRandInt(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		// Fallback to timestamp-based value for test environments
		return time.Now().UnixNano() % max
	}
	return n.Int64()
}

// GenerateTestDNA creates realistic DNA data for testing
func (g *TestDataGenerator) GenerateTestDNA(stewardID string) *common.DNA {
	// Base attributes that work across all platforms
	attributes := map[string]string{
		"hostname":    fmt.Sprintf("test-%s", stewardID),
		"steward_id":  stewardID,
		"version":     "test-1.0.0",
		"environment": "testing",
		"test_mode":   "true",
	}

	// Add platform-specific attributes based on test data size
	switch g.config.TestDataSize {
	case "small":
		// Minimal set for CI speed
		attributes["cpu_cores"] = "2"
		attributes["memory_mb"] = "2048"
		attributes["disk_gb"] = "20"
	case "medium":
		// More comprehensive for local testing
		attributes["cpu_cores"] = fmt.Sprintf("%d", g.cryptoRandInt(8)+2)
		attributes["memory_mb"] = fmt.Sprintf("%d", (g.cryptoRandInt(8)+4)*1024)
		attributes["disk_gb"] = fmt.Sprintf("%d", g.cryptoRandInt(100)+50)
		attributes["network_interfaces"] = fmt.Sprintf("%d", g.cryptoRandInt(3)+1)
		attributes["os_family"] = g.randomChoice([]string{"linux", "windows", "darwin"})
		attributes["architecture"] = g.randomChoice([]string{"amd64", "arm64"})
	case "large":
		// Full dataset for performance testing
		attributes["cpu_cores"] = fmt.Sprintf("%d", g.cryptoRandInt(32)+4)
		attributes["memory_mb"] = fmt.Sprintf("%d", (g.cryptoRandInt(32)+8)*1024)
		attributes["disk_gb"] = fmt.Sprintf("%d", g.cryptoRandInt(1000)+100)
		attributes["network_interfaces"] = fmt.Sprintf("%d", g.cryptoRandInt(10)+1)
		attributes["os_family"] = g.randomChoice([]string{"linux", "windows", "darwin"})
		attributes["architecture"] = g.randomChoice([]string{"amd64", "arm64", "386"})
		attributes["kernel_version"] = g.generateKernelVersion()
		attributes["uptime_seconds"] = fmt.Sprintf("%d", g.cryptoRandInt(86400*30))
		attributes["load_average"] = fmt.Sprintf("%.2f", float64(g.cryptoRandInt(400))/100.0)

		// Add security attributes
		attributes["firewall_enabled"] = g.randomChoice([]string{"true", "false"})
		attributes["antivirus_status"] = g.randomChoice([]string{"active", "inactive", "unknown"})
		attributes["encryption_status"] = g.randomChoice([]string{"enabled", "disabled", "partial"})

		// Add network attributes
		for i := 0; i < int(g.cryptoRandInt(3))+1; i++ {
			attributes[fmt.Sprintf("ip_address_%d", i)] = g.generateIPAddress()
			attributes[fmt.Sprintf("mac_address_%d", i)] = g.generateMACAddress()
		}
	}

	return &common.DNA{
		Id:          stewardID,
		Attributes:  attributes,
		LastUpdated: timestamppb.Now(),
	}
}

// GenerateStewardConfig creates realistic steward configuration for testing
func (g *TestDataGenerator) GenerateStewardConfig(stewardID string) *config.StewardConfig {
	baseConfig := &config.StewardConfig{
		Steward: config.StewardSettings{
			ID:   stewardID,
			Mode: config.ModeController,
			Logging: config.LoggingConfig{
				Level:  "info",
				Format: "json", // JSON for better CI parsing
			},
			ErrorHandling: config.ErrorHandlingConfig{
				ModuleLoadFailure:  config.ActionWarn,
				ResourceFailure:    config.ActionWarn,
				ConfigurationError: config.ActionFail,
			},
		},
		Resources: []config.ResourceConfig{},
	}

	// Add resources based on test data size
	switch g.config.TestDataSize {
	case "small":
		// Minimal resources for fast CI testing
		baseConfig.Resources = append(baseConfig.Resources,
			g.generateDirectoryResource("test-dir", "/tmp/cfgms-test"),
			g.generateFileResource("test-file", "/tmp/cfgms-test/test.txt", "CI Test Content"),
		)
	case "medium":
		// More resources for comprehensive testing
		for i := 0; i < int(g.cryptoRandInt(3))+2; i++ {
			baseConfig.Resources = append(baseConfig.Resources,
				g.generateDirectoryResource(
					fmt.Sprintf("test-dir-%d", i),
					fmt.Sprintf("/tmp/cfgms-test/dir-%d", i),
				),
			)
		}
		for i := 0; i < int(g.cryptoRandInt(5))+2; i++ {
			baseConfig.Resources = append(baseConfig.Resources,
				g.generateFileResource(
					fmt.Sprintf("test-file-%d", i),
					fmt.Sprintf("/tmp/cfgms-test/file-%d.txt", i),
					fmt.Sprintf("Test content %d", i),
				),
			)
		}
		// Add script resource
		baseConfig.Resources = append(baseConfig.Resources,
			g.generateScriptResource("test-script", "echo 'Test script execution'"),
		)
	case "large":
		// Full resource set for performance testing
		// Generate multiple directories
		for i := 0; i < 10; i++ {
			baseConfig.Resources = append(baseConfig.Resources,
				g.generateDirectoryResource(
					fmt.Sprintf("perf-dir-%d", i),
					fmt.Sprintf("/tmp/cfgms-perf/dir-%d", i),
				),
			)
		}
		// Generate multiple files
		for i := 0; i < 20; i++ {
			baseConfig.Resources = append(baseConfig.Resources,
				g.generateFileResource(
					fmt.Sprintf("perf-file-%d", i),
					fmt.Sprintf("/tmp/cfgms-perf/file-%d.txt", i),
					g.generateLargeContent(1024), // 1KB content
				),
			)
		}
		// Add multiple scripts
		for i := 0; i < 5; i++ {
			baseConfig.Resources = append(baseConfig.Resources,
				g.generateScriptResource(
					fmt.Sprintf("perf-script-%d", i),
					fmt.Sprintf("echo 'Performance test script %d'", i),
				),
			)
		}
	}

	return baseConfig
}

// GenerateMultipleStewardConfigs creates multiple steward configurations for scalability testing
func (g *TestDataGenerator) GenerateMultipleStewardConfigs(count int) map[string]*config.StewardConfig {
	configs := make(map[string]*config.StewardConfig)

	// Limit count for CI environments
	if g.config.OptimizeForCI && count > 3 {
		count = 3
	}

	for i := 0; i < count; i++ {
		stewardID := fmt.Sprintf("test-steward-%d", i)
		configs[stewardID] = g.GenerateStewardConfig(stewardID)
	}

	return configs
}

// GenerateTestTenantData creates tenant hierarchy data for RBAC testing
func (g *TestDataGenerator) GenerateTestTenantData() map[string]interface{} {
	return map[string]interface{}{
		"msp": map[string]interface{}{
			"id":   "test-msp",
			"name": "Test MSP",
			"type": "msp",
		},
		"clients": []map[string]interface{}{
			{
				"id":        "test-client-1",
				"name":      "Test Client 1",
				"type":      "client",
				"parent_id": "test-msp",
			},
			{
				"id":        "test-client-2",
				"name":      "Test Client 2",
				"type":      "client",
				"parent_id": "test-msp",
			},
		},
		"groups": []map[string]interface{}{
			{
				"id":        "test-group-1",
				"name":      "Test Group 1",
				"type":      "group",
				"parent_id": "test-client-1",
			},
		},
	}
}

// Helper methods for generating realistic test data

func (g *TestDataGenerator) generateDirectoryResource(name, path string) config.ResourceConfig {
	return config.ResourceConfig{
		Name:   name,
		Module: "directory",
		Config: map[string]interface{}{
			"path":        path,
			"permissions": "755",
			"owner":       "root",
			"group":       "root",
		},
	}
}

func (g *TestDataGenerator) generateFileResource(name, path, content string) config.ResourceConfig {
	return config.ResourceConfig{
		Name:   name,
		Module: "file",
		Config: map[string]interface{}{
			"path":        path,
			"content":     content,
			"permissions": "644",
			"owner":       "root",
			"group":       "root",
		},
	}
}

func (g *TestDataGenerator) generateScriptResource(name, script string) config.ResourceConfig {
	return config.ResourceConfig{
		Name:   name,
		Module: "script",
		Config: map[string]interface{}{
			"script":      script,
			"interpreter": "bash",
			"timeout":     30,
			"run_as":      "root",
		},
	}
}

func (g *TestDataGenerator) generateKernelVersion() string {
	major := g.cryptoRandInt(3) + 5 // 5.x, 6.x, 7.x
	minor := g.cryptoRandInt(20)
	patch := g.cryptoRandInt(10)
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

func (g *TestDataGenerator) generateIPAddress() string {
	return fmt.Sprintf("192.168.%d.%d",
		g.cryptoRandInt(255)+1,
		g.cryptoRandInt(254)+1)
}

func (g *TestDataGenerator) generateMACAddress() string {
	mac := make([]byte, 6)
	if _, err := rand.Read(mac); err != nil {
		// Fallback for the extremely unlikely case that crypto/rand fails
		// Use predictable values for testing
		mac = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	}
	// Set the locally administered bit
	mac[0] |= 2
	mac[0] &= 0xfe
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func (g *TestDataGenerator) generateLargeContent(sizeBytes int) string {
	content := make([]byte, sizeBytes)
	for i := range content {
		content[i] = byte(g.cryptoRandInt(94) + 32) // Printable ASCII
	}
	return string(content)
}

func (g *TestDataGenerator) randomChoice(choices []string) string {
	if len(choices) == 0 {
		return ""
	}
	return choices[g.cryptoRandInt(int64(len(choices)))]
}

// Performance test data generators

// GeneratePerformanceTestData creates data specifically for performance regression tests
func (g *TestDataGenerator) GeneratePerformanceTestData() *PerformanceTestData {
	return &PerformanceTestData{
		ConcurrentStewards:     g.getPerformanceInt("stewards", 10, 100, 1000),
		RequestsPerSecond:      g.getPerformanceInt("rps", 50, 200, 1000),
		TestDurationSeconds:    g.getPerformanceInt("duration", 30, 60, 300),
		DNAAttributesPerNode:   g.getPerformanceInt("dna_attrs", 10, 50, 200),
		ConfigResourcesPerNode: g.getPerformanceInt("config_resources", 5, 20, 100),
	}
}

// PerformanceTestData contains parameters for performance testing
type PerformanceTestData struct {
	ConcurrentStewards     int
	RequestsPerSecond      int
	TestDurationSeconds    int
	DNAAttributesPerNode   int
	ConfigResourcesPerNode int
}

func (g *TestDataGenerator) getPerformanceInt(metric string, small, medium, large int) int {
	switch g.config.TestDataSize {
	case "small":
		return small
	case "medium":
		return medium
	case "large":
		return large
	default:
		return small
	}
}

// Cross-Feature Integration Test Data Generators

// GenerateWorkflowConfigurationScenario creates data for workflow + configuration integration testing
func (g *TestDataGenerator) GenerateWorkflowConfigurationScenario() *WorkflowConfigurationScenario {
	stewardID := "workflow-config-test-steward"
	templateID := "test-app-deployment-template"

	// Create a realistic deployment template
	template := &TemplateData{
		ID:   templateID,
		Name: "Application Deployment Template",
		Content: `
# Application Deployment Configuration
resources:
  - name: app-directory
    module: directory
    config:
      path: $app_path
      permissions: "755"
      owner: $app_user
      
  - name: app-config-file
    module: file
    config:
      path: "$app_path/config.json"
      content: |
        {
          "environment": "$environment",
          "database_url": "$database_url",
          "log_level": "$log_level"
        }
      permissions: "644"
      
  - name: app-service
    module: script
    config:
      script: |
        #!/bin/bash
        systemctl enable $service_name
        systemctl start $service_name
      interpreter: "bash"
      timeout: 30
`,
		Variables: map[string]interface{}{
			"app_path":     "/opt/testapp",
			"app_user":     "testapp",
			"environment":  "testing",
			"database_url": "sqlite:///tmp/test.db",
			"log_level":    "info",
			"service_name": "testapp",
		},
	}

	// Create workflow that uses the template
	workflow := &WorkflowData{
		Name:        "deploy-application-workflow",
		Description: "Deploy application using configuration template",
		Steps: []WorkflowStep{
			{
				Name: "validate-environment",
				Type: "conditional",
				Condition: map[string]interface{}{
					"type":     "variable",
					"variable": "environment",
					"operator": "eq",
					"value":    "testing",
				},
				Steps: []WorkflowStep{
					{
						Name: "environment-setup",
						Type: "delay",
						Config: map[string]interface{}{
							"duration": "1s",
							"message":  "Setting up testing environment",
						},
					},
				},
			},
			{
				Name: "deploy-template",
				Type: "template",
				Config: map[string]interface{}{
					"template_id": templateID,
					"target":      stewardID,
				},
			},
			{
				Name: "verify-deployment",
				Type: "script",
				Config: map[string]interface{}{
					"script":      "test -d /opt/testapp && echo 'Deployment verified'",
					"interpreter": "bash",
					"timeout":     10,
				},
			},
		},
	}

	return &WorkflowConfigurationScenario{
		StewardID: stewardID,
		Template:  template,
		Workflow:  workflow,
	}
}

// GenerateDNADriftScenario creates data for DNA + drift detection integration testing
func (g *TestDataGenerator) GenerateDNADriftScenario() *DNADriftScenario {
	stewardID := "dna-drift-test-steward"

	// Generate baseline DNA
	baselineDNA := g.GenerateTestDNA(stewardID)

	// Create modified DNA simulating system drift
	driftedDNA := g.GenerateTestDNA(stewardID)
	// Simulate critical changes that should trigger alerts
	driftedDNA.Attributes["cpu_cores"] = "8"               // Changed from original
	driftedDNA.Attributes["memory_mb"] = "8192"            // Changed from original
	driftedDNA.Attributes["firewall_enabled"] = "false"    // Security-critical change
	driftedDNA.Attributes["antivirus_status"] = "inactive" // Security-critical change

	// Create remediation workflow
	remediationWorkflow := &WorkflowData{
		Name:        "drift-remediation-workflow",
		Description: "Automatic remediation for detected system drift",
		Steps: []WorkflowStep{
			{
				Name: "assess-drift-severity",
				Type: "conditional",
				Condition: map[string]interface{}{
					"type":       "expression",
					"expression": "${firewall_enabled} == 'false' || ${antivirus_status} == 'inactive'",
				},
				Steps: []WorkflowStep{
					{
						Name: "critical-security-alert",
						Type: "webhook",
						Config: map[string]interface{}{
							"url":    "https://alerts.example.com/critical",
							"method": "POST",
							"payload": map[string]interface{}{
								"severity": "critical",
								"message":  "Security drift detected on ${steward_id}",
							},
						},
					},
				},
			},
			{
				Name: "restore-security-settings",
				Type: "parallel",
				Steps: []WorkflowStep{
					{
						Name: "enable-firewall",
						Type: "script",
						Config: map[string]interface{}{
							"script":      "ufw enable",
							"interpreter": "bash",
							"timeout":     30,
						},
					},
					{
						Name: "start-antivirus",
						Type: "script",
						Config: map[string]interface{}{
							"script":      "systemctl start clamav-daemon",
							"interpreter": "bash",
							"timeout":     30,
						},
					},
				},
			},
		},
	}

	return &DNADriftScenario{
		StewardID:             stewardID,
		BaselineDNA:           baselineDNA,
		DriftedDNA:            driftedDNA,
		RemediationWorkflow:   remediationWorkflow,
		ExpectedDetectionTime: 5 * time.Minute, // SLA requirement
	}
}

// GenerateTemplateRollbackScenario creates data for template + rollback integration testing
func (g *TestDataGenerator) GenerateTemplateRollbackScenario() *TemplateRollbackScenario {
	stewardID := "template-rollback-test"

	// Create a template that will intentionally fail
	faultyTemplate := &TemplateData{
		ID:   "faulty-deployment-template",
		Name: "Faulty Deployment Template",
		Content: `
resources:
  - name: create-directory
    module: directory
    config:
      path: "/opt/testapp"
      permissions: "755"
      
  - name: failing-operation
    module: script
    config:
      script: |
        #!/bin/bash
        # This will fail intentionally
        exit 1
      interpreter: "bash"
      timeout: 10
`,
		Variables: map[string]interface{}{
			"should_fail": true,
		},
	}

	// Create known-good rollback configuration
	rollbackConfig := map[string]interface{}{
		"resources": []map[string]interface{}{
			{
				"name":   "cleanup-directory",
				"module": "directory",
				"config": map[string]interface{}{
					"path":  "/opt/testapp",
					"state": "absent",
				},
			},
		},
	}

	return &TemplateRollbackScenario{
		StewardID:       stewardID,
		FaultyTemplate:  faultyTemplate,
		RollbackConfig:  rollbackConfig,
		MaxRollbackTime: 30 * time.Second,
	}
}

// GenerateTerminalAuditScenario creates data for terminal + audit integration testing
func (g *TestDataGenerator) GenerateTerminalAuditScenario() *TerminalAuditScenario {
	stewardID := "terminal-audit-test"
	userID := "test-user"

	// Create test commands with different security levels
	testCommands := []TerminalCommand{
		{
			Command:        "ls -la",
			ExpectedAction: "allow",
			RiskLevel:      "low",
		},
		{
			Command:        "cat /etc/passwd",
			ExpectedAction: "allow",
			RiskLevel:      "medium",
		},
		{
			Command:        "rm -rf /tmp/testfile",
			ExpectedAction: "block",
			RiskLevel:      "high",
		},
		{
			Command:        "sudo su -",
			ExpectedAction: "audit",
			RiskLevel:      "critical",
		},
	}

	// Create RBAC permissions for test user
	userPermissions := map[string]bool{
		"terminal.connect": true,
		"terminal.execute": true,
		"terminal.view":    true,
		"terminal.audit":   false, // Cannot view audit logs
		"terminal.admin":   false, // Cannot admin terminals
	}

	return &TerminalAuditScenario{
		StewardID:           stewardID,
		UserID:              userID,
		TestCommands:        testCommands,
		UserPermissions:     userPermissions,
		ExpectedAuditEvents: len(testCommands) + 2, // Commands + session start/end
	}
}

// GenerateMultiTenantSaaSScenario creates data for multi-tenant + SaaS integration testing
func (g *TestDataGenerator) GenerateMultiTenantSaaSScenario() *MultiTenantSaaSScenario {
	// Create MSP-level configuration
	mspConfig := map[string]interface{}{
		"tenant_id":   "test-msp",
		"tenant_type": "msp",
		"m365": map[string]interface{}{
			"default_license": "Microsoft 365 Business Premium",
			"security_defaults": map[string]interface{}{
				"mfa_required":        true,
				"password_complexity": "high",
				"session_timeout":     "8h",
			},
		},
	}

	// Create client-level configuration that inherits from MSP
	clientConfig := map[string]interface{}{
		"tenant_id":   "test-client-1",
		"tenant_type": "client",
		"parent_id":   "test-msp",
		"m365": map[string]interface{}{
			"domain": "testclient1.onmicrosoft.com",
			"security_defaults": map[string]interface{}{
				"session_timeout": "4h", // Override MSP setting
			},
			"users": []map[string]interface{}{
				{
					"display_name":        "Test User 1",
					"user_principal_name": "testuser1@testclient1.onmicrosoft.com",
					"job_title":           "Test Engineer",
					"department":          "IT",
				},
			},
		},
	}

	// Create expected effective configuration after inheritance
	expectedEffectiveConfig := map[string]interface{}{
		"tenant_id":   "test-client-1",
		"tenant_type": "client",
		"parent_id":   "test-msp",
		"m365": map[string]interface{}{
			"domain":          "testclient1.onmicrosoft.com",
			"default_license": "Microsoft 365 Business Premium", // Inherited from MSP
			"security_defaults": map[string]interface{}{
				"mfa_required":        true,   // Inherited from MSP
				"password_complexity": "high", // Inherited from MSP
				"session_timeout":     "4h",   // Overridden by client
			},
			"users": []map[string]interface{}{
				{
					"display_name":        "Test User 1",
					"user_principal_name": "testuser1@testclient1.onmicrosoft.com",
					"job_title":           "Test Engineer",
					"department":          "IT",
				},
			},
		},
	}

	return &MultiTenantSaaSScenario{
		MSPConfig:               mspConfig,
		ClientConfig:            clientConfig,
		ExpectedEffectiveConfig: expectedEffectiveConfig,
		SaaSStewardID:           "saas-test-steward",
		TenantHierarchy:         []string{"test-msp", "test-client-1"},
	}
}

// Supporting data structures for cross-feature integration scenarios

type WorkflowConfigurationScenario struct {
	StewardID string
	Template  *TemplateData
	Workflow  *WorkflowData
}

type DNADriftScenario struct {
	StewardID             string
	BaselineDNA           *common.DNA
	DriftedDNA            *common.DNA
	RemediationWorkflow   *WorkflowData
	ExpectedDetectionTime time.Duration
}

type TemplateRollbackScenario struct {
	StewardID       string
	FaultyTemplate  *TemplateData
	RollbackConfig  map[string]interface{}
	MaxRollbackTime time.Duration
}

type TerminalAuditScenario struct {
	StewardID           string
	UserID              string
	TestCommands        []TerminalCommand
	UserPermissions     map[string]bool
	ExpectedAuditEvents int
}

type MultiTenantSaaSScenario struct {
	MSPConfig               map[string]interface{}
	ClientConfig            map[string]interface{}
	ExpectedEffectiveConfig map[string]interface{}
	SaaSStewardID           string
	TenantHierarchy         []string
}

type TemplateData struct {
	ID        string
	Name      string
	Content   string
	Variables map[string]interface{}
}

type WorkflowData struct {
	Name        string
	Description string
	Steps       []WorkflowStep
}

type WorkflowStep struct {
	Name      string
	Type      string
	Condition map[string]interface{} `json:",omitempty"`
	Config    map[string]interface{} `json:",omitempty"`
	Steps     []WorkflowStep         `json:",omitempty"`
}

type TerminalCommand struct {
	Command        string
	ExpectedAction string // "allow", "block", "audit"
	RiskLevel      string // "low", "medium", "high", "critical"
}
