package e2e

import (
	"fmt"
	"math/rand"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	common "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/steward/config"
)

// TestDataGenerator provides lightweight test data generation optimized for CI environments
type TestDataGenerator struct {
	random *rand.Rand
	config *E2EConfig
}

// NewTestDataGenerator creates a new test data generator
func NewTestDataGenerator(config *E2EConfig) *TestDataGenerator {
	return &TestDataGenerator{
		random: rand.New(rand.NewSource(time.Now().UnixNano())),
		config: config,
	}
}

// GenerateTestDNA creates realistic DNA data for testing
func (g *TestDataGenerator) GenerateTestDNA(stewardID string) *common.DNA {
	// Base attributes that work across all platforms
	attributes := map[string]string{
		"hostname":     fmt.Sprintf("test-%s", stewardID),
		"steward_id":   stewardID,
		"version":      "test-1.0.0",
		"environment":  "testing",
		"test_mode":    "true",
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
		attributes["cpu_cores"] = fmt.Sprintf("%d", g.random.Intn(8)+2)
		attributes["memory_mb"] = fmt.Sprintf("%d", (g.random.Intn(8)+4)*1024)
		attributes["disk_gb"] = fmt.Sprintf("%d", g.random.Intn(100)+50)
		attributes["network_interfaces"] = fmt.Sprintf("%d", g.random.Intn(3)+1)
		attributes["os_family"] = g.randomChoice([]string{"linux", "windows", "darwin"})
		attributes["architecture"] = g.randomChoice([]string{"amd64", "arm64"})
	case "large":
		// Full dataset for performance testing
		attributes["cpu_cores"] = fmt.Sprintf("%d", g.random.Intn(32)+4)
		attributes["memory_mb"] = fmt.Sprintf("%d", (g.random.Intn(32)+8)*1024)
		attributes["disk_gb"] = fmt.Sprintf("%d", g.random.Intn(1000)+100)
		attributes["network_interfaces"] = fmt.Sprintf("%d", g.random.Intn(10)+1)
		attributes["os_family"] = g.randomChoice([]string{"linux", "windows", "darwin"})
		attributes["architecture"] = g.randomChoice([]string{"amd64", "arm64", "386"})
		attributes["kernel_version"] = g.generateKernelVersion()
		attributes["uptime_seconds"] = fmt.Sprintf("%d", g.random.Intn(86400*30))
		attributes["load_average"] = fmt.Sprintf("%.2f", g.random.Float64()*4)
		
		// Add security attributes
		attributes["firewall_enabled"] = g.randomChoice([]string{"true", "false"})
		attributes["antivirus_status"] = g.randomChoice([]string{"active", "inactive", "unknown"})
		attributes["encryption_status"] = g.randomChoice([]string{"enabled", "disabled", "partial"})
		
		// Add network attributes
		for i := 0; i < g.random.Intn(3)+1; i++ {
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
		for i := 0; i < g.random.Intn(3)+2; i++ {
			baseConfig.Resources = append(baseConfig.Resources,
				g.generateDirectoryResource(
					fmt.Sprintf("test-dir-%d", i),
					fmt.Sprintf("/tmp/cfgms-test/dir-%d", i),
				),
			)
		}
		for i := 0; i < g.random.Intn(5)+2; i++ {
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
	major := g.random.Intn(3) + 5 // 5.x, 6.x, 7.x
	minor := g.random.Intn(20)
	patch := g.random.Intn(10)
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

func (g *TestDataGenerator) generateIPAddress() string {
	return fmt.Sprintf("192.168.%d.%d", 
		g.random.Intn(255)+1, 
		g.random.Intn(254)+1)
}

func (g *TestDataGenerator) generateMACAddress() string {
	mac := make([]byte, 6)
	g.random.Read(mac)
	// Set the locally administered bit
	mac[0] |= 2
	mac[0] &= 0xfe
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func (g *TestDataGenerator) generateLargeContent(sizeBytes int) string {
	content := make([]byte, sizeBytes)
	for i := range content {
		content[i] = byte(g.random.Intn(94) + 32) // Printable ASCII
	}
	return string(content)
}

func (g *TestDataGenerator) randomChoice(choices []string) string {
	return choices[g.random.Intn(len(choices))]
}

// Performance test data generators

// GeneratePerformanceTestData creates data specifically for performance regression tests
func (g *TestDataGenerator) GeneratePerformanceTestData() *PerformanceTestData {
	return &PerformanceTestData{
		ConcurrentStewards:    g.getPerformanceInt("stewards", 10, 100, 1000),
		RequestsPerSecond:     g.getPerformanceInt("rps", 50, 200, 1000),
		TestDurationSeconds:   g.getPerformanceInt("duration", 30, 60, 300),
		DNAAttributesPerNode:  g.getPerformanceInt("dna_attrs", 10, 50, 200),
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