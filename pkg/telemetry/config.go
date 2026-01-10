// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package telemetry

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ConfigFromEnvironment creates a telemetry configuration from environment variables.
// This allows runtime configuration of telemetry without code changes.
//
// Supported Environment Variables:
//   - CFGMS_TELEMETRY_ENABLED: Enable/disable telemetry (default: true)
//   - CFGMS_TELEMETRY_SERVICE_NAME: Service name for tracing
//   - CFGMS_TELEMETRY_SERVICE_VERSION: Service version for tracing
//   - CFGMS_TELEMETRY_ENVIRONMENT: Deployment environment (development, staging, production)
//   - CFGMS_TELEMETRY_OTLP_ENDPOINT: OpenTelemetry collector endpoint
//   - CFGMS_TELEMETRY_SAMPLE_RATE: Trace sampling rate (0.0 to 1.0)
//
// Example:
//
//	export CFGMS_TELEMETRY_OTLP_ENDPOINT="http://jaeger:14268/api/traces"
//	export CFGMS_TELEMETRY_SAMPLE_RATE="0.1"
//
//	config := telemetry.ConfigFromEnvironment("cfgms-controller", "v0.2.0")
func ConfigFromEnvironment(defaultServiceName, defaultVersion string) *Config {
	config := &Config{
		ServiceName:    getEnvString("CFGMS_TELEMETRY_SERVICE_NAME", defaultServiceName),
		ServiceVersion: getEnvString("CFGMS_TELEMETRY_SERVICE_VERSION", defaultVersion),
		Environment:    getEnvString("CFGMS_TELEMETRY_ENVIRONMENT", "development"),
		OTLPEndpoint:   getEnvString("CFGMS_TELEMETRY_OTLP_ENDPOINT", ""),
		SampleRate:     getEnvFloat("CFGMS_TELEMETRY_SAMPLE_RATE", 1.0),
		Enabled:        getEnvBool("CFGMS_TELEMETRY_ENABLED", true),
	}

	return config
}

// Validate checks the configuration for common issues and returns an error if invalid.
// This helps catch configuration problems early during application startup.
func (c *Config) Validate() error {
	if c.ServiceName == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	if c.ServiceVersion == "" {
		return fmt.Errorf("service version cannot be empty")
	}

	if c.SampleRate < 0.0 || c.SampleRate > 1.0 {
		return fmt.Errorf("sample rate must be between 0.0 and 1.0, got %f", c.SampleRate)
	}

	// Validate environment values
	validEnvironments := []string{"development", "staging", "production", "test"}
	if !contains(validEnvironments, c.Environment) {
		return fmt.Errorf("environment must be one of %v, got %s", validEnvironments, c.Environment)
	}

	return nil
}

// String returns a human-readable string representation of the configuration.
// This is useful for logging configuration details during startup.
func (c *Config) String() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("service=%s", c.ServiceName))
	parts = append(parts, fmt.Sprintf("version=%s", c.ServiceVersion))
	parts = append(parts, fmt.Sprintf("environment=%s", c.Environment))
	parts = append(parts, fmt.Sprintf("enabled=%t", c.Enabled))

	if c.OTLPEndpoint != "" {
		parts = append(parts, fmt.Sprintf("otlp_endpoint=%s", c.OTLPEndpoint))
	} else {
		parts = append(parts, "otlp_endpoint=disabled")
	}

	parts = append(parts, fmt.Sprintf("sample_rate=%.2f", c.SampleRate))

	return "telemetry.Config{" + strings.Join(parts, ", ") + "}"
}

// IsDevelopment returns true if the configuration is for a development environment.
// This can be used to enable development-specific telemetry features.
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsProduction returns true if the configuration is for a production environment.
// This can be used to enable production-specific telemetry optimizations.
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// WithOTLPEndpoint returns a copy of the configuration with the OTLP endpoint set.
// This is useful for programmatic configuration building.
func (c *Config) WithOTLPEndpoint(endpoint string) *Config {
	config := *c
	config.OTLPEndpoint = endpoint
	return &config
}

// WithSampleRate returns a copy of the configuration with the sample rate set.
// This is useful for programmatic configuration building.
func (c *Config) WithSampleRate(rate float64) *Config {
	config := *c
	config.SampleRate = rate
	return &config
}

// WithEnvironment returns a copy of the configuration with the environment set.
// This is useful for programmatic configuration building.
func (c *Config) WithEnvironment(env string) *Config {
	config := *c
	config.Environment = env
	return &config
}

// Helper functions for environment variable parsing

// getEnvString returns the environment variable value or the default if not set.
func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool returns the environment variable as a boolean or the default if not set/invalid.
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// getEnvFloat returns the environment variable as a float64 or the default if not set/invalid.
func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// contains checks if a slice contains a specific string value.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
