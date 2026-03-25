// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	loggingPkg "github.com/cfgis/cfgms/pkg/logging"
)

// envVarPattern matches ${VAR} patterns without defaults
// It excludes ${VAR:-default} and ${VAR:=default} patterns
var envVarPattern = regexp.MustCompile(`\$\{([^}:]+)\}`)

// envVarWithDefaultPattern matches ${VAR:-default} and ${VAR:=default} patterns
var envVarWithDefaultPattern = regexp.MustCompile(`\$\{([^}:]+):-([^}]*)\}`)

// validateEnvVars checks that all referenced environment variables (without defaults) are set.
// This provides fail-safe behavior: if a config references ${VAR} and VAR is not set,
// the application fails fast instead of silently using an empty value.
func validateEnvVars(content string) error {
	matches := envVarPattern.FindAllStringSubmatch(content, -1)
	var missing []string

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		varName := match[1]
		if _, exists := os.LookupEnv(varName); !exists {
			missing = append(missing, varName)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %v (use ${VAR:-default} syntax to provide defaults)", missing)
	}

	return nil
}

// expandEnvWithDefaults expands environment variables with support for ${VAR:-default} syntax.
// This extends Go's os.ExpandEnv to support shell-style defaults.
func expandEnvWithDefaults(content string) string {
	// First, expand ${VAR:-default} patterns
	result := envVarWithDefaultPattern.ReplaceAllStringFunc(content, func(match string) string {
		parts := envVarWithDefaultPattern.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}
		varName := parts[1]
		defaultValue := parts[2]
		if value, exists := os.LookupEnv(varName); exists {
			return value
		}
		return defaultValue
	})

	// Then expand remaining ${VAR} patterns using os.ExpandEnv
	return os.ExpandEnv(result)
}

// Config holds the controller configuration
type Config struct {
	// Controller listen address
	ListenAddr string `yaml:"listen_addr"`

	// External URL for controller API callbacks (used by scripts and external integrations)
	ExternalURL string `yaml:"external_url"`

	// Path to TLS certificates (legacy support)
	CertPath string `yaml:"cert_path"`

	// Data directory
	DataDir string `yaml:"data_dir"`

	// Log level (debug, info, warn, error)
	LogLevel string `yaml:"log_level"`

	// Certificate management configuration
	Certificate *CertificateConfig `yaml:"certificate"`

	// Storage configuration for global storage provider system
	Storage *StorageConfig `yaml:"storage"`

	// Logging configuration for global logging provider system
	Logging *LoggingConfig `yaml:"logging"`

	// High Availability configuration
	HA *HAConfig `yaml:"ha"`

	// QUIC server configuration for data plane communication (deprecated, use Transport)
	QUIC *QUICConfig `yaml:"quic"`

	// Transport is the unified, protocol-agnostic transport configuration.
	// Replaces the separate MQTT and QUIC sections. Old sections map here with deprecation warnings.
	Transport *TransportConfig `yaml:"transport"`
}

// CertificateConfig contains certificate management settings
type CertificateConfig struct {
	// Enable automated certificate lifecycle management
	//
	// When enabled (default: true), the controller handles the complete certificate lifecycle:
	// - Generates certificates if they don't exist (first deployment)
	// - Loads certificates if they exist (reboot/restart)
	// - Validates certificates are not expired or invalid
	// - Automatically renews certificates before expiration
	// - Coordinates certificate distribution in HA clusters
	//
	// When disabled, the controller does not manage certificates. Use this for:
	// - Testing with manually-injected invalid/expired certificates
	// - External certificate management (e.g., Vault, cert-manager, manual PKI)
	//
	// Note: In production, this should always be enabled unless you have
	// a specific external certificate management solution.
	EnableCertManagement bool `yaml:"enable_cert_management"`

	// Path to Certificate Authority storage
	CAPath string `yaml:"ca_path"`

	// Certificate renewal threshold in days (certificates renewed when within this threshold)
	// Default: 30 days
	RenewalThresholdDays int `yaml:"renewal_threshold_days"`

	// Server certificate validity period in days
	// Default: 365 days (1 year)
	ServerCertValidityDays int `yaml:"server_cert_validity_days"`

	// Client certificate validity period in days for stewards
	// Default: 365 days (1 year)
	ClientCertValidityDays int `yaml:"client_cert_validity_days"`

	// Server certificate configuration (used when generating certificates)
	Server *ServerCertificateConfig `yaml:"server"`

	// Story #377: Three-certificate architecture

	// Architecture selects the certificate deployment mode: "unified" (default) or "separated"
	// Unified: Single CertificateTypeServer for all purposes (backward compatible)
	// Separated: Purpose-specific certs (public API, internal mTLS, config signing)
	Architecture string `yaml:"architecture"`

	// SigningCertValidityDays is the validity for config signing certificates (default: 1095 = 3 years)
	SigningCertValidityDays int `yaml:"signing_cert_validity_days"`

	// InternalCertValidityDays is the validity for internal mTLS certificates (default: 365)
	InternalCertValidityDays int `yaml:"internal_cert_validity_days"`

	// PublicAPI contains configuration for the public-facing API certificate
	PublicAPI *PublicAPICertConfig `yaml:"public_api"`

	// Internal contains configuration for the internal mTLS certificate
	Internal *InternalCertConfig `yaml:"internal"`

	// Signing contains configuration for the config signing certificate
	Signing *SigningCertificateConfig `yaml:"signing"`
}

// PublicAPICertConfig contains configuration for the public-facing API certificate
type PublicAPICertConfig struct {
	// Source specifies where the certificate comes from: "internal" (default) or "external"
	// External: Load from CertPath/KeyPath (e.g., certbot/Let's Encrypt managed)
	// Internal: Generate from internal CA
	Source string `yaml:"source"`

	// CertPath is the path to the certificate file (for source=external)
	CertPath string `yaml:"cert_path"`

	// KeyPath is the path to the private key file (for source=external)
	KeyPath string `yaml:"key_path"`

	// CommonName for the public API certificate
	CommonName string `yaml:"common_name"`

	// DNSNames for Subject Alternative Names
	DNSNames []string `yaml:"dns_names"`
}

// InternalCertConfig contains configuration for the internal mTLS certificate
type InternalCertConfig struct {
	// CommonName for the internal certificate (default: "cfgms-internal")
	CommonName string `yaml:"common_name"`

	// DNSNames for Subject Alternative Names
	DNSNames []string `yaml:"dns_names"`

	// IPAddresses for Subject Alternative Names
	IPAddresses []string `yaml:"ip_addresses"`
}

// SigningCertificateConfig contains configuration for the config signing certificate
type SigningCertificateConfig struct {
	// CommonName for the signing certificate (default: "cfgms-config-signer")
	CommonName string `yaml:"common_name"`

	// Organization name
	Organization string `yaml:"organization"`
}

// ServerCertificateConfig contains server certificate settings
type ServerCertificateConfig struct {
	// Common name for server certificate
	CommonName string `yaml:"common_name"`

	// DNS names for Subject Alternative Names
	DNSNames []string `yaml:"dns_names"`

	// IP addresses for Subject Alternative Names
	IPAddresses []string `yaml:"ip_addresses"`

	// Organization name
	Organization string `yaml:"organization"`
}

// StorageConfig contains global storage provider configuration
type StorageConfig struct {
	// Provider specifies which storage provider to use (database, git)
	Provider string `yaml:"provider"`

	// Configuration options passed to the storage provider
	// The structure depends on the specific provider being used
	Config map[string]interface{} `yaml:"config"`
}

// LoggingConfig contains global logging provider configuration
type LoggingConfig struct {
	// Provider specifies which logging provider to use (file, timescale, clickhouse)
	Provider string `yaml:"provider"`

	// Configuration options passed to the logging provider
	// The structure depends on the specific provider being used
	Config map[string]interface{} `yaml:"config"`

	// Global logging settings
	Level       string `yaml:"level"`        // Minimum log level (DEBUG, INFO, WARN, ERROR, FATAL)
	ServiceName string `yaml:"service_name"` // Service identifier
	Component   string `yaml:"component"`    // Component identifier

	// Performance settings
	BatchSize     int    `yaml:"batch_size"`     // Batch size for bulk writes
	FlushInterval string `yaml:"flush_interval"` // Auto-flush interval (duration string)
	AsyncWrites   bool   `yaml:"async_writes"`   // Enable asynchronous writes
	BufferSize    int    `yaml:"buffer_size"`    // Internal buffer size

	// Retention settings (provider-dependent)
	RetentionDays int  `yaml:"retention_days"` // Log retention period
	CompressLogs  bool `yaml:"compress_logs"`  // Enable log compression

	// Multi-tenant settings
	TenantIsolation bool `yaml:"tenant_isolation"` // Enable tenant isolation in logs

	// Enhanced correlation tracking
	EnableCorrelation bool `yaml:"enable_correlation"` // Enable automatic correlation IDs
	EnableTracing     bool `yaml:"enable_tracing"`     // Enable OpenTelemetry integration

	// Event subscriber configuration (optional)
	Subscribers []SubscriberConfig `yaml:"subscribers"` // Event subscribers for real-time forwarding
}

// SubscriberConfig holds configuration for event subscribers
type SubscriberConfig struct {
	Type    string                 `yaml:"type"`    // Subscriber type (e.g., "syslog", "webhook")
	Config  map[string]interface{} `yaml:"config"`  // Subscriber-specific configuration
	Enabled bool                   `yaml:"enabled"` // Enable/disable subscriber
}

// HAConfig contains high availability configuration
type HAConfig struct {
	// Deployment mode (single, blue-green, cluster)
	Mode string `yaml:"mode"`

	// Node configuration
	Node *HANodeConfig `yaml:"node"`

	// Cluster configuration (used in cluster mode)
	Cluster *HAClusterConfig `yaml:"cluster"`

	// Health check configuration
	HealthCheck *HAHealthCheckConfig `yaml:"health_check"`

	// Failover configuration
	Failover *HAFailoverConfig `yaml:"failover"`

	// Load balancing configuration
	LoadBalancing *HALoadBalancingConfig `yaml:"load_balancing"`

	// Split-brain prevention configuration
	SplitBrain *HASplitBrainConfig `yaml:"split_brain"`
}

// HANodeConfig contains node-specific HA configuration
type HANodeConfig struct {
	ID              string            `yaml:"id"`
	Name            string            `yaml:"name"`
	ExternalAddress string            `yaml:"external_address"`
	InternalAddress string            `yaml:"internal_address"`
	Capabilities    []string          `yaml:"capabilities"`
	Metadata        map[string]string `yaml:"metadata"`
}

// HAClusterConfig contains cluster-wide HA configuration
type HAClusterConfig struct {
	ExpectedSize      int                  `yaml:"expected_size"`
	MinQuorum         int                  `yaml:"min_quorum"`
	ElectionTimeout   string               `yaml:"election_timeout"`   // Duration string
	HeartbeatInterval string               `yaml:"heartbeat_interval"` // Duration string
	Discovery         *HADiscoveryConfig   `yaml:"discovery"`
	SessionSync       *HASessionSyncConfig `yaml:"session_sync"`
}

// HADiscoveryConfig contains node discovery configuration
type HADiscoveryConfig struct {
	Method      string                 `yaml:"method"`
	Config      map[string]interface{} `yaml:"config"`
	Interval    string                 `yaml:"interval"`     // Duration string
	NodeTimeout string                 `yaml:"node_timeout"` // Duration string
}

// HASessionSyncConfig contains session synchronization configuration
type HASessionSyncConfig struct {
	Enabled      bool   `yaml:"enabled"`
	SyncInterval string `yaml:"sync_interval"` // Duration string
	StateTimeout string `yaml:"state_timeout"` // Duration string
	MaxStateSize int    `yaml:"max_state_size"`
}

// HAHealthCheckConfig contains health check configuration
type HAHealthCheckConfig struct {
	Interval         string `yaml:"interval"` // Duration string
	Timeout          string `yaml:"timeout"`  // Duration string
	FailureThreshold int    `yaml:"failure_threshold"`
	SuccessThreshold int    `yaml:"success_threshold"`
	EnableInternal   bool   `yaml:"enable_internal"`
	EnableExternal   bool   `yaml:"enable_external"`
}

// HAFailoverConfig contains failover configuration
type HAFailoverConfig struct {
	Enabled             bool   `yaml:"enabled"`
	Timeout             string `yaml:"timeout"`      // Duration string
	MaxDuration         string `yaml:"max_duration"` // Duration string
	GracePeriod         string `yaml:"grace_period"` // Duration string
	MaxSessionMigration int    `yaml:"max_session_migration"`
}

// HALoadBalancingConfig contains load balancing configuration
type HALoadBalancingConfig struct {
	Strategy        string                   `yaml:"strategy"`
	HealthBased     *HAHealthBasedConfig     `yaml:"health_based"`
	ConnectionBased *HAConnectionBasedConfig `yaml:"connection_based"`
}

// HAHealthBasedConfig contains health-based load balancing configuration
type HAHealthBasedConfig struct {
	MinHealthScore     float64 `yaml:"min_health_score"`
	HealthWeightFactor float64 `yaml:"health_weight_factor"`
}

// HAConnectionBasedConfig contains connection-based load balancing configuration
type HAConnectionBasedConfig struct {
	MaxConnectionsPerNode int     `yaml:"max_connections_per_node"`
	ConnectionThreshold   float64 `yaml:"connection_threshold"`
}

// HASplitBrainConfig contains split-brain prevention configuration
type HASplitBrainConfig struct {
	Enabled            bool   `yaml:"enabled"`
	DetectionInterval  string `yaml:"detection_interval"` // Duration string
	QuorumInterval     string `yaml:"quorum_interval"`    // Duration string
	ResolutionStrategy string `yaml:"resolution_strategy"`
}

// QUICConfig contains QUIC server configuration for data plane
type QUICConfig struct {
	// Enable QUIC server
	Enabled bool `yaml:"enabled"`

	// QUIC listen address (e.g., "0.0.0.0:4433")
	ListenAddr string `yaml:"listen_addr"`

	// Use certificate manager for QUIC certificates
	UseCertManager bool `yaml:"use_cert_manager"`

	// TLS certificate path (if not using cert manager)
	TLSCertPath string `yaml:"tls_cert_path,omitempty"`

	// TLS key path (if not using cert manager)
	TLSKeyPath string `yaml:"tls_key_path,omitempty"`

	// CA certificate path for client verification
	TLSCAPath string `yaml:"tls_ca_path,omitempty"`

	// Session timeout in seconds
	SessionTimeout int `yaml:"session_timeout"`
}

// Duration is a time.Duration that supports YAML string parsing ("30s", "5m", etc.)
// This allows human-readable duration values in configuration files.
type Duration time.Duration

// UnmarshalYAML parses duration strings like "30s", "5m", "1h" from YAML.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value.Value, err)
	}
	*d = Duration(dur)
	return nil
}

// MarshalYAML serializes the duration as a human-readable string.
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// AsDuration returns the underlying time.Duration value.
func (d Duration) AsDuration() time.Duration {
	return time.Duration(d)
}

// TransportConfig is the unified, protocol-agnostic transport configuration.
// It replaces the separate MQTTConfig and QUICConfig sections.
// A single listen address serves both control plane and data plane over gRPC-over-QUIC,
// and can accommodate future transport implementations without config changes.
type TransportConfig struct {
	// ListenAddr is the address for the unified transport server (e.g., "0.0.0.0:4433")
	ListenAddr string `yaml:"listen_addr"`

	// UseCertManager enables the controller's certificate manager for TLS.
	// When true (default), certificates are managed automatically.
	UseCertManager bool `yaml:"use_cert_manager"`

	// MaxConnections is the maximum number of concurrent client connections.
	MaxConnections int `yaml:"max_connections"`

	// KeepalivePeriod is how often keepalive probes are sent to detect dead connections.
	// Minimum: 1s. Default: 30s.
	KeepalivePeriod Duration `yaml:"keepalive_period"`

	// IdleTimeout is how long a connection can remain idle before being closed.
	// Default: 5m.
	IdleTimeout Duration `yaml:"idle_timeout"`
}

// Validate checks the TransportConfig for invalid values.
// Returns an error if listen_addr is empty, max_connections < 1, or keepalive_period < 1s.
func (t *TransportConfig) Validate() error {
	if t == nil {
		return fmt.Errorf("transport config must not be nil")
	}
	if t.ListenAddr == "" {
		return fmt.Errorf("transport.listen_addr must not be empty")
	}
	if t.MaxConnections < 1 {
		return fmt.Errorf("transport.max_connections must be at least 1, got %d", t.MaxConnections)
	}
	if t.KeepalivePeriod.AsDuration() < time.Second {
		return fmt.Errorf("transport.keepalive_period must be at least 1s, got %v", t.KeepalivePeriod.AsDuration())
	}
	return nil
}

// DefaultConfig returns a Config with reasonable defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:  "127.0.0.1:8080",
		ExternalURL: "https://localhost:8080", // Default external URL
		CertPath:    "certs/",
		DataDir:     "data/",
		LogLevel:    "info",
		Certificate: &CertificateConfig{
			EnableCertManagement:   true,
			CAPath:                 "certs/ca",
			RenewalThresholdDays:   30,
			ServerCertValidityDays: 365,
			ClientCertValidityDays: 365,
			Server: &ServerCertificateConfig{
				CommonName:   "cfgms-controller",
				DNSNames:     []string{"localhost", "cfgms-controller", "controller-standalone"},
				IPAddresses:  []string{"127.0.0.1"},
				Organization: "CFGMS",
			},
		},
		Storage: &StorageConfig{
			Provider: "git", // Epic 6: Use git as minimum viable storage (no in-memory fallbacks)
			Config: map[string]interface{}{
				"repository_path": "data/cfgms-storage", // Default local git repository
				"branch":          "main",
				"auto_init":       true,
			},
		},
		Logging: &LoggingConfig{
			Provider: "file", // Default to file-based time-series logging
			Config: map[string]interface{}{
				"directory":        "/var/log/cfgms",
				"file_prefix":      "cfgms",
				"max_file_size":    100 * 1024 * 1024, // 100MB
				"max_files":        10,
				"retention_days":   30,
				"compress_rotated": true,
			},
			Level:             "INFO",
			ServiceName:       "cfgms-controller",
			Component:         "controller",
			BatchSize:         100,
			FlushInterval:     "5s",
			AsyncWrites:       true,
			BufferSize:        1000,
			RetentionDays:     30,
			CompressLogs:      true,
			TenantIsolation:   true,
			EnableCorrelation: true,
			EnableTracing:     true,
		},
		HA: &HAConfig{
			Mode: "single", // Default to single server mode for seamless operation
			Node: &HANodeConfig{
				Capabilities: []string{"config", "rbac", "monitoring", "workflow"},
				Metadata:     make(map[string]string),
			},
			Cluster: &HAClusterConfig{
				ExpectedSize:      3,
				MinQuorum:         2,
				ElectionTimeout:   "10s",
				HeartbeatInterval: "2s",
				Discovery: &HADiscoveryConfig{
					Method:      "static",
					Config:      make(map[string]interface{}),
					Interval:    "30s",
					NodeTimeout: "60s",
				},
				SessionSync: &HASessionSyncConfig{
					Enabled:      true,
					SyncInterval: "5s",
					StateTimeout: "300s",
					MaxStateSize: 1024 * 1024, // 1MB
				},
			},
			HealthCheck: &HAHealthCheckConfig{
				Interval:         "10s",
				Timeout:          "5s",
				FailureThreshold: 3,
				SuccessThreshold: 2,
				EnableInternal:   true,
				EnableExternal:   true,
			},
			Failover: &HAFailoverConfig{
				Enabled:             true,
				Timeout:             "30s",
				MaxDuration:         "5m",
				GracePeriod:         "10s",
				MaxSessionMigration: 1000,
			},
			LoadBalancing: &HALoadBalancingConfig{
				Strategy: "health-based",
				HealthBased: &HAHealthBasedConfig{
					MinHealthScore:     0.7,
					HealthWeightFactor: 1.0,
				},
				ConnectionBased: &HAConnectionBasedConfig{
					MaxConnectionsPerNode: 1000,
					ConnectionThreshold:   0.8,
				},
			},
			SplitBrain: &HASplitBrainConfig{
				Enabled:            true,
				DetectionInterval:  "15s",
				QuorumInterval:     "30s",
				ResolutionStrategy: "quorum-based",
			},
		},
		QUIC: &QUICConfig{
			Enabled:        true, // Core data plane - enabled by default (Story #198)
			ListenAddr:     "0.0.0.0:4433",
			UseCertManager: true, // Use controller's certificate manager
			SessionTimeout: 300,  // 5 minutes
		},
		Transport: &TransportConfig{
			ListenAddr:      "0.0.0.0:4433",
			UseCertManager:  true,
			MaxConnections:  50000,
			KeepalivePeriod: Duration(30 * time.Second),
			IdleTimeout:     Duration(5 * time.Minute),
		},
	}
}

// migrateTransportConfig detects deprecated mqtt: and quic: sections in the raw YAML
// and migrates quic: fields to the Transport section with a deprecation warning.
//
// Migration rules:
//   - If transport: is present and quic: is also present: new section wins, log warning
//   - If only quic: is present: migrate listen_addr and use_cert_manager to transport
func migrateTransportConfig(cfg *Config, rawYAML []byte) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(rawYAML, &raw); err != nil {
		return // Can't detect keys, skip migration
	}

	_, hasTransport := raw["transport"]
	_, hasQUIC := raw["quic"]

	if !hasQUIC {
		return // Nothing to migrate
	}

	if hasTransport {
		// New section wins; warn that old sections are ignored
		log.Printf("[WARN] config: transport: section overrides deprecated quic: section — old section is ignored")
		return
	}

	// No transport: section in YAML — migrate from quic: section
	if cfg.Transport == nil {
		cfg.Transport = &TransportConfig{
			ListenAddr:      "0.0.0.0:4433",
			UseCertManager:  true,
			MaxConnections:  50000,
			KeepalivePeriod: Duration(30 * time.Second),
			IdleTimeout:     Duration(5 * time.Minute),
		}
	}

	if hasQUIC && cfg.QUIC != nil {
		log.Printf("[WARN] config: quic: section is deprecated; please migrate to transport: section")
		if cfg.QUIC.ListenAddr != "" {
			cfg.Transport.ListenAddr = cfg.QUIC.ListenAddr
		}
		cfg.Transport.UseCertManager = cfg.QUIC.UseCertManager
	}
}

// findConfigFile searches for the controller configuration file using the following priority:
// 1. Explicit path (if provided and not empty)
// 2. CFGMS_CONTROLLER_CONFIG environment variable
// 3. Production paths: /etc/cfgms/controller.cfg (Unix) or C:\ProgramData\cfgms\controller.cfg (Windows)
// 4. Development path: ./controller.cfg
//
// Returns the path to the configuration file if found, empty string if no config file exists.
func findConfigFile(explicitPath string) (string, error) {
	// Priority 1: Explicit path from CLI flag
	if explicitPath != "" {
		if _, err := os.Stat(explicitPath); err == nil {
			return explicitPath, nil
		}
		// If explicit path provided but doesn't exist, return error
		return "", fmt.Errorf("config file not found at specified path: %s", explicitPath)
	}

	// Priority 2: Environment variable
	if envPath := os.Getenv("CFGMS_CONTROLLER_CONFIG"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath, nil
		}
		// If env var set but file doesn't exist, return error
		return "", fmt.Errorf("config file not found at CFGMS_CONTROLLER_CONFIG path: %s", envPath)
	}

	// Priority 3: Production paths (platform-specific)
	var productionPath string
	if isWindows() {
		productionPath = `C:\ProgramData\cfgms\controller.cfg`
	} else {
		productionPath = "/etc/cfgms/controller.cfg"
	}
	if _, err := os.Stat(productionPath); err == nil {
		return productionPath, nil
	}

	// Priority 4: Development path
	devPath := "controller.cfg"
	if _, err := os.Stat(devPath); err == nil {
		return devPath, nil
	}

	// No config file found - this is OK, will use defaults
	return "", nil
}

// isWindows returns true if running on Windows
func isWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

// LoadWithPath loads the configuration from the specified file path (or searches for it)
// and applies environment variable overrides.
//
// If configPath is empty, searches for config file using findConfigFile().
// If no config file is found, uses default configuration with environment variable overrides.
func LoadWithPath(configPath string) (*Config, error) {
	cfg := DefaultConfig()

	// Find the config file (explicit path, env var, production, or dev)
	foundPath, err := findConfigFile(configPath)
	if err != nil {
		return nil, err
	}

	// Load from config file if found
	if foundPath != "" {
		data, err := os.ReadFile(foundPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", foundPath, err)
		}

		content := string(data)

		// Validate that all referenced env vars (without defaults) are set
		// This provides fail-safe behavior for missing env vars
		if err := validateEnvVars(content); err != nil {
			return nil, fmt.Errorf("configuration validation failed in %s: %w", foundPath, err)
		}

		// Expand environment variables in the configuration content
		// This supports ${VAR} and ${VAR:-default} syntax for explicit env var references
		expandedData := expandEnvWithDefaults(content)
		expandedBytes := []byte(expandedData)

		if err := yaml.Unmarshal(expandedBytes, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", foundPath, err)
		}

		// Migrate deprecated mqtt:/quic: sections to the unified transport: section
		migrateTransportConfig(cfg, expandedBytes)
	}

	// Override with environment variables if set
	if addr := os.Getenv("CFGMS_LISTEN_ADDR"); addr != "" {
		cfg.ListenAddr = addr
	}

	if externalURL := os.Getenv("CFGMS_EXTERNAL_URL"); externalURL != "" {
		cfg.ExternalURL = externalURL
	}

	if certPath := os.Getenv("CFGMS_CERT_PATH"); certPath != "" {
		cfg.CertPath = certPath
	}

	if dataDir := os.Getenv("CFGMS_DATA_DIR"); dataDir != "" {
		cfg.DataDir = dataDir
	}

	if logLevel := os.Getenv("CFGMS_LOG_LEVEL"); logLevel != "" {
		cfg.LogLevel = logLevel
	}

	// Certificate management environment variables
	if enableCertMgmt := os.Getenv("CFGMS_CERT_ENABLE_MANAGEMENT"); enableCertMgmt != "" {
		if val, err := strconv.ParseBool(enableCertMgmt); err == nil {
			cfg.Certificate.EnableCertManagement = val
		}
	}

	if caPath := os.Getenv("CFGMS_CERT_CA_PATH"); caPath != "" {
		cfg.Certificate.CAPath = caPath
	}

	if renewalThreshold := os.Getenv("CFGMS_CERT_RENEWAL_THRESHOLD_DAYS"); renewalThreshold != "" {
		if val, err := strconv.Atoi(renewalThreshold); err == nil {
			cfg.Certificate.RenewalThresholdDays = val
		}
	}

	if serverValidity := os.Getenv("CFGMS_CERT_SERVER_VALIDITY_DAYS"); serverValidity != "" {
		if val, err := strconv.Atoi(serverValidity); err == nil {
			cfg.Certificate.ServerCertValidityDays = val
		}
	}

	if clientValidity := os.Getenv("CFGMS_CERT_CLIENT_VALIDITY_DAYS"); clientValidity != "" {
		if val, err := strconv.Atoi(clientValidity); err == nil {
			cfg.Certificate.ClientCertValidityDays = val
		}
	}

	if serverCommonName := os.Getenv("CFGMS_CERT_SERVER_COMMON_NAME"); serverCommonName != "" {
		cfg.Certificate.Server.CommonName = serverCommonName
	}

	if serverOrg := os.Getenv("CFGMS_CERT_SERVER_ORGANIZATION"); serverOrg != "" {
		cfg.Certificate.Server.Organization = serverOrg
	}

	// Story #377: Three-certificate architecture environment variables
	if certArch := os.Getenv("CFGMS_CERT_ARCHITECTURE"); certArch != "" {
		cfg.Certificate.Architecture = certArch
	}

	if signingValidity := os.Getenv("CFGMS_CERT_SIGNING_VALIDITY_DAYS"); signingValidity != "" {
		if val, err := strconv.Atoi(signingValidity); err == nil {
			cfg.Certificate.SigningCertValidityDays = val
		}
	}

	if publicAPISource := os.Getenv("CFGMS_CERT_PUBLIC_API_SOURCE"); publicAPISource != "" {
		if cfg.Certificate.PublicAPI == nil {
			cfg.Certificate.PublicAPI = &PublicAPICertConfig{}
		}
		cfg.Certificate.PublicAPI.Source = publicAPISource
	}

	if publicAPICertPath := os.Getenv("CFGMS_CERT_PUBLIC_API_CERT_PATH"); publicAPICertPath != "" {
		if cfg.Certificate.PublicAPI == nil {
			cfg.Certificate.PublicAPI = &PublicAPICertConfig{}
		}
		cfg.Certificate.PublicAPI.CertPath = publicAPICertPath
	}

	if publicAPIKeyPath := os.Getenv("CFGMS_CERT_PUBLIC_API_KEY_PATH"); publicAPIKeyPath != "" {
		if cfg.Certificate.PublicAPI == nil {
			cfg.Certificate.PublicAPI = &PublicAPICertConfig{}
		}
		cfg.Certificate.PublicAPI.KeyPath = publicAPIKeyPath
	}

	// Storage configuration environment variables
	if storageProvider := os.Getenv("CFGMS_STORAGE_PROVIDER"); storageProvider != "" {
		cfg.Storage.Provider = storageProvider

		// Initialize storage config map if nil
		if cfg.Storage.Config == nil {
			cfg.Storage.Config = make(map[string]interface{})
		}

		// Map provider-specific environment variables to config
		switch storageProvider {
		case "database":
			// Database storage configuration mapping - support both CFGMS_STORAGE_DATABASE_* and CFGMS_DB_* variants
			if host := os.Getenv("CFGMS_STORAGE_DATABASE_HOST"); host != "" {
				cfg.Storage.Config["host"] = host
			} else if host := os.Getenv("CFGMS_DB_HOST"); host != "" {
				cfg.Storage.Config["host"] = host
			}

			if port := os.Getenv("CFGMS_STORAGE_DATABASE_PORT"); port != "" {
				// Convert port string to int
				if portInt, err := strconv.Atoi(port); err == nil {
					cfg.Storage.Config["port"] = portInt
				}
			} else if port := os.Getenv("CFGMS_DB_PORT"); port != "" {
				// Convert port string to int
				if portInt, err := strconv.Atoi(port); err == nil {
					cfg.Storage.Config["port"] = portInt
				}
			}

			if database := os.Getenv("CFGMS_STORAGE_DATABASE_NAME"); database != "" {
				cfg.Storage.Config["database"] = database
			} else if database := os.Getenv("CFGMS_DB_NAME"); database != "" {
				cfg.Storage.Config["database"] = database
			}

			if username := os.Getenv("CFGMS_STORAGE_DATABASE_USER"); username != "" {
				cfg.Storage.Config["username"] = username
			} else if username := os.Getenv("CFGMS_DB_USER"); username != "" {
				cfg.Storage.Config["username"] = username
			}

			if password := os.Getenv("CFGMS_STORAGE_DATABASE_PASSWORD"); password != "" {
				cfg.Storage.Config["password"] = password
			} else if password := os.Getenv("CFGMS_DB_PASSWORD"); password != "" {
				cfg.Storage.Config["password"] = password
			}

			if sslmode := os.Getenv("CFGMS_STORAGE_DATABASE_SSLMODE"); sslmode != "" {
				cfg.Storage.Config["sslmode"] = sslmode
			} else if sslmode := os.Getenv("CFGMS_DB_SSLMODE"); sslmode != "" {
				cfg.Storage.Config["sslmode"] = sslmode
			}
		case "git":
			// Git storage configuration mapping
			if path := os.Getenv("CFGMS_STORAGE_GIT_PATH"); path != "" {
				cfg.Storage.Config["path"] = path
			}
			if url := os.Getenv("CFGMS_STORAGE_GIT_URL"); url != "" {
				cfg.Storage.Config["url"] = url
			}
			if branch := os.Getenv("CFGMS_STORAGE_GIT_BRANCH"); branch != "" {
				cfg.Storage.Config["branch"] = branch
			}
			if username := os.Getenv("CFGMS_STORAGE_GIT_USERNAME"); username != "" {
				cfg.Storage.Config["username"] = username
			}
			if password := os.Getenv("CFGMS_STORAGE_GIT_PASSWORD"); password != "" {
				cfg.Storage.Config["password"] = password
			}
			if token := os.Getenv("CFGMS_STORAGE_GIT_TOKEN"); token != "" {
				cfg.Storage.Config["token"] = token
			}
		}
	}

	// Logging configuration environment variables
	if loggingProvider := os.Getenv("CFGMS_LOGGING_PROVIDER"); loggingProvider != "" {
		cfg.Logging.Provider = loggingProvider
	}

	if logLevel := os.Getenv("CFGMS_LOG_LEVEL"); logLevel != "" {
		cfg.Logging.Level = logLevel
	}

	if serviceName := os.Getenv("CFGMS_LOGGING_SERVICE_NAME"); serviceName != "" {
		cfg.Logging.ServiceName = serviceName
	}

	if component := os.Getenv("CFGMS_LOGGING_COMPONENT"); component != "" {
		cfg.Logging.Component = component
	}

	// QUIC configuration environment variables
	if quicEnabled := os.Getenv("CFGMS_QUIC_ENABLED"); quicEnabled != "" {
		if val, err := strconv.ParseBool(quicEnabled); err == nil {
			cfg.QUIC.Enabled = val
		}
	}

	if quicListenAddr := os.Getenv("CFGMS_QUIC_LISTEN_ADDR"); quicListenAddr != "" {
		cfg.QUIC.ListenAddr = quicListenAddr
	}

	if quicUseCertManager := os.Getenv("CFGMS_QUIC_USE_CERT_MANAGER"); quicUseCertManager != "" {
		if val, err := strconv.ParseBool(quicUseCertManager); err == nil {
			cfg.QUIC.UseCertManager = val
		}
	}

	// Transport configuration environment variables
	if transportListenAddr := os.Getenv("CFGMS_TRANSPORT_LISTEN_ADDR"); transportListenAddr != "" && cfg.Transport != nil {
		cfg.Transport.ListenAddr = transportListenAddr
	}

	if transportUseCertManager := os.Getenv("CFGMS_TRANSPORT_USE_CERT_MANAGER"); transportUseCertManager != "" && cfg.Transport != nil {
		if val, err := strconv.ParseBool(transportUseCertManager); err == nil {
			cfg.Transport.UseCertManager = val
		}
	}

	if transportMaxConns := os.Getenv("CFGMS_TRANSPORT_MAX_CONNECTIONS"); transportMaxConns != "" && cfg.Transport != nil {
		if val, err := strconv.Atoi(transportMaxConns); err == nil {
			cfg.Transport.MaxConnections = val
		}
	}

	if transportKeepalive := os.Getenv("CFGMS_TRANSPORT_KEEPALIVE_PERIOD"); transportKeepalive != "" && cfg.Transport != nil {
		if dur, err := time.ParseDuration(transportKeepalive); err == nil {
			cfg.Transport.KeepalivePeriod = Duration(dur)
		}
	}

	if transportIdleTimeout := os.Getenv("CFGMS_TRANSPORT_IDLE_TIMEOUT"); transportIdleTimeout != "" && cfg.Transport != nil {
		if dur, err := time.ParseDuration(transportIdleTimeout); err == nil {
			cfg.Transport.IdleTimeout = Duration(dur)
		}
	}

	// HTTP API configuration environment variables
	if httpListenAddr := os.Getenv("CFGMS_HTTP_LISTEN_ADDR"); httpListenAddr != "" {
		cfg.ListenAddr = httpListenAddr
	}

	return cfg, nil
}

// Load loads the configuration using default search paths.
// This is a convenience wrapper around LoadWithPath("") for backward compatibility.
//
// Config file search order:
// 1. CFGMS_CONTROLLER_CONFIG environment variable
// 2. /etc/cfgms/controller.cfg (Unix) or C:\ProgramData\cfgms\controller.cfg (Windows)
// 3. ./controller.cfg
//
// If no config file is found, uses default configuration with environment variable overrides.
func Load() (*Config, error) {
	return LoadWithPath("")
}

// ToLoggingManagerConfig converts the controller logging config to pkg/logging config
func (lc *LoggingConfig) ToLoggingManagerConfig() *loggingPkg.LoggingConfig {
	if lc == nil {
		return loggingPkg.DefaultLoggingConfig("cfgms-controller", "controller")
	}

	// Parse flush interval duration
	flushInterval := 5 * time.Second
	if lc.FlushInterval != "" {
		if duration, err := time.ParseDuration(lc.FlushInterval); err == nil {
			flushInterval = duration
		}
	}

	// Convert subscribers configuration
	var subscribers []loggingPkg.SubscriberConfig
	for _, sub := range lc.Subscribers {
		subscribers = append(subscribers, loggingPkg.SubscriberConfig{
			Type:    sub.Type,
			Config:  sub.Config,
			Enabled: sub.Enabled,
		})
	}

	return &loggingPkg.LoggingConfig{
		Provider:          lc.Provider,
		Config:            lc.Config,
		Level:             lc.Level,
		ServiceName:       lc.ServiceName,
		Component:         lc.Component,
		BatchSize:         lc.BatchSize,
		FlushInterval:     flushInterval,
		AsyncWrites:       lc.AsyncWrites,
		BufferSize:        lc.BufferSize,
		RetentionDays:     lc.RetentionDays,
		CompressLogs:      lc.CompressLogs,
		TenantIsolation:   lc.TenantIsolation,
		EnableCorrelation: lc.EnableCorrelation,
		EnableTracing:     lc.EnableTracing,
		Subscribers:       subscribers,
	}
}

// IsSeparatedArchitecture returns true if the certificate architecture is "separated"
func (cc *CertificateConfig) IsSeparatedArchitecture() bool {
	return cc != nil && cc.Architecture == "separated"
}

// GetPublicAPISource returns the public API certificate source, defaulting to "internal"
func (cc *CertificateConfig) GetPublicAPISource() string {
	if cc != nil && cc.PublicAPI != nil && cc.PublicAPI.Source != "" {
		return cc.PublicAPI.Source
	}
	return "internal"
}
