package config

import (
	"os"
	"strconv"
	"time"
	
	"gopkg.in/yaml.v3"
	
	loggingPkg "github.com/cfgis/cfgms/pkg/logging"
)

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

	// MQTT broker configuration for control plane communication
	MQTT *MQTTConfig `yaml:"mqtt"`

	// QUIC server configuration for data plane communication
	QUIC *QUICConfig `yaml:"quic"`
}

// CertificateConfig contains certificate management settings
type CertificateConfig struct {
	// Enable automated certificate management
	EnableCertManagement bool `yaml:"enable_cert_management"`
	
	// Path to Certificate Authority storage
	CAPath string `yaml:"ca_path"`
	
	// Automatically generate server certificates if missing
	AutoGenerate bool `yaml:"auto_generate"`
	
	// Certificate renewal threshold in days
	RenewalThresholdDays int `yaml:"renewal_threshold_days"`
	
	// Server certificate validity period in days
	ServerCertValidityDays int `yaml:"server_cert_validity_days"`
	
	// Client certificate validity period in days for stewards
	ClientCertValidityDays int `yaml:"client_cert_validity_days"`
	
	// Enable automatic certificate renewal
	EnableAutoRenewal bool `yaml:"enable_auto_renewal"`
	
	// Server certificate configuration
	Server *ServerCertificateConfig `yaml:"server"`
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
	Level         string `yaml:"level"`                       // Minimum log level (DEBUG, INFO, WARN, ERROR, FATAL)
	ServiceName   string `yaml:"service_name"`               // Service identifier
	Component     string `yaml:"component"`                  // Component identifier
	
	// Performance settings
	BatchSize      int    `yaml:"batch_size"`                // Batch size for bulk writes
	FlushInterval  string `yaml:"flush_interval"`            // Auto-flush interval (duration string)
	AsyncWrites    bool   `yaml:"async_writes"`              // Enable asynchronous writes
	BufferSize     int    `yaml:"buffer_size"`               // Internal buffer size
	
	// Retention settings (provider-dependent)
	RetentionDays  int  `yaml:"retention_days"`             // Log retention period
	CompressLogs   bool `yaml:"compress_logs"`              // Enable log compression
	
	// Multi-tenant settings
	TenantIsolation bool `yaml:"tenant_isolation"`          // Enable tenant isolation in logs
	
	// Enhanced correlation tracking
	EnableCorrelation bool `yaml:"enable_correlation"`      // Enable automatic correlation IDs
	EnableTracing     bool `yaml:"enable_tracing"`          // Enable OpenTelemetry integration
	
	// Event subscriber configuration (optional)
	Subscribers []SubscriberConfig `yaml:"subscribers"`     // Event subscribers for real-time forwarding
}

// SubscriberConfig holds configuration for event subscribers
type SubscriberConfig struct {
	Type    string                 `yaml:"type"`     // Subscriber type (e.g., "syslog", "webhook")
	Config  map[string]interface{} `yaml:"config"`   // Subscriber-specific configuration
	Enabled bool                  `yaml:"enabled"`  // Enable/disable subscriber
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
	ExpectedSize      int                    `yaml:"expected_size"`
	MinQuorum         int                    `yaml:"min_quorum"`
	ElectionTimeout   string                 `yaml:"election_timeout"`   // Duration string
	HeartbeatInterval string                 `yaml:"heartbeat_interval"` // Duration string
	Discovery         *HADiscoveryConfig     `yaml:"discovery"`
	SessionSync       *HASessionSyncConfig   `yaml:"session_sync"`
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
	Interval         string `yaml:"interval"`          // Duration string
	Timeout          string `yaml:"timeout"`           // Duration string
	FailureThreshold int    `yaml:"failure_threshold"`
	SuccessThreshold int    `yaml:"success_threshold"`
	EnableInternal   bool   `yaml:"enable_internal"`
	EnableExternal   bool   `yaml:"enable_external"`
}

// HAFailoverConfig contains failover configuration
type HAFailoverConfig struct {
	Enabled             bool   `yaml:"enabled"`
	Timeout             string `yaml:"timeout"`              // Duration string
	MaxDuration         string `yaml:"max_duration"`         // Duration string
	GracePeriod         string `yaml:"grace_period"`         // Duration string
	MaxSessionMigration int    `yaml:"max_session_migration"`
}

// HALoadBalancingConfig contains load balancing configuration
type HALoadBalancingConfig struct {
	Strategy        string                      `yaml:"strategy"`
	HealthBased     *HAHealthBasedConfig        `yaml:"health_based"`
	ConnectionBased *HAConnectionBasedConfig    `yaml:"connection_based"`
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
	DetectionInterval  string `yaml:"detection_interval"`  // Duration string
	QuorumInterval     string `yaml:"quorum_interval"`     // Duration string
	ResolutionStrategy string `yaml:"resolution_strategy"`
}

// MQTTConfig contains MQTT broker configuration
type MQTTConfig struct {
	// Enable MQTT broker
	Enabled bool `yaml:"enabled"`

	// MQTT listen address (e.g., "0.0.0.0:1883")
	ListenAddr string `yaml:"listen_addr"`

	// Enable TLS for MQTT
	EnableTLS bool `yaml:"enable_tls"`

	// Use certificate manager for MQTT certificates
	UseCertManager bool `yaml:"use_cert_manager"`

	// TLS certificate path (if not using cert manager)
	TLSCertPath string `yaml:"tls_cert_path,omitempty"`

	// TLS key path (if not using cert manager)
	TLSKeyPath string `yaml:"tls_key_path,omitempty"`

	// CA certificate path for client verification
	TLSCAPath string `yaml:"tls_ca_path,omitempty"`

	// Require client certificates (mTLS)
	RequireClientCert bool `yaml:"require_client_cert"`

	// Maximum concurrent clients
	MaxClients int `yaml:"max_clients"`

	// Maximum message size in bytes
	MaxMessageSize int64 `yaml:"max_message_size"`

	// Session expiry interval in seconds
	SessionExpiryInterval int64 `yaml:"session_expiry_interval"`

	// Keepalive multiplier for heartbeat detection
	KeepaliveMultiplier float64 `yaml:"keepalive_multiplier"`
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
			CAPath:                "certs/ca",
			AutoGenerate:          true,
			RenewalThresholdDays:  30,
			ServerCertValidityDays: 365,
			ClientCertValidityDays: 365,
			EnableAutoRenewal:     true,
			Server: &ServerCertificateConfig{
				CommonName:   "cfgms-controller",
				DNSNames:     []string{"localhost", "cfgms-controller"},
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
			Provider:          "file", // Default to file-based time-series logging
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
		MQTT: &MQTTConfig{
			Enabled:               true, // Core communication channel - enabled by default
			ListenAddr:            "0.0.0.0:1883",
			EnableTLS:             true,
			UseCertManager:        true,  // Use controller's certificate manager
			RequireClientCert:     true,  // mTLS for security
			MaxClients:            10000,
			MaxMessageSize:        1024 * 1024, // 1MB
			SessionExpiryInterval: 3600,        // 1 hour
			KeepaliveMultiplier:   1.5,         // Disconnect if no activity for keepalive * 1.5
		},
		QUIC: &QUICConfig{
			Enabled:        true,  // Core data plane - enabled by default (Story #198)
			ListenAddr:     "0.0.0.0:4433",
			UseCertManager: true,  // Use controller's certificate manager
			SessionTimeout: 300,   // 5 minutes
		},
	}
}

// Load loads the configuration from file and environment variables
func Load() (*Config, error) {
	cfg := DefaultConfig()
	
	// Try to load from config file if it exists
	if _, err := os.Stat("config.yaml"); err == nil {
		data, err := os.ReadFile("config.yaml")
		if err != nil {
			return nil, err
		}
		
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
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
	
	if autoGen := os.Getenv("CFGMS_CERT_AUTO_GENERATE"); autoGen != "" {
		if val, err := strconv.ParseBool(autoGen); err == nil {
			cfg.Certificate.AutoGenerate = val
		}
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
	
	if enableAutoRenewal := os.Getenv("CFGMS_CERT_ENABLE_AUTO_RENEWAL"); enableAutoRenewal != "" {
		if val, err := strconv.ParseBool(enableAutoRenewal); err == nil {
			cfg.Certificate.EnableAutoRenewal = val
		}
	}
	
	if serverCommonName := os.Getenv("CFGMS_CERT_SERVER_COMMON_NAME"); serverCommonName != "" {
		cfg.Certificate.Server.CommonName = serverCommonName
	}
	
	if serverOrg := os.Getenv("CFGMS_CERT_SERVER_ORGANIZATION"); serverOrg != "" {
		cfg.Certificate.Server.Organization = serverOrg
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

	// MQTT configuration environment variables
	if mqttEnabled := os.Getenv("CFGMS_MQTT_ENABLED"); mqttEnabled != "" {
		if val, err := strconv.ParseBool(mqttEnabled); err == nil {
			cfg.MQTT.Enabled = val
		}
	}

	if mqttListenAddr := os.Getenv("CFGMS_MQTT_LISTEN_ADDR"); mqttListenAddr != "" {
		cfg.MQTT.ListenAddr = mqttListenAddr
	}

	if mqttEnableTLS := os.Getenv("CFGMS_MQTT_ENABLE_TLS"); mqttEnableTLS != "" {
		if val, err := strconv.ParseBool(mqttEnableTLS); err == nil {
			cfg.MQTT.EnableTLS = val
		}
	}

	if mqttUseCertManager := os.Getenv("CFGMS_MQTT_USE_CERT_MANAGER"); mqttUseCertManager != "" {
		if val, err := strconv.ParseBool(mqttUseCertManager); err == nil {
			cfg.MQTT.UseCertManager = val
		}
	}

	if mqttRequireClientCert := os.Getenv("CFGMS_MQTT_REQUIRE_CLIENT_CERT"); mqttRequireClientCert != "" {
		if val, err := strconv.ParseBool(mqttRequireClientCert); err == nil {
			cfg.MQTT.RequireClientCert = val
		}
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

	// HTTP API configuration environment variables
	if httpListenAddr := os.Getenv("CFGMS_HTTP_LISTEN_ADDR"); httpListenAddr != "" {
		cfg.ListenAddr = httpListenAddr
	}

	return cfg, nil
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