package config

import (
	"os"
	"strconv"
	
	"gopkg.in/yaml.v3"
)

// Config holds the controller configuration
type Config struct {
	// Controller listen address
	ListenAddr string `yaml:"listen_addr"`
	
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
	// Provider specifies which storage provider to use (memory, file, database, git)
	Provider string `yaml:"provider"`
	
	// Configuration options passed to the storage provider
	// The structure depends on the specific provider being used
	Config map[string]interface{} `yaml:"config"`
}

// DefaultConfig returns a Config with reasonable defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr: "127.0.0.1:8080",
		CertPath:   "certs/",
		DataDir:    "data/",
		LogLevel:   "info",
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
	}
	
	return cfg, nil
} 