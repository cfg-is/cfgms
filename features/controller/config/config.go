package config

import (
	"os"
	
	"gopkg.in/yaml.v3"
)

// Config holds the controller configuration
type Config struct {
	// Controller listen address
	ListenAddr string `yaml:"listen_addr"`
	
	// Path to TLS certificates
	CertPath string `yaml:"cert_path"`
	
	// Data directory
	DataDir string `yaml:"data_dir"`
	
	// Log level (debug, info, warn, error)
	LogLevel string `yaml:"log_level"`
}

// DefaultConfig returns a Config with reasonable defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr: "127.0.0.1:8080",
		CertPath:   "certs/",
		DataDir:    "data/",
		LogLevel:   "info",
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
	
	return cfg, nil
} 