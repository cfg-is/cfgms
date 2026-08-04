// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	loggingPkg "github.com/cfgis/cfgms/pkg/logging"
)

// envVarPattern matches ${VAR} patterns without defaults
// It excludes ${VAR:-default} and ${VAR:=default} patterns
var envVarPattern = regexp.MustCompile(`\$\{([^}:]+)\}`)

// ringNamePattern validates deployment ring names:
// lowercase letter followed by up to 31 lowercase letters, digits, or hyphens.
var ringNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// DefaultRingNames is the ordered default deployment ring set applied when
// deployment_rings is absent from controller config.
var DefaultRingNames = []string{"pre-release", "early", "default", "stable"}

// DefaultFallbackRing is the ring used when a steward has no or invalid
// deployment_ring DNA attribute and no explicit fallback_ring is configured.
const DefaultFallbackRing = "default"

// RingSpec defines a single deployment ring within the ordered ring set.
type RingSpec struct {
	// Name is the ring identifier matched against the deployment_ring DNA attribute.
	// Must match ^[a-z][a-z0-9-]{0,31}$.
	Name string `yaml:"name"`

	// DesiredVersion is the target steward binary version for this ring (e.g. "v0.5.21").
	// When non-empty, overrides any tenant-path desired_version for stewards in this ring.
	// Empty means no ring-level version override applies.
	DesiredVersion string `yaml:"desired_version,omitempty"`

	// Soak is the minimum time a version must run in this ring before Story S3 advances it.
	// Declared here to avoid a second structural migration when S3 adds the rollout workflow.
	Soak Duration `yaml:"soak,omitempty"`

	// HaltThreshold is the error-rate (0.0–1.0) above which S3 halts promotion.
	// Declared here to avoid a second structural migration when S3 adds the rollout workflow.
	HaltThreshold float64 `yaml:"halt_threshold,omitempty"`

	// ConcurrencyLimit caps simultaneous steward upgrades in this ring.
	// Declared here to avoid a second structural migration when S3 adds the rollout workflow.
	ConcurrencyLimit int `yaml:"concurrency_limit,omitempty"`
}

// DeploymentRingConfig holds the ordered set of deployment rings and fallback policy.
// It is a controller-global governance object; individual tenant configs carry only
// desired_version (from the inheritance resolver or ring resolution).
type DeploymentRingConfig struct {
	// Rings is the ordered list of ring specs. Earlier rings receive updates first.
	Rings []RingSpec `yaml:"rings,omitempty"`

	// FallbackRing is the ring name used when a steward has no or invalid
	// deployment_ring DNA attribute. Must be a declared ring name.
	// Defaults to "default" when empty.
	FallbackRing string `yaml:"fallback_ring,omitempty"`
}

// DefaultDeploymentRingConfig returns the default four-ring configuration with
// empty desired_version fields (no version override until the operator sets one).
func DefaultDeploymentRingConfig() DeploymentRingConfig {
	rings := make([]RingSpec, len(DefaultRingNames))
	for i, name := range DefaultRingNames {
		rings[i] = RingSpec{Name: name}
	}
	return DeploymentRingConfig{
		Rings:        rings,
		FallbackRing: DefaultFallbackRing,
	}
}

// ValidateDeploymentRingConfig validates a DeploymentRingConfig for controller startup.
// Returns nil when rings is the zero value (absent in config — defaults apply).
func ValidateDeploymentRingConfig(rc DeploymentRingConfig) error {
	seen := make(map[string]struct{}, len(rc.Rings))
	for i, ring := range rc.Rings {
		if ring.Name == "" {
			return fmt.Errorf("deployment_rings.rings[%d]: name must not be empty", i)
		}
		if !ringNamePattern.MatchString(ring.Name) {
			return fmt.Errorf("deployment_rings.rings[%d]: name %q must match ^[a-z][a-z0-9-]{0,31}$", i, ring.Name)
		}
		if _, dup := seen[ring.Name]; dup {
			return fmt.Errorf("deployment_rings.rings[%d]: duplicate ring name %q", i, ring.Name)
		}
		seen[ring.Name] = struct{}{}
	}
	if rc.FallbackRing != "" {
		if _, ok := seen[rc.FallbackRing]; !ok {
			return fmt.Errorf("deployment_rings.fallback_ring: %q is not a declared ring name", rc.FallbackRing)
		}
	}
	return nil
}

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

// BlobStorageConfig holds configuration for the blob storage backend (Issue #1702).
type BlobStorageConfig struct {
	// Root is the filesystem directory where installer artifacts are stored.
	// Defaults to <DataDir>/installers when not explicitly set.
	Root string `yaml:"root"`
}

const (
	SecurityProfileDevelopment = "development"
	SecurityProfileTest        = "test"
	SecurityProfilePublicBeta  = "public-beta"
)

// ExecutionSecurityConfig controls security requirements for controller-issued
// execution commands.
type ExecutionSecurityConfig struct {
	// RequireSignedAdhoc requires both the operator's inline-content signature
	// and the controller's signed command envelope for every ad-hoc execution.
	RequireSignedAdhoc bool `yaml:"require_signed_adhoc"`
}

// Config holds the controller configuration
type Config struct {
	// SecurityProfile selects deployment security invariants. Public-beta is a
	// fail-closed production profile; development and test are explicit,
	// non-public profiles.
	SecurityProfile string `yaml:"security_profile"`

	// Execution contains controller-issued execution security policy.
	Execution ExecutionSecurityConfig `yaml:"execution"`

	// Controller listen address
	ListenAddr string `yaml:"listen_addr"`

	// MetricsListenAddr is the dedicated HTTPS listener for product metrics.
	// It is intentionally required rather than defaulted: operators must choose
	// an explicit loopback or private IP address and a fixed port.
	MetricsListenAddr string `yaml:"metrics_listen_addr"`

	// InternalListenAddr is the private HTTPS listener used only for
	// controller-to-controller Raft traffic in cluster mode. It must bind a
	// loopback or private IP address and must never be Internet-published.
	InternalListenAddr string `yaml:"internal_listen_addr,omitempty"`

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

	// Transport is the unified, protocol-agnostic transport configuration.
	Transport *TransportConfig `yaml:"transport"`

	// Registration holds registration approval workflow settings.
	// When nil or when Workflow is empty and no custom workflow exists in the store,
	// the controller seeds the built-in "auto-approve" workflow (Issue #1527).
	Registration *RegistrationConfig `yaml:"registration,omitempty"`

	// AdminBundlePath is the path where --init writes the admin credential bundle.
	// Default: /etc/cfgms/admin.bundle.yaml (Linux) or %ProgramData%\cfgms\admin.bundle.yaml (Windows).
	// Mode 0600, daemon-user-owned. Contains the admin mTLS cert, key, CA, and controller URL.
	AdminBundlePath string `yaml:"admin_bundle_path,omitempty"`

	// BlobStorage configures the blob storage backend for installer artifacts (Issue #1702).
	BlobStorage BlobStorageConfig `yaml:"blob_storage,omitempty"`

	// HA configures the deployment mode for storage selection.
	// Set ha.mode to "cluster" to activate cluster-mode storage (Postgres + S3).
	// Override ha.mode via CFGMS_HA_MODE environment variable.
	// Valid modes: "single" (default), "blue-green", "cluster".
	HA *HAConfig `yaml:"ha,omitempty"`

	// DeploymentRings configures the ordered deployment ring set for fleet version management.
	// When absent, the default four-ring set (pre-release, early, default, stable) is applied
	// with "default" as the fallback ring.
	DeploymentRings *DeploymentRingConfig `yaml:"deployment_rings,omitempty"`
}

// EffectiveRings returns the deployment ring configuration with defaults applied.
// When DeploymentRings is nil or has no rings, the default four-ring set is returned.
func (c *Config) EffectiveRings() DeploymentRingConfig {
	if c.DeploymentRings != nil && len(c.DeploymentRings.Rings) > 0 {
		rc := *c.DeploymentRings
		if rc.FallbackRing == "" {
			rc.FallbackRing = DefaultFallbackRing
		}
		return rc
	}
	return DefaultDeploymentRingConfig()
}

// ValidateDeploymentRings validates the ring configuration at controller startup.
// Returns nil when DeploymentRings is absent (defaults apply and are always valid).
func (c *Config) ValidateDeploymentRings() error {
	if c.DeploymentRings == nil || len(c.DeploymentRings.Rings) == 0 {
		return nil
	}
	return ValidateDeploymentRingConfig(*c.DeploymentRings)
}

// RegistrationConfig holds registration approval workflow settings.
type RegistrationConfig struct {
	// Workflow selects the built-in registration approval workflow.
	// Valid values:
	//   "ip-trust" (default) — auto-approve if the source IP is trusted for the tenant;
	//     quarantine otherwise. The first steward from a new tenant always quarantines
	//     until its IP is established via the 30-minute liveness window (Issue #1694).
	//   "manual-review"      — stewards quarantined pending operator approval via
	//     `cfg registration approve`.
	//   "auto-approve"       — DEPRECATED. Approves all registrations immediately.
	//     Use only in dev/test environments. A startup warning is logged.
	// If empty, defaults to "ip-trust".
	Workflow string `yaml:"workflow"`

	// TrustedProxies is a list of CIDR ranges identifying reverse proxies that are
	// trusted to append the upstream address to X-Forwarded-For. The controller
	// walks the chain right-to-left and uses the first untrusted hop. When empty
	// (the default), X-Forwarded-For is never trusted and the TCP peer address is
	// always used for source controls. Parse once at startup, not per request.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`

	// ApprovalMode selects the registration approval hook implementation.
	// Valid values:
	//   "" (default) — use the workflow engine hook (WorkflowApprovalHook).
	//   "manual-review" — use ManualReviewApprovalHook which stores requests in
	//     PendingRegistrationStore and holds the steward in quarantine until an
	//     operator acts via `cfg registration approve/deny` (#1522-B).
	ApprovalMode string `yaml:"approval_mode,omitempty"`

	// IPTrustThreshold is the minimum continuous liveness duration before an IP
	// is promoted to trusted status (Issue #1694). Default: 30 minutes.
	// Sandbox-detonation attempts (3–15 min lifetime) cannot sustain this window.
	IPTrustThreshold Duration `yaml:"ip_trust_threshold,omitempty"`

	// IPTrustDarkWindow is the consecutive inactivity period after which a
	// non-pre-seeded trusted IP range is auto-revoked (Issue #1697).
	// Default: 30 days. Pre-seeded entries are exempt and can only be revoked
	// explicitly via `cfg registration ip-trust revoke`.
	IPTrustDarkWindow Duration `yaml:"ip_trust_dark_window,omitempty"`

	// PendingReviewTimeout is the maximum time a pending registration may wait
	// for operator action before it is automatically expired (Issue #1697).
	// Default: 5 days.
	PendingReviewTimeout Duration `yaml:"pending_review_timeout,omitempty"`
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

	// Architecture is parsed from YAML to detect legacy "unified" values and reject them.
	// Separated architecture is mandatory; do not set this field in new configurations.
	// Setting it to "unified" causes ValidateCertificateArchitecture to return an error.
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

	// ClusterCA configures CA material sourcing from OpenBao in cluster-mode
	// deployments. When set and ha.mode is "cluster", the controller loads
	// the CA from the vault rather than generating or loading it from local disk.
	ClusterCA *ClusterCAConfig `yaml:"cluster_ca,omitempty"`
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

// ClusterCAConfig configures CA material sourcing from a shared OpenBao secret store
// in cluster-mode deployments. The CA private key never resides on the node disk;
// it is retrieved from the vault at boot and held in-process only.
//
// The vault token must be supplied via the OPENBAO_TOKEN or BAO_TOKEN environment
// variable — never in the configuration file.
type ClusterCAConfig struct {
	// VaultAddress is the OpenBao server URL. Must be HTTPS in production.
	// Example: "https://vault.example.com:8200"
	// Override via CFGMS_CLUSTER_CA_VAULT_ADDRESS environment variable.
	VaultAddress string `yaml:"vault_address"`

	// VaultKeyPath is the secret path in the format "tenantID/key-name" where
	// the cluster CA cert and key PEM are stored in the KV v2 engine.
	// Example: "root/cluster-ca"
	// Override via CFGMS_CLUSTER_CA_VAULT_KEY_PATH environment variable.
	VaultKeyPath string `yaml:"vault_key_path"`

	// VaultTLSCert is the path to a PEM CA certificate for vault TLS verification.
	// Optional; required when the vault uses a private CA.
	VaultTLSCert string `yaml:"vault_tls_cert,omitempty"`

	// VaultMountPath is the KV v2 mount path (default: "secret").
	VaultMountPath string `yaml:"vault_mount_path,omitempty"`
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

// HAConfig selects the controller deployment mode for storage backend selection.
// Only the Mode field is used at init/startup; full cluster coordination lives in pkg/ha.
// This thin config type avoids a pkg/ha import cycle through pkg/testing/storage.
type HAConfig struct {
	// Mode is the deployment mode: "single" (default), "blue-green", or "cluster".
	Mode string `yaml:"mode"`
}

// IsClusterMode returns true when ha.mode is "cluster".
func (h *HAConfig) IsClusterMode() bool {
	return h != nil && h.Mode == "cluster"
}

// ClusterStorageConfig holds Postgres + S3 connection details for cluster-mode deployments.
// Set under storage.cluster.* in controller.cfg when ha.mode is cluster.
type ClusterStorageConfig struct {
	// PostgresDSN is the libpq connection string for the shared Postgres backend.
	// All controller nodes in the cluster must point at the same Postgres instance.
	// Example: "host=pg.example.com port=5432 dbname=cfgms user=cfgms password=... sslmode=require"
	// Override via CFGMS_STORAGE_CLUSTER_POSTGRES_DSN environment variable.
	PostgresDSN string `yaml:"postgres_dsn"`

	// S3 holds S3-compatible blob store configuration keys used for installer artifact storage.
	// Required keys: "bucket". Optional: "region", "endpoint_url", "access_key_id", "secret_access_key".
	// When empty, the S3 bucket name is read from CFGMS_S3_INSTALLER_BUCKET at startup.
	S3 map[string]interface{} `yaml:"s3,omitempty"`
}

// StorageConfig contains global storage provider configuration
type StorageConfig struct {
	// Provider specifies which storage provider to use (database, flatfile, sqlite).
	// The "git" provider is no longer supported; run "cfg storage migrate --from git --to flatfile"
	// to migrate an existing git-backed deployment.
	Provider string `yaml:"provider"`

	// Configuration options passed to the storage provider
	// The structure depends on the specific provider being used
	Config map[string]interface{} `yaml:"config"`

	// FlatfileRoot is the directory root for the flat-file storage provider.
	// When set, the OSS composite storage manager is used (flatfile + SQLite) instead
	// of the single-provider path. Requires SQLitePath to also be set.
	// Example: "/var/lib/cfgms/config"
	FlatfileRoot string `yaml:"flatfile_root,omitempty"`

	// SQLitePath is the file path for the SQLite database used by the OSS composite
	// storage manager. Caller-controlled DSN — use a file path such as
	// "/var/lib/cfgms/cfgms.db". Only used when FlatfileRoot is set.
	SQLitePath string `yaml:"sqlite_path,omitempty"`

	// Cluster holds Postgres + S3 connection details for cluster-mode deployments.
	// Required when ha.mode is cluster. Ignored in single-node deployments.
	Cluster *ClusterStorageConfig `yaml:"cluster,omitempty"`
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
// A single listen address serves both control plane and data plane over gRPC-over-QUIC,
// and can accommodate future transport implementations without config changes.
type TransportConfig struct {
	// ListenAddr is the address for the unified transport server (e.g., "0.0.0.0:4433")
	ListenAddr string `yaml:"listen_addr"`

	// ExternalAddress is the hostname or IP address advertised to stewards when
	// ListenAddr binds 0.0.0.0. Required when ListenAddr starts with "0.0.0.0" and
	// CFGMS_EXTERNAL_HOSTNAME env var is not set. Example: "controller.example.com"
	ExternalAddress string `yaml:"external_address,omitempty"`

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
	cfg := &Config{
		SecurityProfile:   SecurityProfileDevelopment,
		ListenAddr:        "127.0.0.1:8080",
		MetricsListenAddr: "",                       // Required explicitly; startup fails closed when absent.
		ExternalURL:       "https://localhost:8080", // Default external URL
		CertPath:          "certs/",
		DataDir:           "data/",
		LogLevel:          "info",
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
			Provider:     "flatfile",
			FlatfileRoot: "data/cfgms-config",
			SQLitePath:   "data/cfgms.db",
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
		Transport: &TransportConfig{
			ListenAddr:      "0.0.0.0:4433",
			UseCertManager:  true,
			MaxConnections:  50000,
			KeepalivePeriod: Duration(30 * time.Second),
			IdleTimeout:     Duration(5 * time.Minute),
		},
	}
	return cfg
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
		// #nosec G703 -- this process-start configuration path is controlled by
		// the controller administrator/service definition, not a remote request.
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
		// #nosec G304 -- foundPath is selected by findConfigFile from the
		// operator's explicit configuration path or fixed CFGMS search paths.
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

	}

	// Override with environment variables if set
	if securityProfile := strings.TrimSpace(os.Getenv("CFGMS_SECURITY_PROFILE")); securityProfile != "" {
		// An environment variable may tighten a development/test configuration
		// to public-beta, but it may never downgrade a reviewed public-beta file.
		if cfg.SecurityProfile == SecurityProfilePublicBeta && securityProfile != SecurityProfilePublicBeta {
			return nil, fmt.Errorf("CFGMS_SECURITY_PROFILE cannot downgrade configured public-beta security profile to %q", securityProfile)
		}
		cfg.SecurityProfile = securityProfile
	}

	if requireSignedAdhoc := strings.TrimSpace(os.Getenv("CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC")); requireSignedAdhoc != "" {
		val, parseErr := strconv.ParseBool(requireSignedAdhoc)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC value %q: %w", requireSignedAdhoc, parseErr)
		}
		cfg.Execution.RequireSignedAdhoc = val
	}

	if addr := os.Getenv("CFGMS_LISTEN_ADDR"); addr != "" {
		cfg.ListenAddr = addr
	}

	if metricsListenAddr := os.Getenv("CFGMS_METRICS_LISTEN_ADDR"); metricsListenAddr != "" {
		cfg.MetricsListenAddr = metricsListenAddr
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

	// CFGMS_CERT_ARCHITECTURE: parsed for legacy detection only.
	// Setting to "unified" triggers a startup error at ValidateCertificateArchitecture.
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

	// Transport configuration environment variables.
	//
	// If the config file omitted the `transport:` section entirely, cfg.Transport
	// is nil at this point. Previously each env var was guarded with
	// `&& cfg.Transport != nil`, which silently dropped the env-var override
	// when the section was missing. That violated the documented precedence
	// (env > cfg > default) and was caught by the Issue #1919 review.
	// Materialise the struct on first use so env vars apply consistently.
	ensureTransport := func() {
		if cfg.Transport == nil {
			cfg.Transport = &TransportConfig{}
		}
	}

	if transportListenAddr := os.Getenv("CFGMS_TRANSPORT_LISTEN_ADDR"); transportListenAddr != "" {
		ensureTransport()
		cfg.Transport.ListenAddr = transportListenAddr
	}

	if transportUseCertManager := os.Getenv("CFGMS_TRANSPORT_USE_CERT_MANAGER"); transportUseCertManager != "" {
		if val, err := strconv.ParseBool(transportUseCertManager); err == nil {
			ensureTransport()
			cfg.Transport.UseCertManager = val
		}
	}

	if transportMaxConns := os.Getenv("CFGMS_TRANSPORT_MAX_CONNECTIONS"); transportMaxConns != "" {
		if val, err := strconv.Atoi(transportMaxConns); err == nil {
			ensureTransport()
			cfg.Transport.MaxConnections = val
		}
	}

	if transportKeepalive := os.Getenv("CFGMS_TRANSPORT_KEEPALIVE_PERIOD"); transportKeepalive != "" {
		if dur, err := time.ParseDuration(transportKeepalive); err == nil {
			ensureTransport()
			cfg.Transport.KeepalivePeriod = Duration(dur)
		}
	}

	if transportIdleTimeout := os.Getenv("CFGMS_TRANSPORT_IDLE_TIMEOUT"); transportIdleTimeout != "" {
		if dur, err := time.ParseDuration(transportIdleTimeout); err == nil {
			ensureTransport()
			cfg.Transport.IdleTimeout = Duration(dur)
		}
	}

	// HTTP API configuration environment variables
	if httpListenAddr := os.Getenv("CFGMS_HTTP_LISTEN_ADDR"); httpListenAddr != "" {
		cfg.ListenAddr = httpListenAddr
	}

	// Registration configuration environment variables (Issue #1695).
	// CFGMS_REGISTRATION_WORKFLOW selects the approval workflow ("ip-trust",
	// "manual-review", "auto-approve"). Test/dev environments use this to opt
	// into "auto-approve" without mounting a config file.
	if regWorkflow := os.Getenv("CFGMS_REGISTRATION_WORKFLOW"); regWorkflow != "" {
		if cfg.Registration == nil {
			cfg.Registration = &RegistrationConfig{}
		}
		cfg.Registration.Workflow = regWorkflow
	}

	// HA mode environment variable (Issue #2119).
	// CFGMS_HA_MODE overrides ha.mode from the config file.
	// Valid values: "single", "blue-green", "cluster".
	if haMode := os.Getenv("CFGMS_HA_MODE"); haMode != "" {
		if cfg.HA == nil {
			cfg.HA = &HAConfig{}
		}
		cfg.HA.Mode = strings.ToLower(haMode)
	}

	// Cluster storage DSN environment variable (Issue #2119).
	// CFGMS_STORAGE_CLUSTER_POSTGRES_DSN overrides storage.cluster.postgres_dsn.
	if pgDSN := os.Getenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN"); pgDSN != "" {
		if cfg.Storage.Cluster == nil {
			cfg.Storage.Cluster = &ClusterStorageConfig{}
		}
		cfg.Storage.Cluster.PostgresDSN = pgDSN
	}

	// Cluster CA vault configuration environment variables (Issue #2018).
	// Vault token is intentionally NOT configurable here — it must come from
	// OPENBAO_TOKEN or BAO_TOKEN environment variables, never from a config file.
	if vaultAddr := os.Getenv("CFGMS_CLUSTER_CA_VAULT_ADDRESS"); vaultAddr != "" {
		if cfg.Certificate.ClusterCA == nil {
			cfg.Certificate.ClusterCA = &ClusterCAConfig{}
		}
		cfg.Certificate.ClusterCA.VaultAddress = vaultAddr
	}
	if vaultKeyPath := os.Getenv("CFGMS_CLUSTER_CA_VAULT_KEY_PATH"); vaultKeyPath != "" {
		if cfg.Certificate.ClusterCA == nil {
			cfg.Certificate.ClusterCA = &ClusterCAConfig{}
		}
		cfg.Certificate.ClusterCA.VaultKeyPath = vaultKeyPath
	}

	if err := cfg.ValidateExecutionSecurity(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ValidateExecutionSecurity enforces the public-beta connected-execution
// contract after all file and environment paths have been resolved.
func (c *Config) ValidateExecutionSecurity() error {
	switch c.SecurityProfile {
	case "", SecurityProfileDevelopment, SecurityProfileTest:
		return nil
	case SecurityProfilePublicBeta:
		if !c.Execution.RequireSignedAdhoc {
			return fmt.Errorf("public-beta security profile requires execution.require_signed_adhoc: true")
		}
		if c.Transport == nil {
			return fmt.Errorf("public-beta security profile requires connected transport configuration")
		}
		if c.Certificate == nil || !c.Certificate.EnableCertManagement {
			return fmt.Errorf("public-beta security profile requires certificate management and signing roots")
		}
		if !c.Transport.UseCertManager {
			return fmt.Errorf("public-beta security profile requires transport.use_cert_manager: true")
		}
		return nil
	default:
		return fmt.Errorf("invalid security_profile %q: must be development, test, or public-beta", c.SecurityProfile)
	}
}

// ValidatePrivateListenerAddress requires a fixed numeric loopback or private
// address. Hostnames are rejected so DNS changes cannot turn a listener that
// passed startup validation into an Internet-facing listener later.
func ValidatePrivateListenerAddress(address string) error {
	if address == "" {
		return fmt.Errorf("address is required")
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("must be a host:port address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host must be an explicit loopback or private IP address")
	}
	if !ip.IsLoopback() && !ip.IsPrivate() {
		return fmt.Errorf("host %q is not a loopback or private IP address", host)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("a fixed numeric port from 1 to 65535 is required")
	}
	return nil
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

// ValidateCertificateArchitecture returns an error if the config explicitly requests
// the removed unified-mode architecture. Separated architecture is mandatory.
// See docs/security/certificate-architecture.md.
func (cc *CertificateConfig) ValidateCertificateArchitecture() error {
	if cc != nil && cc.Architecture == "unified" {
		return fmt.Errorf(
			"certificate architecture \"unified\" is no longer supported; " +
				"separated architecture is mandatory; " +
				"remove 'architecture: unified' from your configuration; " +
				"see docs/security/certificate-architecture.md#migrating-from-unified-mode",
		)
	}
	return nil
}

// GetPublicAPISource returns the public API certificate source, defaulting to "internal"
func (cc *CertificateConfig) GetPublicAPISource() string {
	if cc != nil && cc.PublicAPI != nil && cc.PublicAPI.Source != "" {
		return cc.PublicAPI.Source
	}
	return "internal"
}

// GetIPTrustThreshold returns the IP-trust establishment threshold, defaulting
// to 30 minutes when not configured (Issue #1694).
func (rc *RegistrationConfig) GetIPTrustThreshold() time.Duration {
	if rc == nil || rc.IPTrustThreshold == 0 {
		return 30 * time.Minute
	}
	return rc.IPTrustThreshold.AsDuration()
}

// GetIPTrustDarkWindow returns the inactivity period after which a non-pre-seeded
// trusted IP range is auto-revoked, defaulting to 30 days (Issue #1697).
func (rc *RegistrationConfig) GetIPTrustDarkWindow() time.Duration {
	if rc == nil || rc.IPTrustDarkWindow == 0 {
		return 30 * 24 * time.Hour
	}
	return rc.IPTrustDarkWindow.AsDuration()
}

// GetPendingReviewTimeout returns the maximum time a pending registration may
// wait for operator action before it is auto-expired, defaulting to 5 days (Issue #1697).
func (rc *RegistrationConfig) GetPendingReviewTimeout() time.Duration {
	if rc == nil || rc.PendingReviewTimeout == 0 {
		return 5 * 24 * time.Hour
	}
	return rc.PendingReviewTimeout.AsDuration()
}
