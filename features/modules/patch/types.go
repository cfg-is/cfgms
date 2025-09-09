package patch

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	// Valid patch types
	validPatchTypes = map[string]bool{
		"security": true,
		"all":      true,
		"kernel":   true,
		"critical": true,
	}

	// Maintenance window format validation (e.g., "sunday_3am", "daily_2am", "monthly_first_sunday_3am")
	maintenanceWindowRegex = regexp.MustCompile(`^(daily|weekly|monthly)_.*|^(monday|tuesday|wednesday|thursday|friday|saturday|sunday)_.*|^[a-zA-Z0-9_]+$`)
)

// PatchManager defines the interface for OS patch management operations
type PatchManager interface {
	// ListAvailablePatches returns available patches for the specified type
	ListAvailablePatches(ctx context.Context, patchType string) ([]PatchInfo, error)
	// ListInstalledPatches returns currently installed patches
	ListInstalledPatches(ctx context.Context) ([]PatchInfo, error)
	// InstallPatches installs patches based on the configuration
	InstallPatches(ctx context.Context, config *Config) error
	// CheckRebootRequired returns true if a reboot is required after patching
	CheckRebootRequired(ctx context.Context) (bool, error)
	// GetLastPatchDate returns the date of the last successful patch operation
	GetLastPatchDate(ctx context.Context) (time.Time, error)
	// Name returns the name of the patch manager
	Name() string
	// IsValidPatchType checks if the given patch type is valid for this platform
	IsValidPatchType(patchType string) bool
}

// PatchInfo represents information about a single patch
type PatchInfo struct {
	ID             string    `json:"id" yaml:"id"`
	Title          string    `json:"title" yaml:"title"`
	Description    string    `json:"description" yaml:"description"`
	Severity       string    `json:"severity" yaml:"severity"` // "critical", "important", "moderate", "low"
	Category       string    `json:"category" yaml:"category"` // "security", "bugfix", "enhancement"
	Size           int64     `json:"size" yaml:"size"`         // Size in bytes
	ReleaseDate    time.Time `json:"release_date" yaml:"release_date"`
	Installed      bool      `json:"installed" yaml:"installed"`
	RebootRequired bool      `json:"reboot_required" yaml:"reboot_required"`
}

// Config represents the patch management configuration
type Config struct {
	// Core patch configuration
	PatchType      string   `yaml:"patch_type"`      // "security", "all", "kernel", "critical"
	AutoReboot     bool     `yaml:"auto_reboot"`     // Automatically reboot if required
	IncludePatches []string `yaml:"include_patches"` // Specific patches to include
	ExcludePatches []string `yaml:"exclude_patches"` // Specific patches to exclude
	MaxDowntime    string   `yaml:"max_downtime"`    // Maximum acceptable downtime (e.g., "30m", "1h")

	// Scheduling and maintenance windows
	Maintenance struct {
		Window   string        `yaml:"window"`   // Optional: Reference to a named maintenance window
		Schedule string        `yaml:"schedule"` // Optional: Inline schedule (cron format)
		Duration time.Duration `yaml:"duration"` // Optional: Duration of the window
		Timezone string        `yaml:"timezone"` // Optional: Timezone for the schedule
	} `yaml:"maintenance,omitempty"`

	// Advanced options
	PrePatchScript  string `yaml:"pre_patch_script"`  // Script to run before patching
	PostPatchScript string `yaml:"post_patch_script"` // Script to run after patching
	TestMode        bool   `yaml:"test_mode"`         // Dry run mode - don't actually install patches

	// Platform-specific options
	Platform struct {
		// Linux options
		UseYum       bool `yaml:"use_yum"`       // Force yum on RHEL systems
		UseApt       bool `yaml:"use_apt"`       // Force apt on Debian systems
		UpdateKernel bool `yaml:"update_kernel"` // Include kernel updates

		// Windows options
		UseWSUS    bool   `yaml:"use_wsus"`    // Use WSUS server
		WSUSServer string `yaml:"wsus_server"` // WSUS server URL

		// macOS options
		IncludeAppStore bool `yaml:"include_app_store"` // Include App Store updates
	} `yaml:"platform,omitempty"`
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *Config) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"patch_type":  c.PatchType,
		"auto_reboot": c.AutoReboot,
		"test_mode":   c.TestMode,
	}

	if len(c.IncludePatches) > 0 {
		result["include_patches"] = c.IncludePatches
	}
	if len(c.ExcludePatches) > 0 {
		result["exclude_patches"] = c.ExcludePatches
	}
	if c.MaxDowntime != "" {
		result["max_downtime"] = c.MaxDowntime
	}
	if c.PrePatchScript != "" {
		result["pre_patch_script"] = c.PrePatchScript
	}
	if c.PostPatchScript != "" {
		result["post_patch_script"] = c.PostPatchScript
	}

	// Include maintenance if it has values
	if c.Maintenance.Window != "" || c.Maintenance.Schedule != "" {
		maintenance := make(map[string]interface{})
		if c.Maintenance.Window != "" {
			maintenance["window"] = c.Maintenance.Window
		}
		if c.Maintenance.Schedule != "" {
			maintenance["schedule"] = c.Maintenance.Schedule
		}
		if c.Maintenance.Duration != 0 {
			maintenance["duration"] = c.Maintenance.Duration
		}
		if c.Maintenance.Timezone != "" {
			maintenance["timezone"] = c.Maintenance.Timezone
		}
		result["maintenance"] = maintenance
	}

	// Include platform options if any are set
	platformMap := make(map[string]interface{})
	if c.Platform.UseYum {
		platformMap["use_yum"] = c.Platform.UseYum
	}
	if c.Platform.UseApt {
		platformMap["use_apt"] = c.Platform.UseApt
	}
	if c.Platform.UpdateKernel {
		platformMap["update_kernel"] = c.Platform.UpdateKernel
	}
	if c.Platform.UseWSUS {
		platformMap["use_wsus"] = c.Platform.UseWSUS
	}
	if c.Platform.WSUSServer != "" {
		platformMap["wsus_server"] = c.Platform.WSUSServer
	}
	if c.Platform.IncludeAppStore {
		platformMap["include_app_store"] = c.Platform.IncludeAppStore
	}
	if len(platformMap) > 0 {
		result["platform"] = platformMap
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *Config) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *Config) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *Config) Validate() error {
	return c.validate()
}

// GetManagedFields returns the list of fields this configuration manages
func (c *Config) GetManagedFields() []string {
	fields := []string{"patch_type", "auto_reboot", "test_mode"}

	if len(c.IncludePatches) > 0 {
		fields = append(fields, "include_patches")
	}
	if len(c.ExcludePatches) > 0 {
		fields = append(fields, "exclude_patches")
	}
	if c.MaxDowntime != "" {
		fields = append(fields, "max_downtime")
	}
	if c.PrePatchScript != "" {
		fields = append(fields, "pre_patch_script")
	}
	if c.PostPatchScript != "" {
		fields = append(fields, "post_patch_script")
	}
	if c.Maintenance.Window != "" || c.Maintenance.Schedule != "" {
		fields = append(fields, "maintenance")
	}

	// Add platform fields if they have values
	if c.Platform.UseYum || c.Platform.UseApt || c.Platform.UpdateKernel ||
		c.Platform.UseWSUS || c.Platform.WSUSServer != "" || c.Platform.IncludeAppStore {
		fields = append(fields, "platform")
	}

	return fields
}

// validate checks if the configuration is valid
func (c *Config) validate() error {
	// Validate patch type
	if c.PatchType == "" {
		return ErrInvalidPatchType
	}
	if !validPatchTypes[c.PatchType] {
		return ErrInvalidPatchType
	}

	// Validate max downtime format if specified
	if c.MaxDowntime != "" {
		if !isValidDuration(c.MaxDowntime) {
			return ErrInvalidMaxDowntime
		}
	}

	// Validate maintenance window format if specified
	if c.Maintenance.Window != "" {
		if !maintenanceWindowRegex.MatchString(c.Maintenance.Window) {
			return ErrInvalidMaintenanceWindow
		}
	}

	// Validate patch IDs format
	for _, patchID := range c.IncludePatches {
		if !isValidPatchID(patchID) {
			return ErrInvalidPatchID
		}
	}
	for _, patchID := range c.ExcludePatches {
		if !isValidPatchID(patchID) {
			return ErrInvalidPatchID
		}
	}

	// Check for conflicts
	for _, include := range c.IncludePatches {
		for _, exclude := range c.ExcludePatches {
			if include == exclude {
				return ErrConflictingPatchLists
			}
		}
	}

	// Validate platform-specific settings
	if c.Platform.UseYum && c.Platform.UseApt {
		return ErrConflictingPlatformOptions
	}

	return nil
}

// isValidDuration checks if a duration string is valid (e.g., "30m", "1h", "2h30m")
func isValidDuration(duration string) bool {
	_, err := time.ParseDuration(duration)
	return err == nil
}

// isValidPatchID checks if a patch ID format is valid
func isValidPatchID(patchID string) bool {
	if patchID == "" {
		return false
	}
	// Basic validation - patch IDs should not contain spaces or special characters that could cause issues
	return !strings.ContainsAny(patchID, " \t\n\r;|&<>(){}[]")
}

// PatchModule implements the Module interface for OS patch management
type PatchModule struct {
	mu           sync.RWMutex
	patchManager PatchManager
	lastCheck    time.Time
	cachedStatus *PatchStatus
}

// PatchStatus represents the current patching status of the system
type PatchStatus struct {
	LastPatchDate    time.Time   `json:"last_patch_date" yaml:"last_patch_date"`
	RebootRequired   bool        `json:"reboot_required" yaml:"reboot_required"`
	AvailablePatches []PatchInfo `json:"available_patches" yaml:"available_patches"`
	InstalledPatches []PatchInfo `json:"installed_patches" yaml:"installed_patches"`
	PendingPatches   []PatchInfo `json:"pending_patches" yaml:"pending_patches"`
	TotalSize        int64       `json:"total_size" yaml:"total_size"`
	SecurityPatches  int         `json:"security_patches" yaml:"security_patches"`
	CriticalPatches  int         `json:"critical_patches" yaml:"critical_patches"`
}
