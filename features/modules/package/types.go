package package_module

import (
	"context"
	"sync"
	"time"
)

// PackageManager defines the interface for package management operations
type PackageManager interface {
	// Install installs or updates a package to the specified version
	Install(ctx context.Context, name string, version string) error
	// Remove removes a package
	Remove(ctx context.Context, name string) error
	// GetInstalledVersion returns the currently installed version of a package
	GetInstalledVersion(ctx context.Context, name string) (string, error)
	// ListInstalled returns a map of installed packages and their versions
	ListInstalled(ctx context.Context) (map[string]string, error)
	// Name returns the name of the package manager
	Name() string
	// IsValidManager checks if the given package manager name is valid
	IsValidManager(name string) bool
}

// Config represents the package configuration
type Config struct {
	Name           string   `yaml:"name"`
	State          string   `yaml:"state"`
	Version        string   `yaml:"version"` // "latest" or specific version, treated as MinVersion if update is true
	Update         bool     `yaml:"update"`  // If true, will check for updates every config validation unless maintenance window is specified
	Dependencies   []string `yaml:"dependencies"`
	PackageManager string   `yaml:"package_manager"`
	Maintenance    struct {
		Window   string        `yaml:"window"`   // Optional: Reference to a named maintenance window
		Schedule string        `yaml:"schedule"` // Optional: Inline schedule (cron format)
		Duration time.Duration `yaml:"duration"` // Optional: Duration of the window
		Timezone string        `yaml:"timezone"` // Optional: Timezone for the schedule
	} `yaml:"maintenance,omitempty"` // Optional: Only used if update is true and window/schedule is specified
}

// PackageModule implements the Module interface for package management
type PackageModule struct {
	mu             sync.RWMutex
	packageManager PackageManager
}
