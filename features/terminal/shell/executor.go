package shell

import (
	"context"
	"fmt"
	"runtime"
)

// Executor defines the interface for shell execution
type Executor interface {
	// Start starts the shell process
	Start(ctx context.Context, config *Config) error

	// WriteData sends input data to the shell
	WriteData(ctx context.Context, data []byte) error

	// Resize resizes the terminal
	Resize(ctx context.Context, cols, rows int) error

	// Close terminates the shell process
	Close(ctx context.Context) error

	// OutputChannel returns a channel for receiving output data
	OutputChannel() <-chan []byte

	// ErrorChannel returns a channel for receiving error notifications
	ErrorChannel() <-chan error

	// IsRunning returns true if the shell process is running
	IsRunning() bool
}

// Config contains configuration for shell execution
type Config struct {
	Shell       string            `json:"shell"`
	Cols        int               `json:"cols"`
	Rows        int               `json:"rows"`
	Environment map[string]string `json:"environment"`
	WorkingDir  string            `json:"working_dir,omitempty"`
}

// Factory creates shell executors based on the operating system and shell type
type Factory struct{}

// NewFactory creates a new shell executor factory
func NewFactory() *Factory {
	return &Factory{}
}

// CreateExecutor creates a shell executor for the given configuration
func (f *Factory) CreateExecutor(config *Config) (Executor, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if !isShellSupported(config.Shell) {
		return nil, fmt.Errorf("unsupported shell: %s", config.Shell)
	}

	switch runtime.GOOS {
	case "windows":
		return NewWindowsExecutor(config)
	case "darwin", "linux", "freebsd", "openbsd", "netbsd":
		return NewUnixExecutor(config)
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// isShellSupported checks if the shell is supported on the current platform
func isShellSupported(shell string) bool {
	switch runtime.GOOS {
	case "windows":
		return shell == "powershell" || shell == "cmd"
	case "darwin", "linux", "freebsd", "openbsd", "netbsd":
		return shell == "bash" || shell == "zsh" || shell == "sh"
	default:
		return false
	}
}

// GetDefaultShell returns the default shell for the current operating system
func GetDefaultShell() string {
	switch runtime.GOOS {
	case "windows":
		return "powershell"
	default:
		return "bash"
	}
}

// GetSupportedShells returns the list of supported shells for the current OS
func GetSupportedShells() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{"powershell", "cmd"}
	case "darwin", "linux", "freebsd", "openbsd", "netbsd":
		return []string{"bash", "zsh", "sh"}
	default:
		return []string{}
	}
}
