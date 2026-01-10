// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"time"
)

// ShellType represents the type of shell to execute the script in
type ShellType string

const (
	// Windows shells
	ShellPowerShell ShellType = "powershell"
	ShellCmd        ShellType = "cmd"

	// Unix shells
	ShellBash ShellType = "bash"
	ShellZsh  ShellType = "zsh"
	ShellSh   ShellType = "sh"

	// Cross-platform interpreters
	ShellPython  ShellType = "python"
	ShellPython3 ShellType = "python3"
)

// SigningPolicy defines the script signing requirements
type SigningPolicy string

const (
	SigningPolicyNone     SigningPolicy = "none"     // No signing required
	SigningPolicyOptional SigningPolicy = "optional" // Validate if signature present
	SigningPolicyRequired SigningPolicy = "required" // Signature must be present and valid
)

// ScriptSignature contains script signature information
type ScriptSignature struct {
	Algorithm  string `yaml:"algorithm"`            // Signature algorithm (e.g., "rsa-sha256")
	Signature  string `yaml:"signature"`            // Base64 encoded signature
	PublicKey  string `yaml:"public_key"`           // Public key for verification
	Thumbprint string `yaml:"thumbprint,omitempty"` // Certificate thumbprint (Windows)
}

// ExecutionResult represents the result of script execution
type ExecutionResult struct {
	ExitCode  int           `json:"exit_code"`
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
	Duration  time.Duration `json:"duration"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	PID       int           `json:"pid,omitempty"`
}

// ExecutionStatus represents the current status of script execution
type ExecutionStatus string

const (
	StatusPending   ExecutionStatus = "pending"
	StatusRunning   ExecutionStatus = "running"
	StatusCompleted ExecutionStatus = "completed"
	StatusFailed    ExecutionStatus = "failed"
	StatusTimeout   ExecutionStatus = "timeout"
	StatusCancelled ExecutionStatus = "cancelled"
)
