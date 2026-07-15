// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"time"
)

// Script action constants
const (
	// ScriptActionExecute is the default action: run inline script content.
	ScriptActionExecute = "execute"
	// ScriptActionStage stages a library script by id+version for delivery
	// without executing it inline. param_bindings are resolved on this path.
	ScriptActionStage = "stage"
)

// StageConfig identifies a library script to stage for delivery.
// Required when ScriptConfig.Action == ScriptActionStage.
type StageConfig struct {
	// ID is the library script identifier.
	ID string `yaml:"id" json:"id"`
	// Version is the semantic version to stage (e.g. "1.2.3").
	Version string `yaml:"version" json:"version"`
}

// StagedRef holds the result of a successful stage action.
type StagedRef struct {
	// ID is the staged library script identifier.
	ID string
	// Version is the staged version string.
	Version string
	// Script is the fetched VersionedScript from the library repository.
	Script *VersionedScript
	// ResolvedParams are the parameter bindings resolved during staging.
	ResolvedParams []ResolvedParam
}

// ExecutionContext defines how a script should be executed in terms of user privilege.
type ExecutionContext string

const (
	// ExecutionContextSystem runs the script as SYSTEM (Windows) or root (Linux/macOS).
	// This is the default behavior; no change to the current steward process identity.
	ExecutionContextSystem ExecutionContext = "system"

	// ExecutionContextLoggedInUser runs the script as the currently logged-in console user.
	// If no interactive user is logged in, execution returns ErrNoUserLoggedIn so the
	// caller can queue the request for retry rather than failing permanently.
	ExecutionContextLoggedInUser ExecutionContext = "logged_in_user"
)

// ShellType represents the type of shell to execute the script in
type ShellType string

const (
	// Windows shells
	ShellPowerShell ShellType = "powershell" // Windows PowerShell 5.1 (powershell.exe)
	ShellPwsh       ShellType = "pwsh"       // PowerShell Core / cross-platform (pwsh.exe)
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
	ExitCode   int           `json:"exit_code"`
	Stdout     string        `json:"stdout"`
	Stderr     string        `json:"stderr"`
	Duration   time.Duration `json:"duration"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	PID        int           `json:"pid,omitempty"`
	ActualUser string        `json:"actual_user,omitempty"` // User the script ran as; empty means system/root
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
	// StatusStaged indicates a library script was staged for delivery.
	// The module recorded the library reference without executing inline content.
	StatusStaged ExecutionStatus = "staged"
)
