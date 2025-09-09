package script

import (
	"errors"
	"fmt"
)

// Script module specific errors
var (
	ErrShellNotSupported     = errors.New("shell not supported on this platform")
	ErrShellNotAvailable     = errors.New("shell not available on system")
	ErrScriptTimeout         = errors.New("script execution timed out")
	ErrScriptFailed          = errors.New("script execution failed")
	ErrSignatureRequired     = errors.New("script signature is required")
	ErrSignatureInvalid      = errors.New("script signature is invalid")
	ErrSignatureVerification = errors.New("script signature verification failed")
	ErrInvalidShellType      = errors.New("invalid shell type specified")
	ErrInvalidTimeout        = errors.New("invalid timeout value")
	ErrEmptyScript           = errors.New("script content cannot be empty")
	ErrInvalidSigningPolicy  = errors.New("invalid signing policy")
)

// ScriptError represents a script execution error with additional context
type ScriptError struct {
	Type       string
	Message    string
	ExitCode   int
	Stdout     string
	Stderr     string
	Underlying error
}

func (e *ScriptError) Error() string {
	if e.Underlying != nil {
		return fmt.Sprintf("%s: %s (underlying: %v)", e.Type, e.Message, e.Underlying)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *ScriptError) Unwrap() error {
	return e.Underlying
}

// NewScriptError creates a new script error
func NewScriptError(errorType, message string, exitCode int, stdout, stderr string, underlying error) *ScriptError {
	return &ScriptError{
		Type:       errorType,
		Message:    message,
		ExitCode:   exitCode,
		Stdout:     stdout,
		Stderr:     stderr,
		Underlying: underlying,
	}
}

// SignatureError represents a signature validation error
type SignatureError struct {
	Reason string
	Detail string
}

func (e *SignatureError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("signature validation failed: %s - %s", e.Reason, e.Detail)
	}
	return fmt.Sprintf("signature validation failed: %s", e.Reason)
}

// NewSignatureError creates a new signature validation error
func NewSignatureError(reason, detail string) *SignatureError {
	return &SignatureError{
		Reason: reason,
		Detail: detail,
	}
}
