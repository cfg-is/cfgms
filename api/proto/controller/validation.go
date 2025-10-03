package controller

import (
	"fmt"

	"github.com/cfgis/cfgms/pkg/security"
)

func (m *RegisterRequest) Validate() error {
	validator := security.NewValidator()
	result := &security.ValidationResult{Valid: true}

	// Validate version
	validator.ValidateString(result, "version", m.Version, "required", "charset:safe_text", "max_length:32")

	// Validate initial DNA
	if m.InitialDna == nil {
		result.AddError("initial_dna", "", "required", "initial DNA cannot be nil")
	} else {
		// Validate DNA ID
		validator.ValidateString(result, "initial_dna.id", m.InitialDna.Id, "required", "uuid")
	}

	// Validate credentials
	if m.Credentials == nil {
		result.AddError("credentials", "", "required", "credentials cannot be nil")
	}

	if !result.Valid {
		// Return the first validation error for compatibility
		return fmt.Errorf("validation failed: %s", result.Errors[0].Message)
	}

	return nil
}
