package controller

import "fmt"

func (m *RegisterRequest) Validate() error {
	if m.Version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	if m.InitialDna == nil {
		return fmt.Errorf("initial DNA cannot be nil")
	}
	// Basic DNA validation
	if m.InitialDna.Id == "" {
		return fmt.Errorf("DNA ID cannot be empty")
	}
	if m.Credentials == nil {
		return fmt.Errorf("credentials cannot be nil")
	}
	return nil
}
