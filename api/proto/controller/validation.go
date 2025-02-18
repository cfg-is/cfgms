package controller

import "fmt"

func (m *RegisterRequest) Validate() error {
	if m.Version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	if m.InitialDna == nil {
		return fmt.Errorf("initial DNA cannot be nil")
	}
	if err := m.InitialDna.Validate(); err != nil {
		return fmt.Errorf("invalid DNA: %w", err)
	}
	if m.Credentials == nil {
		return fmt.Errorf("credentials cannot be nil")
	}
	return nil
}
