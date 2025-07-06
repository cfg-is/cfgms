package common

// Validator interface for proto messages that support validation
type Validator interface {
	Validate() error
}
