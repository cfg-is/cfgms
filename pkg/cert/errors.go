package cert

import "errors"

// Common certificate management errors
var (
	// ErrCertificateNotFound is returned when a certificate cannot be found
	ErrCertificateNotFound = errors.New("certificate not found")
	
	// ErrCANotInitialized is returned when trying to use an uninitialized CA
	ErrCANotInitialized = errors.New("certificate authority not initialized")
	
	// ErrInvalidCertificate is returned when a certificate is invalid or malformed
	ErrInvalidCertificate = errors.New("invalid certificate")
	
	// ErrCertificateExpired is returned when a certificate has expired
	ErrCertificateExpired = errors.New("certificate has expired")
	
	// ErrInvalidKeyPair is returned when a certificate and private key don't match
	ErrInvalidKeyPair = errors.New("certificate and private key do not match")
	
	// ErrUnsupportedKeyType is returned when an unsupported key type is used
	ErrUnsupportedKeyType = errors.New("unsupported key type")
	
	// ErrInvalidPEM is returned when PEM data cannot be decoded
	ErrInvalidPEM = errors.New("invalid PEM data")
	
	// ErrStorageNotFound is returned when certificate storage cannot be found
	ErrStorageNotFound = errors.New("certificate storage not found")
	
	// ErrRenewalNotSupported is returned when certificate renewal is not supported
	ErrRenewalNotSupported = errors.New("certificate renewal not supported")
	
	// ErrAutoRenewalDisabled is returned when auto-renewal is disabled
	ErrAutoRenewalDisabled = errors.New("automatic renewal is disabled")
	
	// ErrInvalidConfig is returned when configuration is invalid
	ErrInvalidConfig = errors.New("invalid configuration")
	
	// ErrCertificateRevoked is returned when a certificate has been revoked
	ErrCertificateRevoked = errors.New("certificate has been revoked")
	
	// ErrInvalidSerialNumber is returned when a serial number is invalid
	ErrInvalidSerialNumber = errors.New("invalid serial number")
	
	// ErrCertificateAlreadyExists is returned when trying to create a certificate that already exists
	ErrCertificateAlreadyExists = errors.New("certificate already exists")
)