// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package acme

import "errors"

var (
	// ErrInvalidDomain is returned when a domain name is invalid
	ErrInvalidDomain = errors.New("invalid domain name")
	// ErrInvalidEmail is returned when an email address is invalid
	ErrInvalidEmail = errors.New("invalid email address")
	// ErrInvalidChallengeType is returned when the challenge type is not supported
	ErrInvalidChallengeType = errors.New("invalid challenge type: must be http-01 or dns-01")
	// ErrUnsupportedDNSProvider is returned when the DNS provider is not supported
	ErrUnsupportedDNSProvider = errors.New("unsupported DNS provider")
	// ErrDNSCredentialMissing is returned when DNS credentials are not found in the secret store
	ErrDNSCredentialMissing = errors.New("DNS credential key not found in secret store")
	// ErrCertificateObtainFailed is returned when certificate issuance fails
	ErrCertificateObtainFailed = errors.New("failed to obtain certificate from ACME server")
	// ErrCertificateRenewFailed is returned when certificate renewal fails
	ErrCertificateRenewFailed = errors.New("failed to renew certificate from ACME server")
	// ErrChallengeFailed is returned when an ACME challenge fails
	ErrChallengeFailed = errors.New("ACME challenge failed")
	// ErrHTTPBindFailed is returned when the HTTP-01 challenge server cannot bind to the address
	ErrHTTPBindFailed = errors.New("failed to bind HTTP-01 challenge server")
	// ErrAccountNotFound is returned when the ACME account cannot be loaded or created
	ErrAccountNotFound = errors.New("ACME account not found and registration failed")
	// ErrDNSProviderRequired is returned when dns-01 challenge type is used without a DNS provider
	ErrDNSProviderRequired = errors.New("dns_provider is required when challenge_type is dns-01")
	// ErrDNSCredentialKeyRequired is returned when dns-01 is used without a credential key
	ErrDNSCredentialKeyRequired = errors.New("dns_credential_key is required when challenge_type is dns-01")
	// ErrCertStoreUnsupported is returned when a cert:\ path is used on a non-Windows platform
	ErrCertStoreUnsupported = errors.New("acme: Windows certificate store paths (cert:\\) are only supported on Windows")
	// ErrCertStoreImportFailed is returned when certificate import into the Windows certificate store fails
	ErrCertStoreImportFailed = errors.New("acme: failed to import certificate into Windows certificate store")
	// ErrCertStoreOpenFailed is returned when the Windows certificate store cannot be opened
	ErrCertStoreOpenFailed = errors.New("acme: failed to open Windows certificate store")
)
