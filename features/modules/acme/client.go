// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const (
	leProductionURL = "https://acme-v02.api.letsencrypt.org/directory"
	leStagingURL    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// ACMEUser implements lego's registration.User interface
type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

// GetEmail returns the user's email
func (u *ACMEUser) GetEmail() string {
	return u.Email
}

// GetRegistration returns the user's ACME registration
func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey returns the user's private key
func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// ACMEClient wraps a lego client with CFGMS-specific functionality
type ACMEClient struct {
	client *lego.Client
	user   *ACMEUser
	store  *ACMECertStore
	config *ACMEConfig
}

// NewACMEClient creates a new ACME client configured for the given ACMEConfig.
// It loads or creates an ACME account, configures the challenge solver, and
// registers with the ACME server if needed.
func NewACMEClient(cfg *ACMEConfig, store *ACMECertStore, solver ChallengeSolver) (*ACMEClient, error) {
	// Load or create the account key
	user, err := loadOrCreateUser(cfg.Email, store)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAccountNotFound, err)
	}

	// Determine ACME server URL
	serverURL := leProductionURL
	if cfg.Staging {
		serverURL = leStagingURL
	}
	if cfg.ACMEServer != "" {
		serverURL = cfg.ACMEServer
	}

	// Configure lego client
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = serverURL
	legoCfg.Certificate.KeyType = toLegoKeyType(cfg.KeyType)

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Configure challenge solver
	if err := solver.Configure(client); err != nil {
		return nil, err
	}

	// Register or recover account if not already registered
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("%w: registration failed: %v", ErrAccountNotFound, err)
		}
		user.Registration = reg

		// Save registration
		regJSON, _ := json.Marshal(reg)
		accountData := &AccountData{
			Email:        cfg.Email,
			Registration: regJSON,
			URI:          reg.URI,
		}
		if err := store.StoreAccount(cfg.Email, accountData); err != nil {
			return nil, fmt.Errorf("failed to save account: %w", err)
		}
	}

	return &ACMEClient{
		client: client,
		user:   user,
		store:  store,
		config: cfg,
	}, nil
}

// ObtainCertificate requests a new certificate from the ACME server
func (c *ACMEClient) ObtainCertificate() (certPEM, keyPEM, issuerPEM []byte, err error) {
	request := certificate.ObtainRequest{
		Domains: c.config.Domains,
		Bundle:  true,
	}

	certificates, err := c.client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrCertificateObtainFailed, err)
	}

	return certificates.Certificate, certificates.PrivateKey, certificates.IssuerCertificate, nil
}

// RenewCertificate renews an existing certificate
func (c *ACMEClient) RenewCertificate(certPEM, keyPEM []byte) (newCertPEM, newKeyPEM, newIssuerPEM []byte, err error) {
	certResource := &certificate.Resource{
		Domain:      c.config.Domains[0],
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	renewed, err := c.client.Certificate.RenewWithOptions(*certResource, &certificate.RenewOptions{
		Bundle: true,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrCertificateRenewFailed, err)
	}

	return renewed.Certificate, renewed.PrivateKey, renewed.IssuerCertificate, nil
}

// loadOrCreateUser loads an existing ACME account or creates a new one
func loadOrCreateUser(email string, store *ACMECertStore) (*ACMEUser, error) {
	user := &ACMEUser{Email: email}

	// Try to load existing account key
	if store.AccountExists(email) {
		keyPEM, err := store.LoadAccountKey(email)
		if err == nil {
			key, err := parseECPrivateKey(keyPEM)
			if err == nil {
				user.key = key

				// Try to load registration
				accountData, err := store.LoadAccount(email)
				if err == nil && accountData.Registration != nil {
					var reg registration.Resource
					if json.Unmarshal(accountData.Registration, &reg) == nil {
						user.Registration = &reg
					}
				}
				return user, nil
			}
		}
	}

	// Generate new account key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account key: %w", err)
	}
	user.key = privateKey

	// Save the key
	keyPEM, err := marshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal account key: %w", err)
	}
	if err := store.StoreAccountKey(email, keyPEM); err != nil {
		return nil, fmt.Errorf("failed to store account key: %w", err)
	}

	return user, nil
}

func parseECPrivateKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func marshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}), nil
}

func toLegoKeyType(keyType string) certcrypto.KeyType {
	switch keyType {
	case "rsa2048":
		return certcrypto.RSA2048
	case "rsa4096":
		return certcrypto.RSA4096
	case "ec256":
		return certcrypto.EC256
	case "ec384":
		return certcrypto.EC384
	default:
		return certcrypto.EC256
	}
}
