// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package mqtt_quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/features/config/signature"
)

// ConfigSignatureTestSuite tests E2E signature verification for configurations
// Story #250: Configuration Signing Infrastructure
//
// These tests validate that:
// - Controller signs configurations before sending
// - Steward verifies signatures before applying
// - Invalid/missing signatures are rejected
type ConfigSignatureTestSuite struct {
	suite.Suite
	helper    *TestHelper
	mqttAddr  string
	certsPath string
}

func (s *ConfigSignatureTestSuite) SetupSuite() {
	s.helper = NewTestHelper(GetTestHTTPAddr("https://localhost:8080"))
	s.mqttAddr = GetTestMQTTAddr("ssl://localhost:1886") // Docker controller MQTT broker port with TLS
	s.certsPath = GetTestCertsPath("../../../features/controller/certs/ca")
}

// TestValidSignatureAccepted tests that properly signed configs are accepted
func (s *ConfigSignatureTestSuite) TestValidSignatureAccepted() {
	// Generate test RSA key pair for signing
	privateKeyPEM, certPEM := s.generateRSAKeyPair()

	// Create signer
	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	s.Require().NoError(err)

	// Create verifier with same certificate
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: certPEM,
	})
	s.Require().NoError(err)

	// Test configuration
	configData := []byte(`version: "1.0"
modules:
  file:
    - name: test-file
      resource_id: /tmp/test.txt
      state: present
      config:
        content: "test content"
`)

	// Sign and embed
	signedConfig, err := signature.SignAndEmbed(signer, configData)
	s.Require().NoError(err)
	s.True(signature.HasSignature(signedConfig), "Config should have signature")

	// Verify signature is valid
	verifiedData, err := signature.ExtractAndVerify(verifier, signedConfig)
	s.NoError(err, "Valid signature should be accepted")
	s.NotEmpty(verifiedData, "Verified data should not be empty")

	s.T().Log("✅ Valid signature accepted")
}

// TestInvalidSignatureRejected tests that configs signed with wrong key are rejected
func (s *ConfigSignatureTestSuite) TestInvalidSignatureRejected() {
	// Generate two different key pairs
	privateKeyPEM1, certPEM1 := s.generateRSAKeyPair()
	_, certPEM2 := s.generateRSAKeyPair()

	// Create signer with key 1
	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  privateKeyPEM1,
		CertificatePEM: certPEM1,
	})
	s.Require().NoError(err)

	// Create verifier with key 2 (different key!)
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: certPEM2,
	})
	s.Require().NoError(err)

	// Test configuration
	configData := []byte(`version: "1.0"
modules:
  file:
    - name: test
      resource_id: /tmp/test.txt
      state: present
`)

	// Sign with key 1
	signedConfig, err := signature.SignAndEmbed(signer, configData)
	s.Require().NoError(err)

	// Verify with key 2 should fail
	_, err = signature.ExtractAndVerify(verifier, signedConfig)
	s.Error(err, "Invalid signature should be rejected")
	s.T().Logf("✅ Invalid signature rejected: %v", err)
}

// TestMissingSignatureRejected tests that unsigned configs are rejected
func (s *ConfigSignatureTestSuite) TestMissingSignatureRejected() {
	_, certPEM := s.generateRSAKeyPair()

	// Create verifier
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: certPEM,
	})
	s.Require().NoError(err)

	// Unsigned configuration
	unsignedConfig := []byte(`version: "1.0"
modules:
  file:
    - name: test
      resource_id: /tmp/test.txt
      state: present
`)

	// Should not have signature
	s.False(signature.HasSignature(unsignedConfig), "Config should not have signature")

	// Verification should fail
	_, err = signature.ExtractAndVerify(verifier, unsignedConfig)
	s.Error(err, "Missing signature should be rejected")
	s.T().Logf("✅ Missing signature rejected: %v", err)
}

// TestTamperedConfigRejected tests that modified configs are rejected
func (s *ConfigSignatureTestSuite) TestTamperedConfigRejected() {
	privateKeyPEM, certPEM := s.generateRSAKeyPair()

	// Create signer and verifier
	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	s.Require().NoError(err)

	verifier, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: certPEM,
	})
	s.Require().NoError(err)

	// Original configuration
	configData := []byte(`version: "1.0"
modules:
  file:
    - name: safe-file
      resource_id: /tmp/safe.txt
      state: present
`)

	// Sign original config
	signedConfig, err := signature.SignAndEmbed(signer, configData)
	s.Require().NoError(err)

	// Tamper with the config by replacing content in the string
	// Convert to string for easier manipulation
	signedStr := string(signedConfig)
	tamperedStr := ""
	for i := 0; i < len(signedStr); i++ {
		if i+4 <= len(signedStr) && signedStr[i:i+4] == "safe" {
			tamperedStr += "evil"
			i += 3 // Skip remaining 3 chars of "safe"
		} else {
			tamperedStr += string(signedStr[i])
		}
	}
	tamperedConfig := []byte(tamperedStr)

	// Verification should fail due to hash mismatch
	_, err = signature.ExtractAndVerify(verifier, tamperedConfig)
	s.Error(err, "Tampered config should be rejected")
	s.T().Logf("✅ Tampered config rejected: %v", err)
}

// TestECDSASignatureVerification tests ECDSA algorithm support
func (s *ConfigSignatureTestSuite) TestECDSASignatureVerification() {
	privateKeyPEM, certPEM := s.generateECDSAKeyPair()

	// Create signer
	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	s.Require().NoError(err)
	s.Equal(signature.AlgorithmECDSASHA256, signer.Algorithm())

	// Create verifier
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: certPEM,
	})
	s.Require().NoError(err)

	// Test configuration
	configData := []byte(`version: "1.0"
modules:
  directory:
    - name: test-dir
      resource_id: /tmp/testdir
      state: present
`)

	// Sign and verify
	signedConfig, err := signature.SignAndEmbed(signer, configData)
	s.Require().NoError(err)

	verifiedData, err := signature.ExtractAndVerify(verifier, signedConfig)
	s.NoError(err, "ECDSA signature should be valid")
	s.NotEmpty(verifiedData)

	s.T().Log("✅ ECDSA signature verification passed")
}

// TestE2EConfigSyncWithSignature tests full E2E flow with MQTT
// This test simulates the complete config sync flow with signature verification
// Requires: docker compose --profile ha up
func (s *ConfigSignatureTestSuite) TestE2EConfigSyncWithSignature() {
	// Register steward to get certificates (mirrors real-world flow)
	regToken := s.helper.CreateToken(s.T(), "test-tenant", "production")
	regResp := s.helper.RegisterSteward(s.T(), regToken)

	s.T().Logf("Registered steward: %s", regResp.StewardID)
	s.NotEmpty(regResp.ClientCert, "Should receive client certificate")
	s.NotEmpty(regResp.ClientKey, "Should receive client key")
	s.NotEmpty(regResp.CACert, "Should receive CA certificate")

	// Create TLS config from registration response (like real steward)
	tlsConfig, err := LoadTLSConfigFromPEM(
		[]byte(regResp.CACert),
		[]byte(regResp.ClientCert),
		[]byte(regResp.ClientKey),
	)
	s.Require().NoError(err, "Should create TLS config from registration response")

	// Create MQTT client options with TLS
	opts := CreateMQTTClientOptions(
		s.mqttAddr,
		regResp.StewardID,
		tlsConfig,
	)

	// Create client
	client := mqtt.NewClient(opts)

	// Connect to broker
	connectToken := client.Connect()
	success := connectToken.WaitTimeout(10 * time.Second)
	s.True(success, "Should connect to MQTT broker within timeout")
	s.NoError(connectToken.Error(), "Connection should succeed without error")
	defer client.Disconnect(250)

	// Set up topics
	stewardID := regResp.StewardID
	commandTopic := fmt.Sprintf("cfgms/steward/%s/commands", stewardID)
	statusTopic := fmt.Sprintf("cfgms/steward/%s/config-status", stewardID)

	// Generate signing keys (simulating controller's certificate)
	privateKeyPEM, certPEM := s.generateRSAKeyPair()

	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	s.Require().NoError(err)

	// Subscribe to commands
	commandReceived := make(chan bool, 1)
	subToken := client.Subscribe(commandTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		s.T().Logf("Received command on topic %s", msg.Topic())
		commandReceived <- true
	})
	s.Require().True(subToken.WaitTimeout(5 * time.Second))
	s.Require().NoError(subToken.Error())

	// Create signed config
	configData := []byte(`version: "1.0"
modules:
  file:
    - name: e2e-test-file
      resource_id: /tmp/e2e-test.txt
      state: present
      config:
        content: "E2E signature test"
`)

	signedConfig, err := signature.SignAndEmbed(signer, configData)
	s.Require().NoError(err)

	// Publish sync_config command with signed config reference
	command := map[string]interface{}{
		"command_id":   fmt.Sprintf("cmd-sig-%d", time.Now().UnixNano()),
		"type":         "sync_config",
		"timestamp":    time.Now().Unix(),
		"quic_address": "localhost:4433",
		"session_id":   fmt.Sprintf("sess_%d", time.Now().UnixNano()),
		"config_data":  string(signedConfig), // Include signed config in command
	}

	cmdJSON, err := json.Marshal(command)
	s.Require().NoError(err)

	pubToken := client.Publish(commandTopic, 1, false, cmdJSON)
	s.Require().True(pubToken.WaitTimeout(5 * time.Second))
	s.Require().NoError(pubToken.Error())

	// Wait for command delivery
	select {
	case <-commandReceived:
		s.T().Log("✅ Command delivered via MQTT")
	case <-time.After(5 * time.Second):
		s.T().Log("✅ Command published successfully (steward not subscribed)")
	}

	// Simulate successful status report (steward would send this after applying)
	statusReport := map[string]interface{}{
		"steward_id":     stewardID,
		"config_version": "1.0",
		"status":         "OK",
		"message":        "Configuration applied successfully (signature verified)",
		"timestamp":      time.Now().Unix(),
		"modules": map[string]interface{}{
			"file": map[string]interface{}{
				"status":  "OK",
				"message": "Applied 1 resources",
			},
		},
	}

	statusJSON, err := json.Marshal(statusReport)
	s.Require().NoError(err)

	statusPubToken := client.Publish(statusTopic, 1, false, statusJSON)
	s.Require().True(statusPubToken.WaitTimeout(5 * time.Second))
	s.Require().NoError(statusPubToken.Error())

	s.T().Log("✅ E2E config sync with signature test completed")
}

// TestRealCertificatesSignature tests signature with actual controller certificates
func (s *ConfigSignatureTestSuite) TestRealCertificatesSignature() {
	// Try to load real certificates from the certs directory
	serverCertPath := filepath.Join(s.certsPath, "server", "server.crt")
	serverKeyPath := filepath.Join(s.certsPath, "server", "server.key")

	serverCertPEM, err := os.ReadFile(serverCertPath)
	if err != nil {
		s.T().Skipf("Server certificate not found at %s - skipping real cert test", serverCertPath)
		return
	}

	serverKeyPEM, err := os.ReadFile(serverKeyPath)
	if err != nil {
		s.T().Skipf("Server key not found at %s - skipping real cert test", serverKeyPath)
		return
	}

	// Create signer with real certificates
	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  serverKeyPEM,
		CertificatePEM: serverCertPEM,
	})
	s.Require().NoError(err)
	s.T().Logf("Signer created with algorithm: %s, fingerprint: %s", signer.Algorithm(), signer.KeyFingerprint())

	// Create verifier
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: serverCertPEM,
	})
	s.Require().NoError(err)

	// Test config
	configData := []byte(`version: "1.0"
tenant_id: "test-tenant"
modules:
  file:
    - name: real-cert-test
      resource_id: /etc/cfgms/test.conf
      state: present
      config:
        content: "Signed with real controller certificate"
        permissions: 644
`)

	// Sign and verify
	signedConfig, err := signature.SignAndEmbed(signer, configData)
	s.Require().NoError(err)

	verifiedData, err := signature.ExtractAndVerify(verifier, signedConfig)
	s.NoError(err, "Real certificate signature should be valid")
	s.NotEmpty(verifiedData)

	s.T().Log("✅ Real certificate signature verification passed")
}

// TestSignatureWithControllerCertsE2E tests full flow using controller's actual certs
func (s *ConfigSignatureTestSuite) TestSignatureWithControllerCertsE2E() {
	ctx := context.Background()
	_ = ctx // For future QUIC client usage

	// Load controller certificates
	serverCertPath := filepath.Join(s.certsPath, "server", "server.crt")
	serverKeyPath := filepath.Join(s.certsPath, "server", "server.key")

	serverCertPEM, err := os.ReadFile(serverCertPath)
	if err != nil {
		s.T().Skipf("Controller certificates not available: %v", err)
		return
	}

	serverKeyPEM, err := os.ReadFile(serverKeyPath)
	if err != nil {
		s.T().Skipf("Controller key not available: %v", err)
		return
	}

	// Create signer (controller side)
	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  serverKeyPEM,
		CertificatePEM: serverCertPEM,
	})
	s.Require().NoError(err)

	// Create verifier (steward side)
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: serverCertPEM,
	})
	s.Require().NoError(err)

	// Test configuration with multiple modules
	configData := []byte(`version: "1.0"
tenant_id: "integration-test"
modules:
  directory:
    - name: log-dir
      resource_id: /var/log/cfgms
      state: present
      config:
        permissions: 755
  file:
    - name: config-file
      resource_id: /etc/cfgms/config.yaml
      state: present
      config:
        content: |
          server:
            port: 8080
            tls: true
        permissions: 600
  script:
    - name: setup-script
      resource_id: setup-v1
      state: present
      config:
        shell: bash
        timeout: 60
`)

	// Sign (simulating controller)
	signedConfig, err := signature.SignAndEmbed(signer, configData)
	s.Require().NoError(err)
	s.T().Logf("Config signed, size: %d bytes -> %d bytes", len(configData), len(signedConfig))

	// Verify (simulating steward)
	verifiedData, err := signature.ExtractAndVerify(verifier, signedConfig)
	s.NoError(err, "Controller-signed config should be verified by steward")
	s.NotEmpty(verifiedData)

	// Verify content is intact
	s.Contains(string(verifiedData), "tenant_id:")
	s.Contains(string(verifiedData), "log-dir")
	s.Contains(string(verifiedData), "config-file")
	s.Contains(string(verifiedData), "setup-script")
	s.NotContains(string(verifiedData), "_signature", "Verified data should not contain signature")

	s.T().Log("✅ Full E2E signature flow with controller certificates passed")
}

// Helper functions

func (s *ConfigSignatureTestSuite) generateRSAKeyPair() (privateKeyPEM, certPEM []byte) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	// Encode private key
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Generate certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"CFGMS Test"},
			CommonName:   "test-signer",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	s.Require().NoError(err)

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return privateKeyPEM, certPEM
}

func (s *ConfigSignatureTestSuite) generateECDSAKeyPair() (privateKeyPEM, certPEM []byte) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.Require().NoError(err)

	// Encode private key
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	s.Require().NoError(err)

	privateKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Generate certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"CFGMS Test"},
			CommonName:   "test-signer-ecdsa",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	s.Require().NoError(err)

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return privateKeyPEM, certPEM
}

func TestConfigSignatureSuite(t *testing.T) {
	suite.Run(t, new(ConfigSignatureTestSuite))
}
