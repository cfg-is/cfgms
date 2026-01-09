// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package mqtt_quic

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// CertificateLifecycleTestSuite validates CA persistence across controller restarts
// This test suite MUST run before other MQTT integration tests to ensure CA exists
type CertificateLifecycleTestSuite struct {
	suite.Suite
	helper *TestHelper
}

// SetupSuite checks test prerequisites
func (s *CertificateLifecycleTestSuite) SetupSuite() {
	if os.Getenv("CFGMS_TEST_SHORT") == "1" {
		s.T().Skip("Skipping certificate lifecycle tests in short mode")
	}

	s.helper = NewTestHelper(GetTestHTTPAddr("https://127.0.0.1:8080"))
}

// Test01_FirstBoot_GeneratesCA verifies CA generation on first boot
// This test simulates a fresh controller start with no existing CA
func (s *CertificateLifecycleTestSuite) Test01_FirstBoot_GeneratesCA() {
	s.T().Log("Phase 1: Delete existing CA to simulate first boot")

	// Delete CA if exists (simulate fresh installation)
	cmd := exec.Command("docker", "exec", "controller-standalone", "rm", "-rf", "/app/certs/ca")
	output, _ := cmd.CombinedOutput()
	s.T().Logf("Deleted CA directory (if existed): %s", output)

	// Restart controller to trigger CA generation
	s.T().Log("Phase 2: Restart controller to trigger CA generation")
	cmd = exec.Command("docker", "restart", "controller-standalone")
	output, err := cmd.CombinedOutput()
	require.NoError(s.T(), err, "Failed to restart controller: %s", output)

	// Wait for controller to start and generate CA
	s.T().Log("Phase 3: Wait for controller startup (15 seconds)")
	time.Sleep(15 * time.Second)

	// Verify CA was created
	s.T().Log("Phase 4: Verify CA certificate exists")
	cmd = exec.Command("docker", "exec", "controller-standalone", "test", "-f", "/app/certs/ca/ca.crt")
	err = cmd.Run()
	require.NoError(s.T(), err, "CA certificate should exist after first boot at /app/certs/ca/ca.crt")

	cmd = exec.Command("docker", "exec", "controller-standalone", "test", "-f", "/app/certs/ca/ca.key")
	err = cmd.Run()
	require.NoError(s.T(), err, "CA key should exist after first boot at /app/certs/ca/ca.key")

	// Get CA certificate and extract serial number
	s.T().Log("Phase 5: Extract CA serial number for next test")
	cmd = exec.Command("docker", "exec", "controller-standalone", "cat", "/app/certs/ca/ca.crt")
	caBytes, err := cmd.Output()
	require.NoError(s.T(), err, "Failed to read CA certificate")

	// Parse PEM-encoded certificate
	block, _ := pem.Decode(caBytes)
	require.NotNil(s.T(), block, "Failed to decode PEM certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(s.T(), err, "Failed to parse CA certificate")

	// Save serial number for next test (persistence validation)
	serialFile := "/tmp/cfgms-test-ca-serial.txt"
	err = os.WriteFile(serialFile, []byte(cert.SerialNumber.String()), 0644)
	require.NoError(s.T(), err, "Failed to save CA serial number")

	s.T().Logf("✅ CA generated successfully on first boot (serial: %s)", cert.SerialNumber.String())
}

// Test02_SubsequentBoot_ReusesCA verifies CA persists across restarts
// This test validates that the same CA is reused (not regenerated) on subsequent boots
func (s *CertificateLifecycleTestSuite) Test02_SubsequentBoot_ReusesCA() {
	s.T().Log("Phase 1: Restart controller (should reuse existing CA)")

	// Restart controller
	cmd := exec.Command("docker", "restart", "controller-standalone")
	output, err := cmd.CombinedOutput()
	require.NoError(s.T(), err, "Failed to restart controller: %s", output)

	// Wait for controller to start
	s.T().Log("Phase 2: Wait for controller startup (15 seconds)")
	time.Sleep(15 * time.Second)

	// Get CA certificate after restart
	s.T().Log("Phase 3: Extract CA serial number after restart")
	cmd = exec.Command("docker", "exec", "controller-standalone", "cat", "/app/certs/ca/ca.crt")
	caBytes, err := cmd.Output()
	require.NoError(s.T(), err, "Failed to read CA certificate")

	// Parse certificate
	block, _ := pem.Decode(caBytes)
	require.NotNil(s.T(), block, "Failed to decode PEM certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(s.T(), err, "Failed to parse CA certificate")

	currentSerial := cert.SerialNumber.String()

	// Compare with serial from first boot
	s.T().Log("Phase 4: Compare serial numbers (should be identical)")
	serialFile := "/tmp/cfgms-test-ca-serial.txt"
	firstBootSerial, err := os.ReadFile(serialFile)
	require.NoError(s.T(), err, "Failed to read saved serial number from Test01")

	require.Equal(s.T(), string(firstBootSerial), currentSerial,
		"CA should be reused (same serial), not regenerated. "+
			"This validates CA persistence across controller restarts.")

	s.T().Logf("✅ CA persisted correctly (serial: %s)", currentSerial)
}

// Test03_ClientCert_PersistsAcrossRestart verifies client certs remain valid
// This test validates that client certificates issued by the CA remain valid
// after controller restart (because CA was reused, not regenerated)
func (s *CertificateLifecycleTestSuite) Test03_ClientCert_PersistsAcrossRestart() {
	// This test will be implemented after registration API changes (Phase 3)
	// and will validate that:
	// 1. Register steward via API (get client cert, key, CA)
	// 2. Connect to MQTT with mTLS (should succeed)
	// 3. Restart controller
	// 4. Reconnect with SAME cert (should still succeed - CA was reused)

	s.T().Skip("TODO: Implement after Phase 3 (registration API certificate distribution)")
}

// TestCertificateLifecycle runs the test suite
// This test MUST run BEFORE other MQTT integration tests
func TestCertificateLifecycle(t *testing.T) {
	suite.Run(t, new(CertificateLifecycleTestSuite))
}
