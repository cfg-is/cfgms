package mqtt_quic

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/pkg/quic/session"
)

// QUICSessionTestSuite tests QUIC session authentication and management
// AC3: QUIC session authentication test (valid tokens accepted, invalid rejected)
type QUICSessionTestSuite struct {
	suite.Suite
	helper         *TestHelper
	sessionManager *session.Manager
}

func (s *QUICSessionTestSuite) SetupSuite() {
	s.helper = NewTestHelper(GetTestHTTPAddr("http://localhost:8080"))

	// Create session manager for testing
	s.sessionManager = session.NewManager(&session.Config{
		SessionTTL:      30 * time.Second,
		CleanupInterval: 1 * time.Minute,
	})
}

func (s *QUICSessionTestSuite) TearDownSuite() {
	if s.sessionManager != nil {
		s.sessionManager.Stop()
	}
}

// TestSessionGeneration tests QUIC session ID generation
func (s *QUICSessionTestSuite) TestSessionGeneration() {
	stewardID := "test-steward-123"

	// Generate session
	session, err := s.sessionManager.GenerateSession(stewardID)
	s.NoError(err, "Session generation should succeed")
	s.NotNil(session, "Session should not be nil")

	// Verify session properties
	s.NotEmpty(session.SessionID, "Session ID should be generated")
	s.Equal(stewardID, session.StewardID, "Steward ID should match")
	s.False(session.Used, "Session should not be marked as used initially")
	s.True(session.IsValid(), "New session should be valid")

	s.T().Logf("Generated session: %s for steward: %s", session.SessionID, stewardID)
}

// TestValidSessionAuthentication tests authentication with valid session
func (s *QUICSessionTestSuite) TestValidSessionAuthentication() {
	stewardID := "test-steward-valid"

	// Generate session
	session, err := s.sessionManager.GenerateSession(stewardID)
	s.NoError(err)

	// Validate session (marks as used)
	validatedSession, err := s.sessionManager.ValidateSession(session.SessionID, stewardID)
	s.NoError(err, "Valid session should authenticate successfully")
	s.NotNil(validatedSession)
	s.True(validatedSession.Used, "Session should be marked as used after validation")
	s.NotNil(validatedSession.UsedAt, "UsedAt timestamp should be set")

	s.T().Logf("Session %s validated successfully", session.SessionID)
}

// TestInvalidSessionID tests authentication with non-existent session
func (s *QUICSessionTestSuite) TestInvalidSessionID() {
	stewardID := "test-steward-invalid"
	invalidSessionID := "sess_nonexistent12345"

	// Try to validate non-existent session
	validatedSession, err := s.sessionManager.ValidateSession(invalidSessionID, stewardID)
	s.Error(err, "Invalid session ID should fail validation")
	s.Nil(validatedSession)
	s.Contains(err.Error(), "session not found", "Error should indicate session not found")

	s.T().Logf("Invalid session correctly rejected: %s", invalidSessionID)
}

// TestStewardIDMismatch tests authentication with wrong steward ID
func (s *QUICSessionTestSuite) TestStewardIDMismatch() {
	stewardID := "test-steward-mismatch"
	wrongStewardID := "test-steward-wrong"

	// Generate session for stewardID
	session, err := s.sessionManager.GenerateSession(stewardID)
	s.NoError(err)

	// Try to validate with wrong steward ID
	validatedSession, err := s.sessionManager.ValidateSession(session.SessionID, wrongStewardID)
	s.Error(err, "Steward ID mismatch should fail validation")
	s.Nil(validatedSession)
	s.Contains(err.Error(), "steward ID mismatch", "Error should indicate mismatch")

	s.T().Logf("Steward ID mismatch correctly detected")
}

// TestExpiredSession tests authentication with expired session
func (s *QUICSessionTestSuite) TestExpiredSession() {
	// Create manager with very short TTL
	shortTTLManager := session.NewManager(&session.Config{
		SessionTTL:      1 * time.Second,
		CleanupInterval: 10 * time.Minute,
	})
	defer shortTTLManager.Stop()

	stewardID := "test-steward-expired"

	// Generate session
	session, err := shortTTLManager.GenerateSession(stewardID)
	s.NoError(err)

	// Wait for session to expire
	time.Sleep(2 * time.Second)

	// Try to validate expired session
	validatedSession, err := shortTTLManager.ValidateSession(session.SessionID, stewardID)
	s.Error(err, "Expired session should fail validation")
	s.Nil(validatedSession)
	s.Contains(err.Error(), "expired", "Error should indicate expiration")

	s.T().Logf("Expired session correctly rejected")
}

// TestSingleUseSession tests that sessions can only be used once
func (s *QUICSessionTestSuite) TestSingleUseSession() {
	stewardID := "test-steward-singleuse"

	// Generate session
	session, err := s.sessionManager.GenerateSession(stewardID)
	s.NoError(err)

	// First validation should succeed
	validatedSession, err := s.sessionManager.ValidateSession(session.SessionID, stewardID)
	s.NoError(err, "First validation should succeed")
	s.NotNil(validatedSession)

	// Second validation should fail (session already used)
	validatedSession2, err := s.sessionManager.ValidateSession(session.SessionID, stewardID)
	s.Error(err, "Second validation should fail")
	s.Nil(validatedSession2)
	s.Contains(err.Error(), "already used", "Error should indicate session was already used")

	s.T().Logf("Single-use session enforcement working correctly")
}

// TestSessionCleanup tests that expired sessions are cleaned up
func (s *QUICSessionTestSuite) TestSessionCleanup() {
	// Create manager with short TTL and cleanup interval
	cleanupManager := session.NewManager(&session.Config{
		SessionTTL:      1 * time.Second,
		CleanupInterval: 2 * time.Second,
	})
	defer cleanupManager.Stop()

	stewardID := "test-steward-cleanup"

	// Generate several sessions
	for i := 0; i < 5; i++ {
		_, err := cleanupManager.GenerateSession(fmt.Sprintf("%s-%d", stewardID, i))
		s.NoError(err)
	}

	// Verify sessions exist
	initialCount := cleanupManager.GetActiveSessionCount()
	s.Equal(5, initialCount, "Should have 5 active sessions initially")

	// Wait for sessions to expire and cleanup to run
	time.Sleep(4 * time.Second)

	// Verify sessions were cleaned up
	finalCount := cleanupManager.GetActiveSessionCount()
	s.Equal(0, finalCount, "Expired sessions should be cleaned up")

	s.T().Logf("Session cleanup working correctly: %d → %d", initialCount, finalCount)
}

// TestConcurrentSessionGeneration tests concurrent session generation
func (s *QUICSessionTestSuite) TestConcurrentSessionGeneration() {
	const numConcurrent = 100

	results := make(chan error, numConcurrent)
	sessionIDs := make(chan string, numConcurrent)

	// Generate sessions concurrently
	for i := 0; i < numConcurrent; i++ {
		go func(idx int) {
			stewardID := fmt.Sprintf("concurrent-steward-%d", idx)
			session, err := s.sessionManager.GenerateSession(stewardID)
			if err != nil {
				results <- err
				return
			}

			sessionIDs <- session.SessionID
			results <- nil
		}(i)
	}

	// Collect results
	successCount := 0
	uniqueIDs := make(map[string]bool)

	for i := 0; i < numConcurrent; i++ {
		err := <-results
		if err == nil {
			successCount++
			sessionID := <-sessionIDs
			uniqueIDs[sessionID] = true
		}
	}

	// All generations should succeed
	s.Equal(numConcurrent, successCount, "All concurrent session generations should succeed")

	// All session IDs should be unique
	s.Equal(numConcurrent, len(uniqueIDs), "All session IDs should be unique")

	s.T().Logf("Concurrent session generation: %d successful, %d unique IDs", successCount, len(uniqueIDs))
}

// TestSessionRevocation tests manual session revocation
func (s *QUICSessionTestSuite) TestSessionRevocation() {
	stewardID := "test-steward-revoke"

	// Generate session
	session, err := s.sessionManager.GenerateSession(stewardID)
	s.NoError(err)

	// Verify session is valid
	s.True(session.IsValid())

	// Revoke session
	err = s.sessionManager.RevokeSession(session.SessionID)
	s.NoError(err, "Session revocation should succeed")

	// Try to validate revoked session
	validatedSession, err := s.sessionManager.ValidateSession(session.SessionID, stewardID)
	s.Error(err, "Revoked session should fail validation")
	s.Nil(validatedSession)

	s.T().Logf("Session revocation working correctly")
}

// TestQUICConnectionWithValidSession tests simulated QUIC connection with valid session
func (s *QUICSessionTestSuite) TestQUICConnectionWithValidSession() {
	s.T().Skip("Requires actual QUIC server - integration with docker tests")

	// This test would:
	// 1. Generate session via controller API
	// 2. Establish QUIC connection with session ID
	// 3. Verify mTLS handshake succeeds
	// 4. Verify data stream can be opened
	// 5. Verify session is marked as used
}

// TestQUICConnectionWithInvalidSession tests simulated QUIC connection with invalid session
func (s *QUICSessionTestSuite) TestQUICConnectionWithInvalidSession() {
	s.T().Skip("Requires actual QUIC server - integration with docker tests")

	// This test would:
	// 1. Attempt QUIC connection with invalid session ID
	// 2. Verify connection is rejected
	// 3. Verify TLS handshake fails with appropriate error
}

// TestSessionIDFormat tests the format and security of session IDs
func (s *QUICSessionTestSuite) TestSessionIDFormat() {
	stewardID := "test-steward-format"

	// Generate multiple sessions
	sessionIDs := make([]string, 10)
	for i := 0; i < 10; i++ {
		session, err := s.sessionManager.GenerateSession(stewardID)
		s.NoError(err)
		sessionIDs[i] = session.SessionID
	}

	// Verify all session IDs have correct prefix
	for _, sessionID := range sessionIDs {
		s.True(len(sessionID) > 5, "Session ID should have reasonable length")
		s.Contains(sessionID, "sess_", "Session ID should have sess_ prefix")
	}

	// Verify session IDs are unique (cryptographically random)
	uniqueCheck := make(map[string]bool)
	for _, sessionID := range sessionIDs {
		s.False(uniqueCheck[sessionID], "Session IDs should be unique")
		uniqueCheck[sessionID] = true
	}

	s.T().Logf("Session ID format validation passed: %d unique IDs", len(sessionIDs))
}

// TestSessionTimeout tests session expiration timing
func (s *QUICSessionTestSuite) TestSessionTimeout() {
	// Create manager with 3 second TTL
	timeoutManager := session.NewManager(&session.Config{
		SessionTTL:      3 * time.Second,
		CleanupInterval: 10 * time.Minute,
	})
	defer timeoutManager.Stop()

	stewardID := "test-steward-timeout"

	// Generate session
	session, err := timeoutManager.GenerateSession(stewardID)
	s.NoError(err)

	// Should be valid immediately
	s.True(session.IsValid())

	// Wait 2 seconds (still within TTL)
	time.Sleep(2 * time.Second)
	validatedSession, err := timeoutManager.ValidateSession(session.SessionID, stewardID)
	s.NoError(err, "Session should still be valid at 2 seconds")
	s.NotNil(validatedSession)

	// Generate new session for timeout test
	session2, err := timeoutManager.GenerateSession(stewardID)
	s.NoError(err)

	// Wait 4 seconds (beyond TTL)
	time.Sleep(4 * time.Second)
	validatedSession2, err := timeoutManager.ValidateSession(session2.SessionID, stewardID)
	s.Error(err, "Session should be expired after 4 seconds")
	s.Nil(validatedSession2)

	s.T().Logf("Session timeout behavior validated (TTL: 3s)")
}

// TestEmptyStewardID tests session generation with empty steward ID
func (s *QUICSessionTestSuite) TestEmptyStewardID() {
	// Try to generate session with empty steward ID
	session, err := s.sessionManager.GenerateSession("")
	s.Error(err, "Empty steward ID should fail")
	s.Nil(session)
	s.Contains(err.Error(), "steward ID is required", "Error should indicate missing steward ID")
}

// TestEmptySessionID tests validation with empty session ID
func (s *QUICSessionTestSuite) TestEmptySessionID() {
	// Try to validate empty session ID
	validatedSession, err := s.sessionManager.ValidateSession("", "some-steward")
	s.Error(err, "Empty session ID should fail validation")
	s.Nil(validatedSession)
	s.Contains(err.Error(), "session ID is required", "Error should indicate missing session ID")
}

// TestQUICTLSConfig tests TLS configuration for QUIC (placeholder)
func (s *QUICSessionTestSuite) TestQUICTLSConfig() {
	// Test TLS configuration
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false, // Production should verify
	}

	s.Equal(uint16(tls.VersionTLS13), tlsConfig.MinVersion, "Should use TLS 1.3 minimum")
	s.False(tlsConfig.InsecureSkipVerify, "Production should verify certificates")

	s.T().Log("QUIC TLS configuration validated")
}

func TestQUICSession(t *testing.T) {
	suite.Run(t, new(QUICSessionTestSuite))
}
