package unit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testutil "github.com/cfgis/cfgms/pkg/testing"
)

// TestSetup holds common test dependencies and cleanup functions
type TestSetup struct {
	T       *testing.T
	Ctx     context.Context
	Cancel  context.CancelFunc
	Logger  *testutil.MockLogger
	Cleanup func()
}

// NewTestSetup creates a new test setup with common dependencies
func NewTestSetup(t *testing.T) *TestSetup {
	ctx, cancel := TestContext(t)
	logger := NewTestLogger(t)

	setup := &TestSetup{
		T:      t,
		Ctx:    ctx,
		Cancel: cancel,
		Logger: logger,
		Cleanup: func() {
			cancel()
		},
	}

	// Register cleanup with testing.T
	t.Cleanup(setup.Cleanup)

	return setup
}

// AddCleanup adds a cleanup function to the test setup
func (s *TestSetup) AddCleanup(cleanup func()) {
	oldCleanup := s.Cleanup
	s.Cleanup = func() {
		cleanup()
		oldCleanup()
	}
}

// TestContext creates a context with timeout for testing
func TestContext(t *testing.T) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// AssertEventually repeatedly checks a condition until it's true or timeout is reached
func AssertEventually(t *testing.T, condition func() bool, timeout time.Duration, msg string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.Fail(t, msg)
}

// RequireEventually repeatedly checks a condition until it's true or timeout is reached
func RequireEventually(t *testing.T, condition func() bool, timeout time.Duration, msg string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.Fail(t, msg)
}

// NewTestLogger creates a new mock logger for testing
func NewTestLogger(t *testing.T) *testutil.MockLogger {
	return testutil.NewMockLogger(false)
}

// AssertLogContains checks if a log message contains a specific string
func AssertLogContains(t *testing.T, logger *testutil.MockLogger, level, contains string) {
	logs := logger.GetLogs(level)
	found := false
	for _, log := range logs {
		if log.Message == contains {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected to find log message '%s' in %s logs", contains, level)
}

// RequireLogContains checks if a log message contains a specific string
func RequireLogContains(t *testing.T, logger *testutil.MockLogger, level, contains string) {
	logs := logger.GetLogs(level)
	found := false
	for _, log := range logs {
		if log.Message == contains {
			found = true
			break
		}
	}
	require.True(t, found, "Expected to find log message '%s' in %s logs", contains, level)
}
