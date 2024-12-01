package testutil

import (
	"github.com/stretchr/testify/require"
)

// TestingT is an interface wrapper around *testing.T
type TestingT interface {
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatal(args ...interface{})
	Helper()
}

// RequireNoError fails the test if err is not nil
func RequireNoError(t TestingT, err error, msgAndArgs ...interface{}) {
	t.Helper()
	require.NoError(t, err, msgAndArgs...)
}
