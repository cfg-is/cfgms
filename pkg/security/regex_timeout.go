// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package security - Regex timeout mechanism to prevent ReDoS attacks
package security

import (
	"context"
	"errors"
	"regexp"
	"time"
)

var (
	// ErrRegexTimeout is returned when regex matching exceeds the timeout
	ErrRegexTimeout = errors.New("regex matching timeout exceeded")

	// DefaultRegexTimeout is the default timeout for regex operations
	// M-INPUT-2: Set to 1 second to prevent ReDoS attacks (security audit finding)
	DefaultRegexTimeout = 1 * time.Second
)

// RegexMatcher provides timeout-protected regex matching
// M-INPUT-2: Prevents Regular Expression Denial of Service (ReDoS) attacks
type RegexMatcher struct {
	timeout time.Duration
}

// NewRegexMatcher creates a new regex matcher with the specified timeout
// M-INPUT-2: If timeout is 0, uses DefaultRegexTimeout (1 second)
func NewRegexMatcher(timeout time.Duration) *RegexMatcher {
	if timeout == 0 {
		timeout = DefaultRegexTimeout
	}
	return &RegexMatcher{
		timeout: timeout,
	}
}

// MatchStringWithTimeout performs regex matching with timeout protection
// M-INPUT-2: Returns ErrRegexTimeout if matching takes longer than configured timeout
func (rm *RegexMatcher) MatchStringWithTimeout(pattern *regexp.Regexp, input string) (bool, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), rm.timeout)
	defer cancel()

	// Channel to receive match result
	resultChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	// Run regex match in goroutine
	go func() {
		defer func() {
			// Recover from panic in regex matching
			if r := recover(); r != nil {
				errChan <- errors.New("regex matching panicked")
			}
		}()

		matched := pattern.MatchString(input)
		resultChan <- matched
	}()

	// Wait for result or timeout
	select {
	case matched := <-resultChan:
		return matched, nil
	case err := <-errChan:
		return false, err
	case <-ctx.Done():
		// M-INPUT-2: Timeout occurred - potential ReDoS attack
		return false, ErrRegexTimeout
	}
}

// FindStringWithTimeout performs regex find with timeout protection
// M-INPUT-2: Returns ErrRegexTimeout if operation takes longer than configured timeout
func (rm *RegexMatcher) FindStringWithTimeout(pattern *regexp.Regexp, input string) (string, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), rm.timeout)
	defer cancel()

	// Channel to receive result
	resultChan := make(chan string, 1)
	errChan := make(chan error, 1)

	// Run regex find in goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- errors.New("regex find panicked")
			}
		}()

		result := pattern.FindString(input)
		resultChan <- result
	}()

	// Wait for result or timeout
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errChan:
		return "", err
	case <-ctx.Done():
		return "", ErrRegexTimeout
	}
}

// MatchString is a convenience function using DefaultRegexTimeout
// M-INPUT-2: Safe wrapper around pattern.MatchString with 1-second timeout
func MatchStringWithTimeout(pattern *regexp.Regexp, input string) (bool, error) {
	matcher := NewRegexMatcher(DefaultRegexTimeout)
	return matcher.MatchStringWithTimeout(pattern, input)
}
