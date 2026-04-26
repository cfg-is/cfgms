// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package graph

import (
	"context"
	"sync"
	"time"
)

// TokenBucketRateLimiter implements a token bucket rate limiter
type TokenBucketRateLimiter struct {
	// tokens is the current number of available tokens
	tokens float64

	// capacity is the maximum number of tokens
	capacity float64

	// refillRate is the rate at which tokens are added (tokens per second)
	refillRate float64

	// lastRefill is the last time tokens were added
	lastRefill time.Time

	// mutex protects the token bucket state
	mutex sync.Mutex
}

// NewTokenBucketRateLimiter creates a new token bucket rate limiter
func NewTokenBucketRateLimiter(capacity float64, refillRate float64) *TokenBucketRateLimiter {
	return &TokenBucketRateLimiter{
		tokens:     capacity,
		capacity:   capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available
func (r *TokenBucketRateLimiter) Wait(ctx context.Context) error {
	for {
		if r.Allow() {
			return nil
		}

		// Calculate how long to wait
		waitTime := r.calculateWaitTime()
		if waitTime <= 0 {
			continue // Try again immediately
		}

		// Wait for either the timeout or context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			continue // Try again after waiting
		}
	}
}

// Allow checks if a request is allowed without blocking
func (r *TokenBucketRateLimiter) Allow() bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Refill tokens based on elapsed time
	r.refill()

	// Check if we have tokens available
	if r.tokens >= 1 {
		r.tokens--
		return true
	}

	return false
}

// refill adds tokens to the bucket based on elapsed time
func (r *TokenBucketRateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()

	// Add tokens based on elapsed time and refill rate
	tokensToAdd := elapsed * r.refillRate
	r.tokens = min(r.capacity, r.tokens+tokensToAdd)

	r.lastRefill = now
}

// calculateWaitTime calculates how long to wait before retrying
func (r *TokenBucketRateLimiter) calculateWaitTime() time.Duration {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.refill()

	if r.tokens >= 1 {
		return 0 // No wait needed
	}

	// Calculate time needed to accumulate one token
	tokensNeeded := 1 - r.tokens
	waitSeconds := tokensNeeded / r.refillRate

	return time.Duration(waitSeconds * float64(time.Second))
}

// GetAvailableTokens returns the current number of available tokens
func (r *TokenBucketRateLimiter) GetAvailableTokens() float64 {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.refill()
	return r.tokens
}

// Reset resets the rate limiter to its initial state
func (r *TokenBucketRateLimiter) Reset() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.tokens = r.capacity
	r.lastRefill = time.Now()
}

// AdaptiveRateLimiter adjusts its rate based on server responses
type AdaptiveRateLimiter struct {
	// baseLimiter is the underlying rate limiter
	baseLimiter RateLimiter

	// currentRate is the current adjusted rate
	currentRate float64

	// baseRate is the original configured rate
	baseRate float64

	// successCount tracks consecutive successful requests
	successCount int

	// throttleCount tracks consecutive throttling responses
	throttleCount int

	// mutex protects the adaptive state
	mutex sync.Mutex
}

// NewAdaptiveRateLimiter creates a new adaptive rate limiter
func NewAdaptiveRateLimiter(baseRate float64, capacity float64) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		baseLimiter:   NewTokenBucketRateLimiter(capacity, baseRate),
		currentRate:   baseRate,
		baseRate:      baseRate,
		successCount:  0,
		throttleCount: 0,
	}
}

// Wait blocks until a request is allowed
func (r *AdaptiveRateLimiter) Wait(ctx context.Context) error {
	return r.baseLimiter.Wait(ctx)
}

// Allow checks if a request is allowed without blocking
func (r *AdaptiveRateLimiter) Allow() bool {
	return r.baseLimiter.Allow()
}

// RecordSuccess records a successful request for rate adaptation
func (r *AdaptiveRateLimiter) RecordSuccess() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.successCount++
	r.throttleCount = 0

	// Gradually increase rate after sustained success
	if r.successCount >= 10 && r.currentRate < r.baseRate {
		r.increaseRate()
		r.successCount = 0
	}
}

// RecordThrottle records a throttling response for rate adaptation
func (r *AdaptiveRateLimiter) RecordThrottle() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.throttleCount++
	r.successCount = 0

	// Immediately decrease rate on throttling
	r.decreaseRate()
}

// increaseRate gradually increases the request rate
func (r *AdaptiveRateLimiter) increaseRate() {
	// Increase by 10% but don't exceed base rate
	newRate := r.currentRate * 1.1
	if newRate > r.baseRate {
		newRate = r.baseRate
	}

	r.currentRate = newRate
	r.updateBaseLimiter()
}

// decreaseRate immediately decreases the request rate
func (r *AdaptiveRateLimiter) decreaseRate() {
	// Decrease by 50% on throttling
	r.currentRate = r.currentRate * 0.5

	// Don't go below 10% of base rate
	minRate := r.baseRate * 0.1
	if r.currentRate < minRate {
		r.currentRate = minRate
	}

	r.updateBaseLimiter()
}

// updateBaseLimiter updates the underlying rate limiter with the new rate
func (r *AdaptiveRateLimiter) updateBaseLimiter() {
	// For token bucket, we need to create a new limiter with the new rate
	if bucket, ok := r.baseLimiter.(*TokenBucketRateLimiter); ok {
		r.baseLimiter = NewTokenBucketRateLimiter(bucket.capacity, r.currentRate)
	}
}

// GetCurrentRate returns the current adjusted rate
func (r *AdaptiveRateLimiter) GetCurrentRate() float64 {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.currentRate
}

// Reset resets the adaptive rate limiter to its initial state
func (r *AdaptiveRateLimiter) Reset() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.currentRate = r.baseRate
	r.successCount = 0
	r.throttleCount = 0
	r.baseLimiter.Reset()
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// NewMicrosoftGraphRateLimiter creates a rate limiter optimized for Microsoft Graph API
// Microsoft Graph has different rate limits for different endpoints:
// - Most endpoints: 10,000 requests per 10 minutes per tenant
// - Some high-volume endpoints: Up to 3,000 requests per minute
func NewMicrosoftGraphRateLimiter() RateLimiter {
	// Conservative rate: 15 requests per second (900 per minute)
	// This should be well under most Graph API limits while allowing good throughput
	return NewAdaptiveRateLimiter(15.0, 30.0)
}
