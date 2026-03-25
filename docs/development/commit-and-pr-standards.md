# Commit Message & PR Description Standards

## Core Principle: FACTS ONLY

Everything in commit/PR messages must be provable fact from actual measurements, not estimates or aspirations.

- **GOOD:** "Reduced max latency from 5.4ms to 34µs (measured in test run)"
- **BAD:** "Should reduce latency by ~50%" (not measured)

When in doubt: Either measure it or don't claim it.

## Commit Messages

**Format:** `<scope>: <what changed> (Issue #XXX)`
**Length:** 15-25 lines for significant changes

**Rules:**
- **Title**: Imperative mood ("Fix" not "Fixed"), lowercase after colon, no period
- **Body**: Explain WHY (problem + solution context), then FACTS with citations
- **Changes**: 3-5 bullets of key modifications
- **Footer**: `Fixes #XXX` and `Co-Authored-By: Claude <noreply@anthropic.com>`

**Example:**
```
features/rbac: eliminate statistics lock contention (Issue #355)

The zero-trust policy engine used mutex-based statistics tracking.
Under concurrent load (50 goroutines), this caused serialization
where goroutine #50 waited 5ms while earlier goroutines held the
lock for 100ns each. This was causing performance test failures.

Replaced mutex with atomic operations (atomic.Int64, CAS loop for
EMA). Performance test results show:
- Concurrent max: 5.421ms → 34.093µs (measured in test output)
- Average: 77µs → 5.658µs (50 iterations)
- 100% success rate: 50/50 requests completed

Changes:
- Convert ZeroTrustStats fields to atomic.Int64/Uint64
- Replace mutex.Lock() with atomic.Add() for counters
- Use CAS loop for exponential moving average updates
- Restore 5ms timeout in performance tests (was 10ms)

Fixes #355
Co-Authored-By: Claude <noreply@anthropic.com>
```

## Pull Request Descriptions

**Length:** 60-80 lines for significant changes

**Rules:**
- **Summary**: 2-3 sentences with measured impact and actual numbers
- **Problem Context**: 1-2 paragraphs explaining WHY (enough context to avoid clicking through)
- **Changes**: 3-5 bullets of key technical changes (no code examples)
- **Measured Impact**: FACTS ONLY - cite test names, use table for 4+ metrics
- **Testing**: What was tested + pass/fail status

**Anti-patterns to avoid:**
- Speculation ("should", "approximately", "estimated")
- Code dumps (trust the diff)
- Implementation lectures (belongs in code comments)
- Repetition (say things once)

**Example:**
```markdown
## Summary

Replaces mutex-based statistics with atomic operations in zero-trust
policy engine. Under concurrent load (50 goroutines), eliminates
serialization that caused 5.4ms max latency. Test results show max
latency reduced to 34µs.

## Problem Context

The zero-trust policy engine tracked statistics using mutex-protected
counters. When 50 goroutines evaluated access concurrently, each
waited for exclusive lock access to increment counters.

## Changes

- Convert ZeroTrustStats fields to atomic.Int64/atomic.Uint64
- Remove sync.RWMutex, use atomic.Add() for counter increments
- Implement CAS loop for exponential moving average calculation
- Restore 5ms timeout in performance test

## Measured Impact

Test: TestZeroTrustPolicyEvaluationPerformance/Concurrent
- Max latency: 5.421ms → 34.093µs (159x improvement)
- Average: 77µs → 5.658µs (13x improvement)
- Success rate: 50/50 requests (100%)

## Testing

✅ All validation passed (test-complete)
✅ Performance requirements met (<5ms timeout)
✅ Zero test failures

Fixes #355
```

## Pre-Commit Checklist

- [ ] Facts verified: All performance claims from actual measurements
- [ ] Sources cited: Test names or benchmark references included
- [ ] No speculation: No "should", "approximately", "estimated"
- [ ] No code dumps: Let the diff show code changes
- [ ] Issue linked: `Fixes #XXX` or `Part of #XXX`
