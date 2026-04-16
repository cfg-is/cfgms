// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package gitsync implements a write-through git-sync component for config scopes.
//
// Git-sync pulls config entries from an external git origin (GitHub, GitLab, or any
// HTTP git remote) and writes them through to a ConfigStore. Sync is triggered by a
// webhook push event or a configurable polling interval.
//
// v1 semantics — read-only, one-way (git → backend):
//   - The controller never writes back to the git origin.
//   - For bound scopes, all edits happen at the git origin (PRs, commits, merges)
//     and flow down via sync.
//   - Conflict detection (remote diverged from last-synced commit) logs and skips
//     the affected scope; no merge is attempted.
//   - Scopes without a git binding are unaffected.
//
// Credentials reference:
// For v1, CredentialsRef accepts an environment-variable name (prefix "env:") or a
// plaintext file path. TODO: migrate to pkg/secrets SecretStore once sub-story H lands.
package gitsync

import "errors"

// Typed error sentinels returned by the git-sync component.
var (
	// ErrOriginUnreachable is returned when the git origin cannot be contacted.
	ErrOriginUnreachable = errors.New("gitsync: origin unreachable")

	// ErrAuthFailed is returned when credentials are rejected by the git origin.
	ErrAuthFailed = errors.New("gitsync: authentication failed")

	// ErrBranchNotFound is returned when the configured branch does not exist on the
	// origin.
	ErrBranchNotFound = errors.New("gitsync: branch not found")

	// ErrConflictDetected is returned when the remote has diverged from the
	// last-synced commit in a way that cannot be fast-forwarded. v1 logs and
	// skips — no merge is attempted.
	ErrConflictDetected = errors.New("gitsync: conflict detected (remote diverged from last-synced commit)")

	// ErrIntervalTooShort is returned when a polling interval is configured below
	// the minimum of MinPollingInterval (60 s).
	ErrIntervalTooShort = errors.New("gitsync: polling interval must be at least 60 seconds")
)
