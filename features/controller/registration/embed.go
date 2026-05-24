// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package registration provides built-in workflow YAML templates for
// the registration approval hook (Issue #1527).
package registration

import _ "embed"

//go:embed auto_approve.yaml
var AutoApproveYAML []byte

//go:embed manual_review.yaml
var ManualReviewYAML []byte
