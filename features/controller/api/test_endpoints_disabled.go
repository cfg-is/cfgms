//go:build !cfgms_test_endpoints

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

// registerTestRoutes deliberately does nothing in normal builds. Test
// administration endpoints must be absent—not merely runtime-disabled—from
// every production controller binary.
func registerTestRoutes(_ *Server) {}
