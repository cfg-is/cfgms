// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package terminal

var GetApplicableFilterRules = (*SecurityValidator).getApplicableFilterRules
var GenerateAlert = (*SessionMonitor).generateAlert
var UpdateThreatLevel = (*SessionMonitor).updateThreatLevel
var HandleAuditCommand = (*CommandFilter).handleAuditCommand
