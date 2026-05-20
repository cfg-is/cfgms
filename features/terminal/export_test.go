// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package terminal

var GetApplicableFilterRules = (*SecurityValidator).getApplicableFilterRules
var GenerateAlert = (*SessionMonitor).generateAlert
var UpdateThreatLevel = (*SessionMonitor).updateThreatLevel
var HandleAuditCommand = (*CommandFilter).handleAuditCommand
