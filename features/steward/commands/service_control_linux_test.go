// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build linux

package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCgroupServiceUnit(t *testing.T) {
	assert.Equal(t, "cfgms-steward.service", cgroupServiceUnit("0::/system.slice/cfgms-steward.service\n"))
	assert.Equal(t, "ssh.service", cgroupServiceUnit("12:cpu:/system.slice/ssh.service/sub\n0::/system.slice/ssh.service\n"))
	assert.Equal(t, "", cgroupServiceUnit("0::/user.slice/user-1000.slice/session-3.scope\n"))
	assert.Equal(t, "", cgroupServiceUnit(""))
}
