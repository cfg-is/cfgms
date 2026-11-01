// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build linux

package commands

import (
	"errors"
	"fmt"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
)

func TestCgroupServiceUnit(t *testing.T) {
	assert.Equal(t, "cfgms-steward.service", cgroupServiceUnit("0::/system.slice/cfgms-steward.service\n"))
	assert.Equal(t, "ssh.service", cgroupServiceUnit("12:cpu:/system.slice/ssh.service/sub\n0::/system.slice/ssh.service\n"))
	assert.Equal(t, "", cgroupServiceUnit("0::/user.slice/user-1000.slice/session-3.scope\n"))
	assert.Equal(t, "", cgroupServiceUnit(""))
}

func TestIsAccessDenied(t *testing.T) {
	assert.True(t, isAccessDenied(dbus.Error{Name: "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"}))
	assert.True(t, isAccessDenied(fmt.Errorf("wrapped: %w", dbus.Error{Name: "org.freedesktop.DBus.Error.AccessDenied"})))
	assert.False(t, isAccessDenied(dbus.Error{Name: systemdDest + ".NoSuchUnit"}))
	assert.False(t, isAccessDenied(errors.New("other")))
	assert.True(t, isNoSuchUnit(dbus.Error{Name: systemdDest + ".NoSuchUnit"}))
}
