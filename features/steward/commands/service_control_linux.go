// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build linux

package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	systemdDest    = "org.freedesktop.systemd1"
	systemdPath    = dbus.ObjectPath("/org/freedesktop/systemd1")
	systemdManager = "org.freedesktop.systemd1.Manager"
	systemdUnit    = "org.freedesktop.systemd1.Unit"
	systemdService = "org.freedesktop.systemd1.Service"

	// serviceJobTimeout bounds how long a start/stop/restart job may stay queued.
	serviceJobTimeout = 30 * time.Second
)

type systemdServiceController struct{}

// newPlatformServiceController returns the systemd D-Bus controller. It connects to
// the system bus the same way the telemetry collector does.
func newPlatformServiceController() ServiceController { return systemdServiceController{} }

func systemdUnitName(name string) string {
	if strings.HasSuffix(name, ".service") {
		return name
	}
	return name + ".service"
}

func connectSystemd() (*dbus.Conn, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("%w: system bus: %v", ErrServiceUnsupported, err)
	}
	return conn, nil
}

func isNoSuchUnit(err error) bool {
	var dbusErr dbus.Error
	if errors.As(err, &dbusErr) {
		return dbusErr.Name == systemdDest+".NoSuchUnit" || dbusErr.Name == systemdDest+".LoadFailed"
	}
	return false
}

func (systemdServiceController) Control(ctx context.Context, op ServiceOp, name string) error {
	method := ""
	switch op {
	case ServiceOpStart:
		method = systemdManager + ".StartUnit"
	case ServiceOpStop:
		method = systemdManager + ".StopUnit"
	case ServiceOpRestart:
		method = systemdManager + ".RestartUnit"
	default:
		return fmt.Errorf("unknown service op %q", op)
	}

	conn, err := connectSystemd()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// Subscribe to job completion before issuing the job so the result cannot be missed.
	signals := make(chan *dbus.Signal, 32)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)
	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath(systemdPath),
		dbus.WithMatchInterface(systemdManager),
		dbus.WithMatchMember("JobRemoved"),
	); err != nil {
		return fmt.Errorf("subscribe to job results: %w", err)
	}

	var job dbus.ObjectPath
	call := conn.Object(systemdDest, systemdPath).CallWithContext(ctx, method, 0, systemdUnitName(name), "replace")
	if call.Err != nil {
		if isNoSuchUnit(call.Err) {
			return ErrServiceNotFound
		}
		return fmt.Errorf("%s: %w", op, call.Err)
	}
	if err := call.Store(&job); err != nil {
		return fmt.Errorf("%s: read job path: %w", op, err)
	}

	timer := time.NewTimer(serviceJobTimeout)
	defer timer.Stop()
	for {
		select {
		case sig := <-signals:
			// JobRemoved body: (uint32 id, object path job, string unit, string result).
			if sig == nil || sig.Name != systemdManager+".JobRemoved" || len(sig.Body) < 4 {
				continue
			}
			if p, _ := sig.Body[1].(dbus.ObjectPath); p != job {
				continue
			}
			if result, _ := sig.Body[3].(string); result != "done" {
				return fmt.Errorf("%s: job finished with result %q", op, result)
			}
			return nil
		case <-timer.C:
			return fmt.Errorf("%s: timed out waiting for job", op)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (systemdServiceController) IsStewardService(ctx context.Context, name string) (bool, error) {
	unit := systemdUnitName(name)
	self := os.Getpid()

	// Cheap check first: the steward's own cgroup names its unit.
	if raw, err := os.ReadFile("/proc/self/cgroup"); err == nil && cgroupServiceUnit(string(raw)) == unit {
		return true, nil
	}

	conn, err := connectSystemd()
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	mgr := conn.Object(systemdDest, systemdPath)

	// The unit containing this process, resolved by systemd itself.
	var ownPath dbus.ObjectPath
	if call := mgr.CallWithContext(ctx, systemdManager+".GetUnitByPID", 0, uint32(self)); call.Err == nil { // #nosec G115 -- pid fits uint32
		if err := call.Store(&ownPath); err == nil {
			if id, err := unitStringProperty(ctx, conn, ownPath, systemdUnit, "Id"); err == nil && id == unit {
				return true, nil
			}
		}
	} else if !strings.Contains(call.Err.Error(), "NoUnitForPID") {
		return false, fmt.Errorf("resolve own unit: %w", call.Err)
	}

	// Any service whose main process is the steward.
	var targetPath dbus.ObjectPath
	call := mgr.CallWithContext(ctx, systemdManager+".GetUnit", 0, unit)
	if call.Err != nil {
		if isNoSuchUnit(call.Err) {
			return false, nil // not loaded, so it has no main process
		}
		return false, fmt.Errorf("look up unit: %w", call.Err)
	}
	if err := call.Store(&targetPath); err != nil {
		return false, fmt.Errorf("look up unit: %w", err)
	}
	v, err := conn.Object(systemdDest, targetPath).GetProperty(systemdService + ".MainPID")
	if err != nil {
		return false, fmt.Errorf("read main pid: %w", err)
	}
	if pid, ok := v.Value().(uint32); ok && int(pid) == self {
		return true, nil
	}
	return false, nil
}

func unitStringProperty(_ context.Context, conn *dbus.Conn, path dbus.ObjectPath, iface, prop string) (string, error) {
	v, err := conn.Object(systemdDest, path).GetProperty(iface + "." + prop)
	if err != nil {
		return "", err
	}
	s, _ := v.Value().(string)
	return s, nil
}

// cgroupServiceUnit returns the first systemd ".service" unit named in the
// content of a /proc/<pid>/cgroup file, or "" when the process is not in a service.
func cgroupServiceUnit(content string) string {
	for _, line := range strings.Split(content, "\n") {
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		for _, part := range strings.Split(line[idx+1:], "/") {
			if strings.HasSuffix(part, ".service") {
				return part
			}
		}
	}
	return ""
}
