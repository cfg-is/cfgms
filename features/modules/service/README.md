# Service Module

## Purpose and scope

The Service Module provides idempotent configuration management for OS services.
It implements the core Module interface (Get/Set/Test) to manage service runtime
state (running/stopped) and boot-enable configuration (enabled/disabled) through
the native OS service manager.

Platform support:
- **Linux**: systemd via `systemctl`
- **Windows**: Windows Service Control Manager via `sc.exe`
- **macOS**: launchd via `launchctl`

The module follows the Get→Compare→Set→Verify convergence model: Get reports current
state, the steward framework compares it to desired state, and Set converges to the
desired state if drift is detected.

## Configuration options

The module accepts configuration in YAML format with the following fields:

```yaml
state: "running"      # Required: "running" or "stopped"
enabled: true         # Required: true = start on boot, false = manual start only
restart_on: ""        # Optional: hint for the resource dependency engine to restart
                      # this service when a named related resource changes
```

The `resourceID` parameter (the service name) must match the OS-level service
identifier:
- Linux: systemd unit name without `.service` suffix (e.g., `cfgms-controller`)
- Windows: service name as registered with SCM (e.g., `CFGMSController`)
- macOS: launchd label (e.g., `com.cfgms.controller`)

Service names are validated to contain only safe characters
(`[a-zA-Z0-9._@-]`) before being passed to OS commands.

## Usage examples

1. Ensure a service is running and starts on boot:

    ```yaml
    - name: "cfgms-controller"
      module: "service"
      config:
        state: "running"
        enabled: true
    ```

2. Stop a service and prevent it from starting on boot:

    ```yaml
    - name: "some-service"
      module: "service"
      config:
        state: "stopped"
        enabled: false
    ```

3. Service that restarts when a related config file changes:

    ```yaml
    - name: "cfgms-controller"
      module: "service"
      config:
        state: "running"
        enabled: true
        restart_on: "cfgms-controller-config"
    ```

## Known limitations

1. Start/stop/enable/disable operations require elevated privileges (root on
   Linux/macOS, Administrator on Windows).
2. `Get` does not require elevated privileges on Linux (systemctl is-active/is-enabled
   work as a regular user).
3. The `restart_on` field is a dependency hint for the steward's resource dependency
   engine — the module itself does not watch for changes or trigger restarts.
4. macOS launchd `enabled` detection is based on whether the service is currently
   loaded. A service loaded without the `-w` flag may not persist across reboots.
5. Tests that interact with the OS service manager are skipped in environments
   without a running init system (e.g., Docker containers without systemd).

## Security considerations

1. Service names are validated against a strict allowlist
   (`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,254}$`) before being passed to OS commands.
2. `exec.Command` is used without invoking a shell, preventing shell injection.
3. The `resourceID` is sanitized in log output via `logging.SanitizeLogValue`.
4. The module requires elevated privileges for write operations — the steward
   should be configured to run with appropriate permissions.
