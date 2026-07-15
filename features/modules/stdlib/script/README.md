# Script Module

**Kind:** steward

## Purpose and scope

The Script module provides cross-platform script execution capabilities for CFGMS. It is designed for:

- One-off script execution for automation tasks
- Cross-platform script support (Windows, Linux, macOS)
- Shell-specific script execution (bash, PowerShell, Python, etc.)
- Secure script execution with optional signature validation
- Integration with workflow systems for orchestrated operations

This module is essential for executing custom logic, performing system operations, and integrating with external tools that require script-based automation. Unlike other modules that manage persistent resources, the script module focuses on execution rather than state management.

## Actions

The `action` field selects the execution path. Two values are accepted:

| Value | Behaviour |
|-------|-----------|
| `execute` (default, may be omitted) | Runs inline `content` immediately |
| `stage` | Looks up a library script by `id`+`version`, resolves `param_bindings`, records `StatusStaged` — **does not execute inline content** |

## Configuration options

### Execute action (default)

The execute action accepts configuration in YAML format with the following options:

```yaml
# action: execute  # optional; "execute" is the default
content: |
  echo "Hello World"
  echo "Script execution complete"
shell: bash
timeout: 30s
signing_policy: none
description: "Example script"
environment:
  VAR1: "value1"
  VAR2: "value2"
working_dir: "/tmp"
signature:
  algorithm: "rsa-sha256"
  signature: "base64-encoded-signature"
  public_key: "public-key-pem"
```

#### Required Fields

- **`content`** - The script content to execute
- **`shell`** - The shell type to use for execution

#### Optional Fields

- **`timeout`** - Execution timeout (default: 5 minutes)
- **`signing_policy`** - Signature validation policy (`none`, `optional`, `required`)
- **`description`** - Human-readable description of the script
- **`environment`** - Environment variables to set during execution
- **`working_dir`** - Working directory for script execution
- **`signature`** - Script signature information (required if signing_policy is `required`)

### Stage action

The stage action looks up a versioned library script and stages it for delivery to the endpoint without executing inline content. Use this when a workflow needs to make a script available on the host but defer execution.

```yaml
action: stage
stage:
  id: "my-setup-script"
  version: "1.2.3"
param_bindings:
  - name: api_token
    from: secret-store
    key: my-api-token-key
  - name: environment
    from: literal
    value: "production"
```

#### Required Fields (stage action)

- **`action`** - Must be `"stage"`
- **`stage.id`** - The library script identifier to look up in the `ScriptRepository`
- **`stage.version`** - The semantic version to stage (e.g. `"1.2.3"`)

#### Optional Fields (stage action)

- **`param_bindings`** - Parameter bindings resolved at staging time (see [Parameter Bindings](#parameter-bindings) below). `content` and `shell` are **not** used on this path.

#### Stage execution status

When the stage action completes successfully the resource status is set to `StatusStaged` (`"staged"`). No `ExecutionResult` is produced (the script was not run). Downstream steps can observe `"staged"` status to confirm a script is ready for delivery.

## Parameter Bindings

`param_bindings` declares how script parameters receive their values at execution time. Bindings are resolved on both the `execute` and `stage` paths via the module's secret store. Resolved values are injected as environment variables — secrets are never written to the command line or script block content.

```yaml
param_bindings:
  - name: db_password       # parameter name
    from: secret-store      # resolve from the steward secret store
    key: prod/db/password   # secret store lookup key
  - name: region
    from: literal           # use the value field directly
    value: "us-east-1"
```

### ParamSource values

| `from` value | Description | Required field |
|---|---|---|
| `secret-store` | Fetches the value from the steward secret store at execution time. The plaintext value is never stored in the config. | `key` (secret store lookup key) |
| `literal` | Uses the `value` field directly. Suitable for non-secret runtime variables. | `value` |

### Environment variable naming

Resolved parameter values are injected as environment variables. The variable name depends on the shell and whether the parameter is a secret:

| Shell | Secret (`from: secret-store`) | Literal (`from: literal`) |
|---|---|---|
| PowerShell / CMD | `CFGMS_SECRET_<PARAM_UPPER>` | `CFGMS_PARAM_<PARAM_UPPER>` |
| Bash / Zsh / Sh / Python | `<PARAM_UPPER>` | `CFGMS_PARAM_<PARAM_UPPER>` |

## Signing Policies

### None (Default)
No signature validation is performed. Scripts can be executed without signatures.

### Optional
If a signature is provided, it will be validated. Scripts without signatures are allowed to execute.

### Required
A valid signature must be provided. Scripts without valid signatures will be rejected.

### Supported Shells

#### Windows
- **PowerShell** (`powershell`) - Windows PowerShell with execution policy bypass
- **Command Prompt** (`cmd`) - Windows Command Prompt  
- **Python** (`python`, `python3`) - Python interpreter

#### Unix/Linux/macOS
- **Bash** (`bash`) - Bourne Again Shell
- **Zsh** (`zsh`) - Z Shell
- **Sh** (`sh`) - POSIX Shell
- **Python** (`python`, `python3`) - Python interpreter

## Usage examples

### Basic Shell Script (Linux/macOS)
```yaml
module: script
config:
  content: |
    #!/bin/bash
    echo "System information:"
    uname -a
    df -h
  shell: bash
  timeout: 60s
```

### PowerShell Script (Windows)
```yaml
module: script
config:
  content: |
    Write-Host "Windows system information:"
    Get-ComputerInfo | Select-Object WindowsProductName, TotalPhysicalMemory
    Get-Disk | Select-Object Number, Size, HealthStatus
  shell: powershell
  timeout: 60s
```

### Python Script (Cross-platform)
```yaml
module: script
config:
  content: |
    import os
    import platform
    
    print(f"Platform: {platform.system()}")
    print(f"Architecture: {platform.architecture()}")
    print(f"Working directory: {os.getcwd()}")
  shell: python3
  timeout: 30s
```

### Script with Environment Variables
```yaml
module: script
config:
  content: |
    echo "App environment: $APP_ENV"
    echo "Config path: $CONFIG_PATH"
  shell: bash
  environment:
    APP_ENV: "production"
    CONFIG_PATH: "/etc/myapp/config.yml"
```

### Signed Script (Required Signature)
```yaml
module: script
config:
  content: |
    echo "This is a signed script"
    # Perform sensitive operations here
  shell: bash
  signing_policy: required
  signature:
    algorithm: "rsa-sha256"
    signature: "MEUCIQDXvW..."
    public_key: |
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
      -----END PUBLIC KEY-----
```

## One-off Script Execution

The script module is designed primarily for one-off script execution, making it ideal for:

- **Workflow Integration** - Scripts can be executed as part of automated workflows
- **Ad-hoc Operations** - On-demand script execution for maintenance or troubleshooting
- **Configuration Tasks** - Scripts that need to run occasionally rather than maintaining persistent state

Unlike other modules that manage persistent resources (files, directories), the script module focuses on execution rather than state management.

## Security Considerations

### Execution Context
- Scripts run with the same privileges as the CFGMS steward process
- Use appropriate user contexts and privilege separation
- Consider using dedicated service accounts for script execution

### Input Validation
- All script content is validated before execution
- Shell availability is checked before attempting execution
- Timeout limits prevent runaway scripts

### Signature Validation
- Optional cryptographic signature validation for script integrity
- Supports RSA and ECDSA signature algorithms
- Public key or certificate-based verification

### Environment Variables
- Environment variables are sanitized and validated
- Sensitive values should not be logged or exposed
- Use secure methods for passing secrets to scripts

## Error Handling

The module provides detailed error information for script execution failures:

- **Exit codes** - Captured from script execution
- **Standard output** - Script stdout is captured
- **Standard error** - Script stderr is captured
- **Execution duration** - Time taken for script execution
- **Timeout detection** - Clear indication when scripts exceed timeout limits

## Integration Notes

### Workflow Engine Compatibility
The script module is designed to integrate seamlessly with the CFGMS workflow engine (future feature):

- Scripts can be invoked as workflow steps
- Execution results can be passed between workflow steps
- Error handling follows workflow execution patterns

### REST API Access
Script execution can be triggered via the CFGMS REST API:

```bash
# Execute a script via API
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "script", 
    "config": {
      "content": "echo Hello World",
      "shell": "bash"
    }
  }' \
  http://localhost:9080/api/v1/stewards/{id}/execute
```

## Testing

The module includes comprehensive tests covering:

- Cross-platform shell execution
- Configuration validation
- Signature verification
- Error handling scenarios
- Timeout behavior
- Environment variable handling

Run tests with:
```bash
go test -v ./features/modules/stdlib/script/
```

## Known limitations

- Scripts must be self-contained (no external dependencies unless pre-installed)
- Network access depends on system configuration and firewall rules
- File system access limited to steward process permissions
- Signature verification is basic (full PKI integration planned for future releases)
- Script execution timeout cannot exceed system-defined maximum
- Environment variables are limited by system constraints
- Shell availability depends on target system configuration

## Security considerations

### Execution Context
- Scripts run with the same privileges as the CFGMS steward process
- Use appropriate user contexts and privilege separation
- Consider using dedicated service accounts for script execution

### Input Validation
- All script content is validated before execution
- Shell availability is checked before attempting execution
- Timeout limits prevent runaway scripts

### Signature Validation
- Optional cryptographic signature validation for script integrity
- Supports RSA and ECDSA signature algorithms
- Public key or certificate-based verification

### Environment Variables
- Environment variables are sanitized and validated
- Sensitive values should not be logged or exposed
- Use secure methods for passing secrets to scripts