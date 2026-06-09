# Module Behavioral Envelope

Every CFGMS module declares a behavioral envelope in `module.yaml` as part of the signed bundle. The envelope is a machine-readable description of what the module does at runtime: which file-system paths it reads or writes, which network destinations it contacts, which shells or interpreters it invokes, and why.

The behavioral envelope is **part of the signed bundle** — it cannot be changed without invalidating the publisher signature and the bundle's content hash. An operator, reviewer, or automated gate can inspect the declared envelope before approving a module for deployment.

---

## Why the envelope exists

Modules run on managed endpoints, often under application allowlisting and EDR monitoring. The behavioral envelope serves two audiences:

1. **Operators** — the envelope is the module's "what will this do to my device" promise. An operator approving a bundle sees exactly which paths, processes, and network destinations the module declares.
2. **Security tooling** — on platforms where the OS supports process-level observation (Linux namespaces, Windows Job Objects, macOS sandbox), the steward enforces the envelope at runtime. On platforms where enforcement is not available, the envelope is recorded and logged for audit purposes.

CI lint gates on declared permissions at bundle publish time on all supported platforms.

---

## Envelope schema

The envelope is declared under the `behavioral_envelope:` key in `module.yaml`.

```yaml
# module.yaml — behavioral_envelope fields
behavioral_envelope:
  shells_out_to:
    - "/bin/sh"
    - "C:\\Windows\\System32\\cmd.exe"
  writes_paths:
    - "/etc/cfgms/"
    - "/var/lib/cfgms/"
  reads_paths:
    - "/etc/hosts"
    - "/var/log/cfgms/"
  network_egress:
    - "10.0.0.0/8"
    - "ldap.corp.example:389"
  lolbin_usage_justification: |
    This module invokes cmd.exe to call netsh.exe for firewall rule management.
    The netsh.exe path is declared in shells_out_to. No dynamic command strings
    are constructed; the argument list is fully static.
```

All fields are optional. An absent field means the module makes no claim for that category. Omitting a field is not equivalent to declaring an empty list — the distinction matters for enforcement: an empty `writes_paths: []` asserts the module writes nothing; an absent `writes_paths` makes no assertion.

---

## Field reference

### `shells_out_to`

**Type**: list of strings  
**Content**: Absolute paths to shells or interpreters this module invokes as child processes (e.g. `/bin/sh`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`).

Declaring a shell here is an explicit statement that the module shells out. A module that does not need to shell out should omit this field or declare an empty list. The steward's EDR-friendly posture requires that every shell invocation be declared; undeclared shell invocations are a CI lint failure.

If a module shells out to a LOLBIN (living-off-the-land binary — a legitimate OS binary that can be misused), it must also populate `lolbin_usage_justification`.

### `writes_paths`

**Type**: list of strings (path prefixes or exact paths)  
**Content**: File-system paths or path prefixes the module writes to. Glob patterns are not supported in v1; use path prefixes (e.g. `/etc/cfgms/` matches all files under that directory).

The steward uses this list to configure OS-level write restrictions where supported. On Linux, this maps to `seccomp` or namespace path restrictions. On Windows, this maps to Job Object write filters. On macOS, this maps to the sandbox profile.

### `reads_paths`

**Type**: list of strings (path prefixes or exact paths)  
**Content**: File-system paths or path prefixes the module reads. The same path-prefix semantics as `writes_paths` apply.

Reads are less strictly enforced than writes on most platforms, but declaring them supports audit tooling and makes the module's intent inspectable.

### `network_egress`

**Type**: list of strings (CIDR ranges or `host:port` pairs)  
**Content**: External hosts or network ranges the module connects to.

Examples:
- `"10.0.0.0/8"` — any host on the 10.x.x.x subnet
- `"ldap.corp.example:389"` — a specific host and port
- `"443"` — any host on port 443 (port-only format; use sparingly)

The steward uses this list to configure egress filtering where the OS supports it. Undeclared outbound connections are blocked on platforms with enforcement capability.

### `lolbin_usage_justification`

**Type**: string (free-form text)  
**Required when**: `shells_out_to` lists a binary that is also a known LOLBIN.

LOLBIN (living-off-the-land binary) usage must be justified because the same binaries are commonly used in attack chains. The justification must explain:

1. Which binary is a LOLBIN and why it is needed.
2. That the argument list is static (no dynamic string construction).
3. What the module would do differently if the LOLBIN were unavailable.

A justification that says "needed for X" without explaining the static-argument constraint does not satisfy the CI lint gate.

**Examples of LOLBIN binaries that require justification:**
- `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe` (Windows)
- `bash`, `sh`, `python`, `perl`, `ruby` (Unix)
- `netsh.exe`, `reg.exe`, `schtasks.exe`, `wmic.exe` (Windows admin tools with broad capabilities)

---

## Banned execution patterns

The following patterns are unconditionally banned from module payloads. CI lint rejects bundles that contain them, regardless of what the behavioral envelope declares:

| Pattern | Why banned |
|---------|-----------|
| `iex` / `Invoke-Expression` | Executes arbitrary strings — no static analysis possible |
| `powershell -Command "<string>"` | Inline string execution bypasses disk-based content addressing |
| `-EncodedCommand <base64>` | Base64-encoded PowerShell — obfuscates intent from tooling |
| `-ExecutionPolicy Bypass` | Disables the PowerShell execution policy boundary |
| `bash -c "<string>"` | Shell inline string execution — same bypass as PowerShell |
| `eval` | Shell `eval` — executes arbitrary strings at runtime |
| `python -c "<code>"` | Python inline execution — same bypass pattern |
| Any runtime code composition | Constructing a command string from variables and executing it |

Scripts must be **staged to disk** before execution. Inline string execution bypasses disk-based content addressing and behavioral envelope enforcement, and is prohibited regardless of trust mode or publisher identity.

Modules that cannot perform their task without one of these patterns must be redesigned. The preference is in-process managed APIs (WMI, OS syscalls, vendor SDKs). Shelling out at all is a deliberate choice declared in the manifest; shelling out to inline-evaluated strings is never acceptable.

---

## EDR-friendly patterns

The behavioral envelope exists to make modules look like predictable admin tooling to EDR products. To preserve EDR signal fidelity:

- **Declared paths**: every file the module reads or writes appears in `reads_paths` or `writes_paths`. Modules that write to undeclared paths create noise in file-integrity monitoring.
- **Declared LOLBINs**: every LOLBIN invocation is in `shells_out_to` with a justification. Undeclared LOLBIN invocations are the highest-signal EDR alert pattern and will trigger alerts on allowlisted endpoints.
- **Static argument lists**: shell invocations use static, fully-constructed argument arrays — not `fmt.Sprintf`-assembled strings. Static lists are detectable by static analysis; dynamic assembly is not.
- **Signed binaries**: all module binaries carry the publisher's Ed25519 signature. The steward verifies the signature before spawning the process. An EDR product observing a process spawn from the steward can confirm the binary hash matches the declared bundle.
- **No in-memory tricks**: all code that runs arrives from a file on disk. No `mmap`-and-execute, no `memfd_create`, no process injection.

---

## Enforcement by platform

| Platform | `writes_paths` | `reads_paths` | `network_egress` | `shells_out_to` |
|----------|---------------|--------------|-----------------|----------------|
| Linux | seccomp + namespace | namespace (best-effort) | network namespace / iptables | seccomp execve filter |
| Windows | Job Object write ACL | ACL (best-effort) | Windows Filtering Platform | Job Object process creation |
| macOS | sandbox profile | sandbox profile | sandbox profile | sandbox profile |

On platforms where enforcement is not available for a given dimension, the envelope is recorded in steward logs and available for offline audit. The module is not blocked from running — enforcement degrades gracefully without breaking the module contract.

---

## Related documentation

- [ADR-006](../decisions/006-module-packaging-and-distribution.md) — Module packaging architecture and design rationale
- [Module System](README.md) — Module kinds, manifest fields, and available modules
- [Module Contract](interface.md) — gRPC wire contract (Handshake/Get/Set/Test/Shutdown)
- [Distribution](distribution.md) — Bundle format, content addressing, and trust store
- [Steward Configuration](../steward-configuration.md) — `module_trust:` configuration
