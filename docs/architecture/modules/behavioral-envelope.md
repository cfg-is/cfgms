# Module Behavioral Envelope

Declare a module's intended filesystem, process and network behavior for review.
The `behavioral_envelope` field in `module.yaml` is metadata, defined by
[`BehavioralEnvelope`](../../../features/modules/metadata.go).
It is not an OS sandbox policy enforced by the current module launcher.

## Declaration

```yaml
behavioral_envelope:
  shells_out_to:
    - /usr/bin/systemctl
  reads_paths:
    - /etc/systemd/system/
  writes_paths: []
  network_egress: []
  lolbin_usage_justification: |
    Uses fixed systemctl subcommands with a validated service-name argument.
    No shell-evaluated command strings are constructed.
```

Use actual paths and destinations for the module's supported platforms. The
example is a declaration fragment, not a generated runtime confinement profile.

| Field | Intended declaration |
|---|---|
| `shells_out_to` | Executables/interpreters invoked as child processes. |
| `reads_paths` | Filesystem paths or prefixes read by the module. |
| `writes_paths` | Filesystem paths or prefixes written by the module. |
| `network_egress` | Intended external destinations/ranges. |
| `lolbin_usage_justification` | Why a broadly capable OS executable is needed and how invocation is constrained. |

All fields are optional. An omitted field makes no assertion for that category;
an explicit empty list declares no intended accesses in that category. Neither
form creates a runtime allow/deny rule. Treat destinations and path prefixes as
reviewable descriptions, not a promise of a particular glob or firewall matcher.

## What is enforced

Publisher trust, bundle/signature validation, resource validation and execution
authorization are separate contracts. Follow the
[distribution contract](distribution.md) and current module trust settings for
those checks. A signed declaration can identify the publisher's intended
behavior; a signature does not prove the process will stay within it.

The current runtime does not derive Linux namespaces/seccomp, Windows Job Object
filesystem filters, macOS sandbox profiles or egress firewalls from this metadata.
Do not approve a module on the assumption that undeclared reads, writes or
connections will be blocked. Host account privileges, OS controls and endpoint
security remain relevant to the process's effective permissions.

Runtime confinement would require an explicit implementation and platform-level
validation before this document could claim it. Metadata availability, a lint
rule or a platform's general sandbox capability does not establish that delivery.

## Author and reviewer requirements

- Prefer in-process OS/vendor APIs. Declare child executables when they are needed.
- Pass validated data as separate arguments to fixed executables; do not build
  shell-evaluated command strings from data.
- Stage script content to a file before execution. Inline evaluators such as
  `Invoke-Expression`, `powershell -Command`, `-EncodedCommand`,
  `-ExecutionPolicy Bypass`, `bash -c`, `eval` and `python -c` violate the
  repository execution rules regardless of a manifest declaration.
- Preserve inspectable on-disk execution and explain any broadly capable utility
  in the declaration. Do not claim that EDR will accept a process merely because
  the declaration is present.
- Review implementation/tests against declared paths, child processes and network
  behavior. Do not describe policy requirements as a proven exhaustive CI gate.

The [module architecture](README.md), [ADR-006](../decisions/006-module-packaging-and-distribution.md)
and [repository execution rules](../../../CLAUDE.md#modules) supply
the broader contracts and rationale.
