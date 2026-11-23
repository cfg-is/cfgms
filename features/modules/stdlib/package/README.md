# Package Module

Manage package presence and version through a declared package-manager provider.
This page owns the package resource's operator configuration. Developers should
start with [Config](types.go), [Set/Get](module.go) and [provider selection](providers.go).

## Resource configuration

Example fragment in a steward desired-state document:

```yaml
resources:
  - name: application-package
    module: package
    config:
      name: example-package
      state: present
      version: latest
      providers: [apt]
```

Choose a real package available from the endpoint's configured repositories.
The `resources[].name` is the CFGMS resource identifier; `config.name` is the
package name. If omitted, `config.name` falls back to the resource identifier.

| Field | Behavior |
|---|---|
| `name` | Package name; required after resource-ID fallback. Slashes, spaces and a leading dash are rejected. |
| `state` | `present` or `absent`. |
| `version` | Required for `present`: `latest` or a supported version string. Exact-version availability depends on the selected manager/repository. |
| `update` | When true, Set replaces the requested version with `latest`. Defaults false; this is not a minimum-version constraint. |
| `dependencies` | Package names installed at `latest` before the requested package. Self/duplicate dependencies are rejected. |
| `providers` | Ordered provider allowlist; the first available provider is selected. Unknown names are rejected. |
| `package_manager` | Legacy singular selector, used when `providers` is empty. Use current provider names below. |

### Version pinning

A declared `version` other than `latest` installs that version where the
provider supports pinning, and is joined to the package name as a single
argument. Drift detection compares the declared `version` with the installed
version by exact string match, so use the form the provider reports:

| Provider | Install argument | Accepted `version` form |
|---|---|---|
| `apt` | `name=version` | The full `dpkg-query ${Version}` string, including any epoch (for example `1:2.3-1`). |
| `dnf` | `name-version` | The rpm `%{VERSION}` only, without the release (for example `7.76.1`). |
| `yum` | `name-version` | The rpm `%{VERSION}` only, without the release (for example `7.76.1`). |
| `winget`, `choco` | `--version` | The version string the provider reports. |
| `pacman` | none | Pins are rejected. Use `version: latest`. |
| `brew` | none | Pins are rejected. Declare the versioned formula name (for example `python@3.12`) with `version: latest`. |

A provider that cannot pin returns an error that wraps
`ErrVersionPinUnsupported` and names the provider; it runs no command and never
installs a different version. `apt` install and remove run with
`DEBIAN_FRONTEND=noninteractive` (set on those commands only), so a debconf
question cannot block until the operation deadline.

`state: absent` removes the package through the selected provider; it does not
require a version. Provider/version configuration also affects observed state
and comparison. The steward's convergence cycle determines when Set is needed;
this module does not independently schedule updates.

## Provider selection

A resource's `providers` list takes precedence over the host policy at reserved
resource `@defaults`, which takes precedence over platform defaults. Selection
never falls back to a provider outside the effective allowlist.

| Platform | Built-in default order | Other registered provider |
|---|---|---|
| Linux/Unix fallback | `apt`, `dnf`, `yum`, `pacman` | — |
| macOS | `brew` | — |
| Windows | `winget` | `choco` (explicit opt-in) |

### macOS Homebrew requirement

Homebrew refuses to run as root, and the steward runs as root. The `brew`
provider therefore requires Homebrew to be installed at its fixed location for
the architecture (`/opt/homebrew/bin/brew` on Apple silicon,
`/usr/local/bin/brew` on Intel; `PATH` is never consulted) and runs every
`brew` command as the user that owns the Homebrew repository directory
(`/opt/homebrew`, or `/usr/local/Homebrew` on Intel), with that user's `HOME`.
The module refuses to run `brew` when the resolved binary is world-writable or
owned by neither root nor that user. If Homebrew is not installed, the
repository directory cannot be read, or it is owned by root, the operation fails
with an error naming the cause; it never falls back to running `brew` as root.
The module does not install Homebrew.

Installing a different provider is not an automatic substitute for the one
allowed by policy. If none of the allowed providers is usable, the operation
fails with the attempted list.

A host-wide policy fragment can set a narrower default:

```yaml
resources:
  - name: "@defaults"
    module: package
    config:
      providers: [apt]
```

Ensure the policy resource is applied before resources that rely on it.

## Chocolatey policy

Select Chocolatey with provider name `choco`, not `chocolatey`. The host policy
must supply `choco_source` for the organization's feed. Optional
`choco_source_name` defaults to `org`; `choco_bootstrap_package` defaults to the
feed's `chocolatey.nupkg`. Bootstrapping requires the operator-pinned
`choco_bootstrap_sha256` (64 hexadecimal characters).

Chocolatey is invoked only from the verified absolute install path
`C:\ProgramData\chocolatey\choco.exe`, never an arbitrary PATH entry. The
module checks file/directory ownership, writable ACLs and reparse points before
selection and after bootstrap. An untrusted install is unavailable; no fallback
outside the allowlist is attempted. Bootstrap uses only the configured source,
not the public community feed. See [bootstrap implementation](choco_bootstrap.go)
and [Windows trust checks](choco_trust_windows.go) for the enforced contract.

## Limits and failures

- The module requires the permissions needed by the selected OS package manager.
- Resource `manager`, `options`, `force`, `allow_untrusted`, `timeout` and `retry`
  are not consumed by the current Set implementation; do not use old examples
  claiming these configure manager operations.
- `maintenance` exists in Config metadata, but the current Set path does not
  enforce maintenance windows or a minimum-version update policy. A field being
  declared is not evidence that its scheduling behavior is implemented.
- The [field schema](schema.yaml) describes both resource and `@defaults`
  payloads. Context-dependent name/state/version requirements are enforced by
  Config/Set; field declarations do not establish additional runtime behavior.
- Package-manager failures are returned to the caller. Retry/error handling
  belongs to the surrounding execution/convergence policy, not an undocumented
  package retry block.
