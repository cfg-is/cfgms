# Casing Conventions (user-facing surfaces)

Which case to use on the surfaces operators and module authors actually touch.
This is **not** about Go source naming — that follows standard Go (see
[Go Coding Standards](go-coding-standards.md); exported identifiers are PascalCase).

## The rule

- **`snake_case` for everything declarative** — config you author, push, or read back.
- **`PascalCase` for everything PowerShell-facing** — code you script or invoke.

| Surface | Case | Example |
|---|---|---|
| YAML/JSON config keys (`steward.cfg`, pushed fleet config) | `snake_case` | `converge_interval`, `module_trust` |
| Module resource config keys (`module.yaml`, `hyperv.vm` config) | `snake_case` | `enroll_steward_path`, `on_existing` |
| CLI flags | `kebab-case` | `--controller-url`, `--regtoken` |
| PowerShell transport functions + params | `PascalCase` / `-PascalCase` | `Cfgms-CopyToSeedVHD -StewardSrc` |
| Module manifest cmdlet / behavioral-envelope references | `PascalCase` | `Get-VM`, `Add-ClusterVirtualMachineRole` |

Rationale: declarative config lives next to cloud-init, Kubernetes, Ansible, and
GitHub Actions — all `snake_case`; matching them keeps CFGMS config unsurprising and
lint-clean. The scripting surface is PowerShell, so it stays `PascalCase` — a
PowerShell-native operator writes modules/scripts in `PascalCase` and pushes
`snake_case` config, each idiomatic on its own side.

## Do

- Add a `yaml:"snake_case"` **and** a matching `json:"snake_case"` tag to every config
  struct field, so a config round-trips identically whether it is shown as YAML or JSON.
- Name new PowerShell functions/params in `PascalCase` to match the existing
  `Cfgms-*` transport surface.

## Don't

- **Don't** put `PascalCase` keys in a config file — even for PowerShell-oriented
  users. `ConvergeInterval:` in YAML is wrong; `converge_interval:` is right.
- **Don't** ship a config struct field with a `yaml:` tag but no `json:` tag. JSON
  marshalling then falls back to the Go field name and leaks `PascalCase` to the
  wire (this is the bug behind `cfg config show` emitting `ConvergeInterval` while
  `cfg config upload` expects `converge_interval` — the two stop round-tripping).
- **Don't** invent a third case (`camelCase`) for config keys.
- **Don't** rename established keys for cosmetic consistency — casing is a wire
  contract; changing it breaks existing pushed configs.
