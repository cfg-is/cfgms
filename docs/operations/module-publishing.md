# Publishing, Trusting, Approving and Troubleshooting Modules

This guide takes an operator from a built module binary to that module running on
stewards, and explains how to diagnose each step when it fails. It covers publishing a
signed bundle, trusting its publisher on the controller, approving the version, how
stewards pull it, the two trust modes, and a troubleshooting reference keyed to the
error names and messages you will see.

For the bundle format, content hash and signature scheme, see
[Module Distribution Architecture](../architecture/modules/distribution.md).

## 1. How the pieces fit

```
publisher                controller                          steward
---------                ----------                          -------
cfg module keygen
cfg module bundle build
git tag + push  ───────► module_sources (git, https/ssh)
                         cfg push with required_modules ───► resolves tag, verifies,
                         bundle cached as "pending"          caches the bundle
                         cfg module approve  ──────────────► bundle becomes "approved"
                                                             config sync delivers
                                                             required_modules
                         FetchModuleBundle (mTLS) ◄───────── steward pulls own platform,
                                                             verifies, installs, loads
```

Three independent decisions gate a third-party module:

1. **Source** — the controller can fetch the bundle (`module_sources`).
2. **Trust** — the publisher's key is known (`module_trust.publishers` on the controller;
   the steward's build-time keys in `strict` mode).
3. **Approval** — a human approved this exact version (`cfg module approve`).

## 2. Publishing a module

### 2.1 Create a publisher identity

```bash
cfg module keygen
```

Prints the seed, the public key and the public key SHA-256 fingerprint once. Nothing is
written to disk.

- Store the **seed** in the publisher's secret manager. Never commit it to a repository,
  never write it to a file in a repository, and never pass it as a command argument — the
  CLI has no seed flag and no key-file flag on purpose.
- The public key and fingerprint are not secret; the controller operator needs them
  (section 3).
- The well-known development seed is refused by `cfg module bundle build`.

To re-derive the public key and fingerprint from an existing seed:

```bash
<secret-manager-cli> get publisher-seed | cfg module pubkey --seed-stdin
```

### 2.2 Write the manifest

`module.yaml` is the publisher's manifest and is copied into the bundle byte for byte
(the content hash covers its bytes). It must name:

- `publisher` — the publisher name you will register on the controller, matching
  `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`. The name `cfgms` is reserved.
- `name` — the module name (same character rules). A name in the stdlib set
  (`file`, `service`, `package`, `script`, `firewall`, `patch`, `user`, `cert_trust`,
  `time`, `hostname`) is reserved for the `cfgms` publisher.
- `version` — an exact semantic version such as `1.2.0`, with no `v` prefix.
- `executors` — exactly one kind (for example `steward`).

### 2.3 Build the bundle

Supply the seed on **stdin** (preferred). An environment variable
(`CFGMS_PUBLISHER_SEED`) also works, but it is readable by other processes of the same
user and inherited by child processes.

```bash
<secret-manager-cli> get publisher-seed | cfg module bundle build --seed-stdin \
    --manifest module.yaml \
    --binary linux-amd64=dist/linux-amd64/mymod \
    --binary linux-arm64=dist/linux-arm64/mymod \
    --binary windows-amd64=dist/windows-amd64/mymod.exe \
    --out ./bundle-root
```

| Flag | Meaning |
|------|---------|
| `--manifest` | Path to the publisher's `module.yaml` |
| `--binary <os>-<arch>=<path>` | One per platform; repeatable. `os` is `windows`, `darwin` or `linux`; `arch` is `amd64` or `arm64` |
| `--out` | Installation root to create. It must not already exist |
| `--seed-stdin` | Read the seed from stdin instead of `CFGMS_PUBLISHER_SEED` |

The command is local; it never contacts the controller. It prints the publisher name,
the content hash and the public key fingerprint. Check the fingerprint against the
controller's trust entry.

**A third-party root carries every platform's binary.** Build one `--binary` per platform
you support. (Stdlib roots shipped in the steward installer stay single-platform.) The
steward downloads and installs only its own platform's binary; a bundle without a binary
for a steward's platform cannot be installed there.

### 2.4 Publish to a git source

The repository layout **is** the bundle root: `--out` produces the files that sit at the
top of the repository.

```
module.yaml
bundle.yaml
cfgms-module-mymod-linux-amd64   # binaries, at the paths bundle.yaml records
...
```

Rules the controller enforces when it fetches:

- One repository per module, at `<base>/<name>` where `<base>` comes from the
  publisher's `module_sources` entry.
- Commit the contents of `--out` at the repository root, and nothing else besides `.git`.
  Extra files are refused.
- Tag the commit with the **exact manifest version, no `v` prefix** — manifest version
  `1.2.0` is tag `1.2.0`. Only tags are fetched; branches, `HEAD`, commit ids and
  `v1.2.0` are refused.
- The source base URL must be `https://` or `ssh://`. `file://`, `http://`, `git://` and
  scp-style paths are refused.

```bash
git add module.yaml bundle.yaml <binaries>
git commit -m "mymod 1.2.0"
git tag 1.2.0
git push origin 1.2.0
```

A published version is immutable. To change anything — a binary, the manifest — build and
tag a new version.

### 2.5 Point the controller at the source

In `controller.cfg`:

```yaml
module_sources:
  acme-corp:
    type: git
    base: https://git.example.com/acme-corp
```

The clone URL for `acme-corp/mymod@1.2.0` is `https://git.example.com/acme-corp/mymod`.
Private repositories use the controller's environment for credentials and trust roots:
`GIT_SSL_CAINFO` for an internal CA and `GIT_SSH_COMMAND` for ssh options. Host keys are
checked normally and no prompts are possible.

## 3. Trusting a publisher

Publisher trust on the controller is declared in `controller.cfg`:

```yaml
module_trust:
  publishers:
    - name: acme-corp
      public_key: "<base64 of the 32-byte Ed25519 public key>"
```

Match the entry to the publisher's output of `cfg module keygen` / `cfg module pubkey`.
Compare fingerprints out of band — the `fingerprint` printed by `cfg module pubkey` must
equal the SHA-256 the controller logs at startup
(`Module trust: publisher trusted from controller.cfg`) and the first 12 hex characters
shown in `cfg module list`.

**The set changes only by editing the controller config file and restarting.** No API,
CLI command, config-store key or `cfg push` field adds, changes or removes a publisher.
Trust is global to the controller. The baked-in `cfgms` publisher is always present in a
release build and may not be redeclared.

An invalid entry stops the controller from starting. See section 7.

### Steward build variable (strict mode)

A steward in `strict` mode (section 6) verifies signatures itself against keys compiled
into its binary. Third-party publisher keys reach a steward only through the build
variable:

```bash
make build-steward STEWARD_ADDITIONAL_PUBLISHER_KEYS=acme-corp=<base64-ed25519-pub>
# several publishers, comma separated
make build-steward STEWARD_ADDITIONAL_PUBLISHER_KEYS=acme-corp=<b64>,vendor-a=<b64>
```

`steward.cfg` then names which of those compiled-in publishers to honour:

```yaml
module_trust:
  mode: strict
  additional_publishers:
    - acme-corp
```

`steward.cfg` can name a publisher but cannot supply or change key material. An
`additional_publishers` name with no compiled-in key fails with
`ErrAdditionalPublisherUnresolvable`.

## 4. Approving a module

The first time a `required_modules` entry names a module the controller has not cached,
the controller fetches the bundle from its source, evaluates it and stores it. Every
version waits for a human, whether or not the publisher is trusted:

| Bundle | Result |
|--------|--------|
| No signature at all | `rejected` — never queued, never approvable |
| Publisher in the trust store, no signature verifies | `rejected` |
| Publisher in the trust store, signature verifies | `pending` |
| Publisher not in the trust store | `pending` (signature shown as `unverifiable`) |

List and inspect:

```bash
cfg module list
cfg module list --status pending
cfg module list --status rejected
cfg module list --json
```

The `SIGNATURES` column for a pending bundle shows who signed, the first 12 hex
characters of the key fingerprint, and:

- `valid` — trusted publisher, signature verifies.
- `invalid` — trusted publisher, signature does not verify.
- `unverifiable` — the publisher is not in the trust store. Verify the publisher out of
  band before approving. `--json` adds the full fingerprint and signed content hash.

Approve:

```bash
cfg module approve acme-corp/mymod@1.2.0
cfg module approve acme-corp/mymod@1.2.0 --content-hash <hash or unambiguous prefix>
```

- A bundle cache entry is keyed by content hash, so one `publisher/name@version` can
  match more than one pending bundle. The command then fails and lists each candidate
  hash; rerun with `--content-hash` naming the one you reviewed. The approved hash is
  echoed on success.
- Only `pending` entries can be approved. A bundle that carries no signature can never be
  approved.
- Each version needs its own approval.

**Step-up presence.** `module:approve` requires proof that the administrator touched
their security key for this specific approval. `cfg module approve` handles it: it prints
a short confirmation code and a URL on the controller's web origin
(`https://<controller>/cli/presence?request_id=<id>`). Open the URL, confirm the code and
the displayed action (permission, method, path, body digest) match your terminal, and
complete the security-key prompt. The command then continues. API-key and other machine
principals cannot approve.

All `cfg module` commands accept `--url` (or `CFGMS_API_URL`), `--tls-ca-cert` and
`--server-name`; do not use `--tls-insecure` against a production controller.

## 5. How stewards get modules

A steward receives modules by declaration in its configuration:

```yaml
required_modules:
  - name: "acme-corp/mymod"   # publisher/name
    version: "1.2.0"          # exact version
```

- Versions are **exact**. Ranges (`^1.0.0`), aliases (`latest`) and a `v` prefix are
  refused at `cfg push`.
- **Stdlib modules are excluded.** A name in the stdlib set is provided by the steward
  installer and is never fetched; declaring one in `required_modules` makes its
  resources fail with "provided by the installer, not by required_modules".
- At `cfg push` the controller checks every entry. Entries not yet cached are fetched and
  queued; the push is blocked until all entries are approved
  (`cfg deployment blocked: module <name>@<version> requires approval before deploying`).
  Approve, then push again.
- On config apply, the steward compares each entry with its installed bundles. A module
  not installed at exactly that publisher, name and version is pulled over its mTLS
  connection with `FetchModuleBundle`, for the steward's **own platform only**. The
  controller serves it only when the steward's own effective configuration requires that
  exact publisher/name/version and the bundle is approved.
- The steward verifies the received bytes, applies its trust mode, installs the tree and
  loads the module in the same apply. A failed pull fails only the resources of that
  module; other resources still converge.

Installed trees live at `C:\Program Files\CFGMS\modules\<name>\` (Windows) and
`/usr/local/lib/cfgms/modules/<name>/` (Linux and macOS).

## 6. Trust modes

`steward.cfg`:

```yaml
module_trust:
  mode: controller   # strict | controller | bypass
```

| Mode | What the steward does |
|------|-----------------------|
| `controller` (default) | Accepts a bundle the controller delivered. Still checks hashes and identity locally |
| `strict` | Verifies a publisher signature itself against compiled-in keys (the `cfgms` key and `STEWARD_ADDITIONAL_PUBLISHER_KEYS` named by `additional_publishers`) |
| `bypass` | No signature enforcement. Development only; logs a warning |

**`controller` mode trusts the controller's approval; `strict` is the control that holds
if the controller or an admin account is compromised.** In `controller` mode, anyone who
can edit `controller.cfg` trust or complete an approval can place a binary on stewards.
In `strict` mode the steward refuses any bundle whose publisher key was not compiled into
that steward build, regardless of what the controller approved.

Lowering the mode (for example `strict` to `controller`) through configuration inheritance
is refused unless `authorize_downgrade: true` is set at the same level; the stronger mode
continues to apply and the refusal is audited.

## 7. Troubleshooting

Find the symptom, then the cause. Messages are matched by the error name or text.

### Controller will not start

| Error | Cause and fix |
|-------|---------------|
| `ErrModuleTrustEmptyName` | A `module_trust.publishers` entry has no `name`. The message gives the entry index |
| `ErrModuleTrustReservedName` | Entry uses `cfgms`, reserved for the baked-in identity. Pick another publisher name |
| `ErrModuleTrustDuplicateName` | Two entries share a name |
| `ErrModuleTrustBadBase64` | `public_key` is not standard base64 |
| `ErrModuleTrustBadKeyLength` | `public_key` does not decode to 32 bytes. Use the output of `cfg module pubkey`, not the seed |
| `ErrModuleTrustUnusableKey` | The key is a weak or placeholder point (for example all zeros) |
| `ErrModuleSourceBadBase` | A `module_sources` base is not an absolute `https://` or `ssh://` URL with a host, or carries credentials, a query or a fragment |

Fix `controller.cfg` and restart.

### `cfg push` is blocked or fails

| Message | Cause and fix |
|---------|---------------|
| `ErrVersionNotExact` ("required module version must be an exact version") | `required_modules` has a range, `latest` or a `v` prefix. Use `1.2.0` |
| `cfg deployment blocked: module <name>@<version> requires approval before deploying` | The bundle is `pending` or `rejected`. Run `cfg module list`, then `cfg module approve`. If `rejected`, see "Bundle is rejected" below |
| `no module source configured for publisher "..."` | Add the publisher to `module_sources` and restart |
| `unsupported source type` | `type` must be `git` |
| `tag "<version>" not found on module source` | The tag must equal the manifest version exactly, with no `v`, and must be pushed |
| `module source is unreachable or refused the request` | Network, credentials, TLS trust or ssh host key. Check `GIT_SSL_CAINFO` / `GIT_SSH_COMMAND` in the controller's environment. Details are in the controller log; the message deliberately omits the URL |
| `source base URL must be an absolute https:// or ssh:// URL` | Change the `module_sources` base |
| `module manifest publisher/name/version "..." does not match requested ...` | The manifest in the tagged commit disagrees with the reference. Re-tag a corrected new version |
| `module signature publisher "..." does not match manifest publisher` | The bundle was signed under a different publisher name than its manifest. Rebuild with the matching manifest |
| `ErrSidecarMissing`, `ErrSidecarMalformed`, `ErrManifestMissing`, `ErrManifestInvalid` | The repository root is not a bundle root. Commit the contents of `--out` at the root |
| `ErrUnexpectedEntry`, `ErrNotRegularFile`, `ErrBundleTooLarge` | Extra files, symlinks or oversize files at the repository root. Keep only bundle files |
| `ErrContentHashMismatch`, `ErrDigestListInvalid` | The files do not match `bundle.yaml`. Rebuild with `cfg module bundle build` and tag a new version |
| `ErrContentAddressConflict` | A different bundle for this `publisher/name@version` is already cached. A published version cannot change; publish a new version |
| `ErrContentHashIdentityConflict` | This content hash is already recorded under a different publisher/name/version. Publish a build with its own identity |

### `cfg module approve` fails

| Message | Cause and fix |
|---------|---------------|
| `not found in pending approval queue` | Nothing is pending for that ref. `cfg module list`; it may already be approved or rejected, or the controller has not fetched it (run a `cfg push`) |
| `matches N pending bundles; re-run with --content-hash` | Choose the reviewed hash from the list |
| `ErrNotQueued` ("module is not queued for review") | Entry is already `approved` or `rejected`; the message names the current status |
| `ErrNoSignature` ("module bundle carries no signature and cannot be approved") | There is no override. Rebuild with `cfg module bundle build` and publish a new version |
| `401` with a presence challenge | Normal: complete the security-key step at the printed URL |

### Bundle is rejected

A bundle is `rejected` when it has no signature, or when its publisher is trusted and none
of its signatures verifies. **A trusted publisher's bad signature permanently rejects
that publisher/name/version — publish a new version.** The content address is immutable;
re-tagging or re-pushing the same version does not reset it. Check the signing seed and
the controller's `module_trust` key with `cfg module pubkey`, rebuild, and tag the next
version.

### Steward does not get the module

The controller answers every refusal of a bundle fetch with the same `module bundle not
found` so that the response reveals nothing; the real reason is in the controller log
line `Module bundle fetch refused`:

| `reason` in the log | Fix |
|---------------------|-----|
| `steward not registered to a tenant` | Register the steward |
| `module not required by the steward's configuration` | The steward's effective config does not list that exact publisher/name/version. Push the config |
| `bundle not in cache` | Never fetched. Run `cfg push` |
| `bundle not approved (pending)` or `(rejected)` | Approve it, or publish a new version |
| `bundle payload unreadable or altered` | The controller's stored bytes failed re-verification against the signed digests. Publish a new version |
| `bundle has no binary for the platform` | The bundle lacks the steward's `<os>-<arch>`. Rebuild with that `--binary` and publish a new version |

### Steward install errors

Reported per module in the steward's `ConfigStatusReport` and logs as
`required module <publisher/name@version> could not be installed: ...`.

| Error | Cause and fix |
|-------|---------------|
| `ErrFetchFailed` | Stream failed or was cut short; connectivity. The next config apply retries |
| `ErrStreamInvalid`, `ErrDigestListInvalid` | The stream broke the protocol, or has no digest for this platform |
| `ErrBinaryDigestMismatch`, `ErrContentHashMismatch` | Received bytes differ from what was signed. Treat as a security event; investigate the controller cache |
| `ErrIdentityMismatch` | Manifest publisher, name or version differs from the request |
| `ErrTrustRefused` | Trust policy refused the bundle. In `strict` mode, see below |
| `ErrStdlibName` | A non-`cfgms` publisher used a stdlib module name. Rename the module |
| `ErrPublisherMismatch` | The module name is already installed from a different publisher |
| `ErrInstallFailed` | Local write failure; check disk space and permissions on the module root |

`ErrTrustRefused`, `ErrBinaryDigestMismatch`, `ErrContentHashMismatch` and
`ErrIdentityMismatch` are reported with a `security failure:` prefix and the steward does
not retry that exact module and version until the next config sync delivers a new
configuration.

In `strict` mode, `ErrTrustRefused` means no signature verified against a compiled-in
key. Check that the publisher is named in `module_trust.additional_publishers` and that
the steward was built with that publisher in `STEWARD_ADDITIONAL_PUBLISHER_KEYS`. The
wrapped cause says which check failed:

- `ErrPublisherNotTrusted` — the publisher name is not known to the steward.
- `ErrKeyMismatch` or `ErrInvalidSignature` — the compiled-in key or the signature is wrong.
- `ErrUntrustedPublisherKey` — the steward carries the all-zero placeholder key; a default
  `make build-steward` build refuses every bundle.
- `ErrAdditionalPublisherUnresolvable` — a name in `additional_publishers` has no
  compiled-in key.

Rebuild the steward with the correct key variable; the config file cannot fix this.

**Windows: a module in use.** On Windows a running module holds its binary open, so
replacing it with a new version fails with `ErrModuleInUse` ("installed module is in use
and cannot be replaced"). The old version is left intact and working, and the next
configuration apply retries. No action is needed unless it persists; then stop the
resources that use the module or restart the steward.

### Module installed but will not load

| Error | Cause and fix |
|-------|---------------|
| `ErrTreeNotProtected` | The module tree is writable by non-administrators. Restore ownership by root/SYSTEM/Administrators and remove user-write permissions on the module root; the steward refuses to run unprotected binaries |
| `ErrContentHashMismatch` / `ErrUnexpectedEntry` (load-time) | A file under the module tree changed or an unexpected file appeared after install. Investigate the host; remove the module directory so the next apply reinstalls it |
| `ErrNoInstallRoot` | The bundle has no installation root; reinstall |
| `ErrWrongModuleKind` | The module's `executors` is not `steward` |

## Related

- [Module Distribution Architecture](../architecture/modules/distribution.md)
- [Steward Configuration](../architecture/steward-configuration.md)
- [ADR-006: Module Packaging and Distribution](../architecture/decisions/006-module-packaging-and-distribution.md)
