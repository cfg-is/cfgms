# Security review methodology

This document is the review methodology every finder lane of the security review
harness is held to. It states what CFGMS considers a security defect, who the attacker
is assumed to be, and what `critical`, `high`, `medium` and `low` mean here. A human
owns it. It is not generated, and it must not be edited by an autonomous agent: a
miscalibrated rubric degrades every future sweep in the same direction, every lane
agrees with every other lane because they were all told the same wrong thing, and no
test can detect that.

Two audiences read it:

- **Operators** triaging a consolidated report, who need to know what a severity in the
  report means and which attacker it assumes.
- **Finder lanes**, which receive parts of this document inside every step prompt
  through `harness_runner.py`. The lanes never read this file directly; the harness
  runner does, once, at import, and hands the same text to every lane.

## How this document reaches a finder lane

The document is split into two kinds of content, marked with HTML comments that
`.claude/scripts/security-review/lanes/harness_runner.py` parses:

- **The compact core**, between the `methodology-core:begin` and `methodology-core:end`
  HTML comments. It is inlined into every step prompt of every lane,
  between the shared system prompt and the shared output-schema description. It has a
  character ceiling, `METHODOLOGY_CORE_MAX_CHARS`, enforced when the document is
  loaded and asserted by `harness_runner_test.py`. The ceiling exists because the core
  is paid once per step per lane, at roughly 250 steps per lane.
- **Worked examples (severity anchors)**, each between an `anchor:begin` and an
  `anchor:end` HTML comment, the opening one carrying an `id`, a `severity` and a comma-separated `tags`
  list. For every step, `harness_runner.select_anchors()` picks exactly one anchor per
  severity level: the anchor whose tags overlap most with the step's own scope, files,
  description and hypotheses, ties broken by document order. The selection is a pure
  function of the step's content and this document, so the same step always receives
  the same anchors. Each anchor has its own ceiling, `ANCHOR_MAX_CHARS`.

Everything outside those markers, including this section, is for human readers only and
never reaches a prompt.

There is one copy of this text, here. `harness_runner.py` holds the only loading code
and the only constants (`METHODOLOGY_CORE`, `METHODOLOGY_ANCHORS`), and every lane's
`build_prompt` calls `harness_runner.shared_preamble(step)` rather than assembling its
own. A test fails if a second definition appears anywhere under
`.claude/scripts/security-review/`. The choices behind this shape, and the alternatives
that were rejected, are recorded in
[`docs/architecture/security-review-harness.md`](../architecture/security-review-harness.md)
under *Review methodology: compact core and per-step anchors*.

### Editing rules

- Keep the marker comments exactly as they are. The loader fails closed on a missing or
  duplicated marker, and the lanes then do not start.
- Never write a full marker comment anywhere else in this file, not even in prose or in
  backticks. The loader counts exact occurrences, and a second one is a duplicate.
- Keep the core under its ceiling and every anchor under its ceiling. The loader
  rejects an oversized core or anchor; the tests say which.
- Keep at least two anchors per severity level. The loader rejects a level with fewer.
- Give a new anchor a unique `id` and tags that name the subsystem it is about, in the
  words a plan step's scope, file paths and hypotheses would use (`cert`, `tenant`,
  `module`, `registration`, `log`). Tags are matched as whole lower-case tokens after
  splitting paths and camel-case identifiers.
- Any change to the core or to an anchor changes `prompt_version` on every envelope
  written afterwards, so a sweep spanning the change is visible as such.

<!-- methodology-core:begin -->
## Threat model

CFGMS is a zero-trust, multi-tenant configuration management system. A **controller**
(central, SaaS or on-premises) manages **stewards** (agents on Windows, Linux and macOS
endpoints) over mutual-TLS gRPC-over-QUIC. Administrators reach the controller through a
REST API and the `cfg` CLI using an mTLS bundle. Tenants form a tree
(`root/msp-a/client-1`); configuration inherits root to leaf. Storage is git with SOPS
encryption by default; secrets live in the OS keychain or SOPS, never in cleartext on
disk. Modules are publisher-signed out-of-process binaries; the controller verifies and
forwards signatures intact and never re-signs.

Standing assumptions. Judge every finding against them:

1. **Any steward host may already be compromised.** Root on one endpoint is the
   attacker's starting position, not a prize. The boundary that matters is between that
   steward and everything else: the controller, other stewards, other tenants.
2. **Admin accounts may be phished or taken over for short periods.** Rarely-touched
   settings (`module_trust.mode: strict`, additional trusted publishers, publisher
   revocations) exist to bound what a compromised admin or a compromised controller can
   do to endpoints. A defect that lets an attacker weaken or bypass one of those bounds
   is judged by the blast radius the bound was meant to contain.
3. **Endpoints run application allowlisting and EDR.** Code CFGMS runs on an endpoint
   must behave like predictable admin tooling: declared paths, signed binaries, no
   runtime code composition (`iex`, `bash -c "<string>"`, `eval`, `-EncodedCommand`).
4. **A tenant must never read or affect a sibling or ancestor tenant.** Tenant identity
   comes from the authenticated principal, never from a client-supplied path.

Trust boundaries, in decreasing attacker distance: internet to REST/gRPC listener;
enrolled steward to controller; tenant admin to another tenant; module publisher to the
hosts that run the module; controller to steward (bounded by trust modes and end-to-end
signatures).

## Vulnerability classes in scope

Set `vuln_class` to exactly one identifier from this list, or to `other: <short label>`
when none fits. The escape is allowed and expected. Never force a finding into the
nearest identifier, and never drop a finding because no identifier fits.

| Identifier | Class | Typical CFGMS surface |
|---|---|---|
| CWE-295 | Improper certificate validation | mTLS chain, hostname, expiry or revocation checks skipped |
| CWE-287 | Improper authentication | gRPC/REST boundary, registration tokens |
| CWE-306 | Missing authentication for critical function | unauthenticated admin or fleet operation |
| CWE-862 | Missing authorization | handler with no permission check |
| CWE-863 | Incorrect authorization | tenant scoping, prefix or path confusion, wrong principal |
| CWE-269 | Improper privilege management | implicit admin, escalation through inheritance |
| CWE-347 | Improper signature verification | module bundles, signed admin commands, payload markers |
| CWE-345 | Insufficient data authenticity | unsigned or stale configuration accepted |
| CWE-613 | Insufficient session or credential expiration | tokens, leases, certificates accepted past their window |
| CWE-330 | Insufficiently random values | tokens, identifiers, nonces |
| CWE-798 | Hard-coded credentials | any credential in source or fixtures |
| CWE-312 | Cleartext storage of sensitive information | secrets on disk, in caches, in temp files |
| CWE-532 | Sensitive information in log | secrets or tokens logged |
| CWE-117 | Log output neutralization | unsanitized steward or admin input in logs |
| CWE-209 | Sensitive information in error message | internal paths, identities, other tenants' data |
| CWE-78 | OS command injection | command construction, banned shell patterns |
| CWE-88 | Argument injection | attacker-controlled argv or flags |
| CWE-89 | SQL injection | any non-parameterized query |
| CWE-22 | Path traversal | tenant paths, module cache, file staging |
| CWE-59 | Link following | symlinks in staging, cache or convergence paths |
| CWE-502 | Deserialization of untrusted data | YAML, JSON, protobuf handled unsafely |
| CWE-20 | Improper input validation at a trust boundary | anything crossing a boundary above, unchecked |
| CWE-362 | Race condition, check-then-act | staging, atomic writes, convergence, leadership |
| CWE-400 | Uncontrolled resource consumption | only when a lower-trust party can trigger it |

## Severity rubric

Severity is **impact given the assumed attacker**. Confidence is a separate field; a
low-confidence critical is still critical. Name the attacker tier in `evidence`.

Attacker tiers:

- **T0 Network party.** Reaches a controller listener; holds no credential.
- **T1 Compromised steward.** Root on one enrolled endpoint; holds that steward's mTLS
  identity and registration material.
- **T2 Compromised tenant admin.** Holds a valid admin bundle or session for one tenant
  subtree, for a short window.
- **T3 Compromised controller or root admin.** The worst case the design bounds rather
  than prevents. A finding that needs T3 is `low`, unless the defect is in a control
  whose purpose is to bound T3; then judge it by the blast radius that control was meant
  to contain.
- **P Untrusted publisher.** Produces a module bundle whose publisher is not in the trust
  store.

Levels:

- **critical.** T0, T1 or P gains control of the controller, of stewards other than
  their own, or of another tenant: an unauthenticated or steward-credential path to
  admin capability; code execution on other endpoints; a cross-tenant write; an mTLS or
  signature verification bypass on the control path; unknown-publisher code running on
  an endpoint. Fleet-wide or cross-tenant, no user interaction, no precondition beyond
  the tier's starting position.
- **high.** T2 escapes the tenant subtree or one of the blast-radius bounds; T1 reads
  other stewards' or other tenants' secrets or configuration, or keeps access past
  revocation or expiry; T0 reads sensitive fleet data or cheaply takes the controller
  down. A cross-tenant read, or tenant-wide control beyond what the role grants.
- **medium.** Impact stays inside the attacker's own tenant or own host, but a stated
  control is violated: a privileged action without audit; a rarely-touched setting
  weakened without its designed friction; false state reported to the controller; a
  cleartext secret on the attacker's own disk; log injection from a T1 input; local
  user to root on one endpoint through a CFGMS-owned path.
- **low.** A defence-in-depth gap with no boundary crossing shown: validation missing
  where every caller is already T3; weak randomness behind another control;
  non-sensitive internals exposed; hardening misses. Report it anyway.

Moving a level. **Up one** if the required tier drops (T2 to T1, T1 to T0) or the scope
grows (own host, to own tenant, to cross-tenant, to fleet). **Down one** if it needs a
non-default insecure setting (`module_trust.mode: bypass` is development-only), or a
second independent control blocks it today; still report the finding, and name that
control.
<!-- methodology-core:end -->

## Worked examples (severity anchors)

Each example below is an **illustrative, CFGMS-shaped defect**, written to calibrate the
scale. None of them describes a known defect in the codebase. Each states what makes it
that level, which attacker tier it assumes, and what would move it one level up or
down. A lane receives one example per level, chosen by subject-matter overlap with its
step.

### Critical

<!-- anchor:begin id=crit-mtls-verify severity=critical tags=tls,mtls,cert,certificate,certs,ca,chain,quic,transport,handshake,verify,dial,client,server -->
**Steward-to-controller TLS accepts any server certificate.** The QUIC client
configuration for the steward's control-plane connection installs a verification
callback that returns success without checking the presented chain against the
controller CA. Attacker: T0, on the network path. Level: critical, because a network
party with no credential impersonates the controller and pushes configuration or module
bundles to every steward that connects through it, with no user interaction. Down to
high if the unchecked connection is a metrics or liveness probe that carries no
configuration and accepts no commands. It cannot move up; record the fleet-wide scope
in `evidence`.
<!-- anchor:end -->

<!-- anchor:begin id=crit-strict-mode-bypass severity=critical tags=module,modules,bundle,bundles,publisher,publishers,signature,signing,trust,trusted,strict,staging,cache,manifest,verify,approval -->
**`module_trust.mode: strict` trusts the bundle's own publisher list.** Steward-side
verification in strict mode reads the set of trusted publishers from the metadata of the
bundle it is verifying, instead of from the publisher identity baked into the steward
binary plus the steward's local additional-publishers setting. Attacker: T3 (a
compromised controller) together with P (any publisher). Level: critical. T3 would
normally lower severity, but strict mode exists exactly to bound a compromised
controller; when that bound fails, unknown-publisher code runs on every strict-mode
endpoint, which is the blast radius the setting was meant to contain. Down to high if
the defect affects only `controller` mode, where the steward delegates verification by
design. Down to low if it is reachable only under `bypass`.
<!-- anchor:end -->

<!-- anchor:begin id=crit-tenant-from-path severity=critical tags=tenant,tenants,path,subtree,inheritance,scope,principal,rest,api,handler,http,authorization,authz,admin,write,config -->
**A configuration write handler takes the tenant from the URL, not the principal.** A
REST handler resolves the target tenant from a client-supplied path segment and never
checks that it sits under the authenticated admin's own tenant subtree. Attacker: T2.
Level: critical: this is a cross-tenant write, so a phished admin of one client alters
configuration that deploys to another client's fleet. Down to high if the handler is
read-only, making it a cross-tenant read. Down to medium if a downstream store check
refuses the write today; report it and name that check.
<!-- anchor:end -->

### High

<!-- anchor:begin id=high-regtoken-replay severity=high tags=registration,regtoken,token,tokens,enrol,enroll,enrolment,enrollment,expiry,expires,reuse,replay,generator,store,device,identity -->
**A registration token is honoured after expiry or reuse.** The registration store
checks the token's signature but not its expiry or its single-use marker, so a captured
token enrols additional devices indefinitely. Attacker: T1, since a compromised steward
holds its own enrolment material. Level: high: the attacker mints additional certified
identities inside the tenant and gains a tenant-wide presence its one host never had. Up
to critical if the token is root-scoped or the new identity lands in a different tenant.
Down to medium if enrolment still requires an admin approval step before a certificate
is issued.
<!-- anchor:end -->

<!-- anchor:begin id=high-secrets-device-filter severity=high tags=secret,secrets,sops,keychain,dataplane,distribution,device,devices,steward,fetch,pull,credential,credentials -->
**A data-plane secret fetch filters by tenant but not by device.** The steward-facing
secret distribution endpoint returns every secret in the caller's tenant rather than only
the secrets targeted at the calling device. Attacker: T1. Level: high: a compromised
steward reads secrets meant for sibling stewards, so one host's compromise becomes
tenant-wide credential exposure. Up to critical if the filter also fails across tenants.
Down to medium if the values are non-privileged configuration rather than credentials.
<!-- anchor:end -->

<!-- anchor:begin id=high-signer-revocation severity=high tags=signing,signer,signature,revocation,revoke,revoked,rotation,rotate,command,commands,payload,marker,cursor,lifecycle,cert,certificate,mtls -->
**A signed admin command is accepted after the signer was revoked.** Command
verification checks the signature against the signing certificate embedded in the
command and never consults the revocation store or the current signing cursor.
Attacker: T2 whose access was revoked once a takeover was noticed. Level: high: the
attacker keeps issuing valid-looking commands to the tenant's stewards past the point
the operator believed access was cut off, defeating the recovery path the threat model
relies on. Up to critical if an accepted command can alter trust settings or run code
fleet-wide. Down to medium if the window is already bounded by a short certificate
lifetime enforced elsewhere.
<!-- anchor:end -->

### Medium

<!-- anchor:begin id=med-log-injection severity=medium tags=log,logs,logging,logger,sanitize,sanitizelogvalue,slog,hostname,inventory,telemetry,injection,audit -->
**A steward-reported hostname is written to controller logs unsanitized.** An inventory
handler logs the device's self-reported hostname raw, so newline and control characters
forge log entries. Attacker: T1. Level: medium: the attacker corrupts operator-facing
logs on the controller but crosses no confidentiality or integrity boundary for
configuration or secrets. Up to high if the log is the audit trail used for
authorization decisions or incident evidence, or if the injected text reaches another
tenant's view. Down to low if the value was validated to a strict character set before
it reached the logger.
<!-- anchor:end -->

<!-- anchor:begin id=med-cleartext-temp severity=medium tags=cleartext,plaintext,disk,temp,tmp,file,files,permissions,perm,mode,secret,credential,module,render,write -->
**A module renders a credential to a temp file with default permissions.** A steward
module writes a fetched credential to disk in cleartext before handing it to the managed
application, and leaves it readable by other local users. Attacker: a local user on that
same endpoint, below T1. Level: medium: the threat model already grants root on the host
to T1, so exposure on the attacker's own disk is not a boundary crossing, but "no
cleartext secrets on disk" is a stated control, and other local users gain a credential
they did not have. Up to high if the credential is tenant-wide, or the file survives
across runs on a shared host. Down to low if the material is the steward's own
certificate, already available to root.
<!-- anchor:end -->

<!-- anchor:begin id=med-convergence-symlink severity=medium tags=file,symlink,link,toctou,race,check,nofollow,convergence,converge,staging,atomic,rename,module,path,drift -->
**The file module follows a symlink when converging a managed path.** The file module
checks a path's state, then writes through it without a no-follow flag, so a local user
who controls a parent directory redirects the write. Attacker: a local non-root user on
one endpoint. Level: medium: local escalation to root on a single host through a
CFGMS-owned path, bounded to that host and needing a local foothold. Up to high if the
managed path is user-writable by default, or if T1 on one host can trigger the write on
another host. Down to low if the path is under a steward-owned, root-only directory.
<!-- anchor:end -->

### Low

<!-- anchor:begin id=low-error-disclosure severity=low tags=error,errors,message,response,http,status,disclosure,leak,notfound,path,handler -->
**A REST error response echoes an internal storage path.** A not-found error on an
unauthenticated endpoint includes the on-disk storage path and the tenant identifier
being looked up. Attacker: T0. Level: low: internal layout is exposed, but no
credential, no configuration and no other tenant's data. Up to medium if the message
includes another tenant's identifiers or values, or confirms a tenant's existence to a
T0 caller.
<!-- anchor:end -->

<!-- anchor:begin id=low-internal-validation severity=low tags=parse,parser,validation,validate,internal,helper,loader,config,unmarshal,decode,inheritance -->
**A controller-internal parser trusts its input.** A helper that parses stored
configuration accepts malformed values without validation, but every caller is
controller code reading controller-written storage. Attacker: T3 only. Level: low: a
defence-in-depth gap with no lower-tier path to the function. Up to medium if a T1 or T2
input reaches the helper through any route, including a stored value they can write.
<!-- anchor:end -->

<!-- anchor:begin id=low-weak-random-id severity=low tags=rand,random,randomness,entropy,identifier,uuid,nonce,job,jobs,generator,math -->
**A non-cryptographic random source for a job identifier.** A job id is generated with a
non-cryptographic source. It is unique enough for logging, is never used as a bearer
credential, and every operation on it is authorized by the caller's mTLS identity.
Attacker: any tier. Level: low: predictability buys nothing, because a second control
authorizes every use. Up to high if the same generator produces a token whose knowledge
alone grants access.
<!-- anchor:end -->

## What this document does not cover

- Which tools a lane may run inside a step. That is a harness concern, tracked
  separately.
- The finding schema. `vuln_class` carries the identifier chosen above until a dedicated
  field exists; the schema is defined once in `schema.py`.
- How the consolidator adjudicates severity when lanes disagree. This document gives
  every lane the same scale; reconciling their ratings is the consolidator's job.
