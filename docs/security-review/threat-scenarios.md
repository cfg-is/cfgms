# CFGMS threat scenarios

Product-level companion to [`methodology.md`](methodology.md). That document says what to call a
finding. This one says what to look for.

Each scenario states a property that must hold. None describes current behaviour — a sweep reports
that. A sweep finding that a property does not hold produces a finding, triaged into its own issue,
never a note added here.

## Editing rules

- One scenario per `scenario:begin` / `scenario:end` block. Only text between the markers is loaded.
- `id` is stable forever. It appears in coverage reports and the regression corpus. Retire, never reuse.
- `tier` is a `methodology.md` attacker tier. `boundary` is a `methodology.md` trust boundary.
- `keys` are fallback lexical hints, used only when no step assignment exists.
- Three fields, in order: **Must hold**, **Why**, **Check**. No status, no dates, no issue numbers.
- Name packages, not line numbers. Name no third-party vendor. Give no exploit detail.

---

## Boundary 1 — internet to REST/gRPC listener

<!-- scenario:begin id=TS-01 tier=T0 boundary=internet-listener keys=route,handler,api,rest,unauthenticated,middleware,permission -->
**Every administrative route requires authorisation, and the permission names the object the handler touches.**

- **Why:** an unchecked route exposes every tenant to a party with no credential. A permission naming
  the wrong object is the same defect wearing a check.
- **Check:** in the controller's HTTP API package, find routes registered without the permission
  wrapper, or wrapping a resource or action the handler does not operate on.
<!-- scenario:end -->

<!-- scenario:begin id=TS-02 tier=T0 boundary=internet-listener keys=tls,mtls,verify,handshake,quic,transport,certificate,chain -->
**No connection is usable unless the peer's certificate chain verified.**

- **Why:** a steward trusting a false controller accepts configuration and module bundles from it.
  One network party with no credential reaches the whole fleet.
- **Check:** every client-side TLS configuration in the certificate package and the QUIC transport
  adapter — verification callback, minimum version, and whether any error branch still yields a
  usable connection.
<!-- scenario:end -->

<!-- scenario:begin id=TS-03 tier=T0 boundary=internet-listener keys=input,validation,decode,parse,yaml,json,protobuf,deserialize,traversal -->
**Untrusted request content is validated before its first use.**

- **Why:** validation after first use is not a control. The damage is done by the use.
- **Check:** for each controller handler, whether a decoded value reaches a file path, store key,
  tenant lookup or command argument before the protobuf validators run on it.
<!-- scenario:end -->

---

## Boundary 2 — enrolled steward to controller

<!-- scenario:begin id=TS-04 tier=T1 boundary=steward-to-controller keys=registration,enrollment,token,regtoken,join,pending,identity -->
**A registration token enrols exactly what it was issued for, exactly once.**

- **Why:** anything that can enrol becomes a steward, receives configuration, and holds an identity
  other components trust. Enrolment is the widest door in the system.
- **Check:** in the registration package and its stores — is consumption atomic with use, or after
  it? Is expiry enforced at redemption or only at issue? Can one token yield two identities? Does
  approval compare the approving identity against the one recorded at request time?
<!-- scenario:end -->

<!-- scenario:begin id=TS-05 tier=T1 boundary=steward-to-controller keys=secret,sops,keychain,config,distribute,fetch,scope,steward -->
**A steward receives only the secret material addressed to it.**

- **Why:** distributing secrets to endpoints is the product's core function. One endpoint reading its
  neighbours' secrets turns a single host compromise into a fleet compromise.
- **Check:** in the configuration transport handler, fleet storage and secrets providers — does the
  response scope come from the verified connection identity or from the request? Is decrypted
  material cached, and under a key the caller controls?
<!-- scenario:end -->

<!-- scenario:begin id=TS-06 tier=T1 boundary=steward-to-controller keys=log,sanitize,inject,steward,report,status,error -->
**Steward-reported data is neutralised before the controller records it.**

- **Why:** a steward host may already be compromised, so what it reports is attacker-controlled text,
  and the controller's log is what an operator reads to decide what happened.
- **Check:** controller-side log and audit calls mixing a sanitised identifier with a bare error
  value. The error carries the tainted input back out inside its message.
<!-- scenario:end -->

---

## Boundary 3 — tenant admin to another tenant

<!-- scenario:begin id=TS-07 tier=T2 boundary=tenant-to-tenant keys=tenant,path,prefix,selector,scope,inherit,hierarchy -->
**Tenant scope comes from the authenticated principal and compares by path segment.**

- **Why:** a string prefix test makes `root/msp-a` match `root/msp-ab`. Sibling and ancestor
  isolation is the guarantee a multi-tenant platform sells.
- **Check:** scope comparisons using a string prefix on a joined path rather than segment equality.
  In the fleet selector, whether a parsed tenant prefix authorises, or only filters inside a scope
  the principal already holds. The second is correct.
<!-- scenario:end -->

<!-- scenario:begin id=TS-08 tier=T2 boundary=tenant-to-tenant keys=inherit,resolve,hierarchy,parent,child,config,merge,override -->
**Configuration inheritance resolves root to leaf in every path that resolves it.**

- **Why:** a resolver walking the other way lets a descendant read or override what sits above it —
  lateral movement up the tenant tree with no handler being wrong.
- **Check:** trace one key from leaf to root through the tenant stores and config resolution. Which
  end wins on conflict, and is it the same end in every path? One path disagreeing is the defect.
<!-- scenario:end -->

---

## Boundary 4 — module publisher to the hosts that run the module

<!-- scenario:begin id=TS-09 tier=P boundary=publisher-to-host keys=signature,verify,publisher,bundle,ed25519,trust,key -->
**Signature verification fails closed, and no pushed value can disable it.**

- **Why:** this is the control between an untrusted publisher and code execution on every endpoint.
  A trust mode reachable from the controller also removes the bound that makes controller compromise
  survivable.
- **Check:** in the module trust package and the steward-side trust plumbing — every success return
  in verification, reachable without a signature having been checked? An absent or empty signature
  treated as valid? The bypass mode selectable by anything but local development configuration?
<!-- scenario:end -->

<!-- scenario:begin id=TS-10 tier=P boundary=publisher-to-host keys=version,rollback,downgrade,bundle,stale,cache,module -->
**A host never accepts a module older than the one it already runs.**

- **Why:** an old bundle passes every signature check by definition — it was genuinely signed.
  Replaying one reintroduces whatever a newer version fixed, fleet-wide, using material the attacker
  already has.
- **Check:** in bundle installation and the controller's module cache and approval path — is there
  an ordered version comparison at install, or only a signature check? Can the cache serve a bundle
  older than the one a host runs?
<!-- scenario:end -->

<!-- scenario:begin id=TS-11 tier=T3 boundary=publisher-to-host keys=resign,forward,signature,controller,intact,strip -->
**Publisher signatures reach the steward intact; the controller never re-signs.**

- **Why:** end-to-end signing is what makes independent steward verification mean anything. A
  controller that re-signs converts strict verification into "trust the controller".
- **Check:** any controller-side path that constructs a signature rather than copies one. Whether
  the publisher identity compiled into the steward binary is read from anywhere writable at runtime.
<!-- scenario:end -->

---

## Boundary 5 — controller to steward

<!-- scenario:begin id=TS-12 tier=T2 boundary=controller-to-steward keys=fleet,selector,filter,apply,push,scope,blast,bulk -->
**One action reaches only what the principal is authorised for, and a bounded number of endpoints.**

- **Why:** this is the outcome that turns a management platform into a distribution channel. It is a
  missing bound rather than a defect, so no single handler looks wrong.
- **Check:** in the fleet selector and the operation path that applies a resolved set — at which step
  is the set intersected with the caller's scope? Filtering after resolution means the wider set
  existed. Is there any ceiling on one operation, or staging between a subset and the remainder?
<!-- scenario:end -->

<!-- scenario:begin id=TS-13 tier=T2 boundary=controller-to-steward keys=availability,converge,rollback,brick,recover,safe,config -->
**A steward refuses a configuration that would sever its own control-plane connection.**

- **Why:** losing remote access to an entire estate at once is catastrophic with no confidentiality
  loss at all. The resource-exhaustion class is scoped to a lower-trust party, so a tenant admin
  destroying their own estate falls outside it.
- **Check:** in the convergence loop and the rollback feature — can a converged configuration disable
  the transport needed to receive the next one? Is the refusal explicit? Does rollback require the
  controller to be reachable?
<!-- scenario:end -->

<!-- scenario:begin id=TS-14 tier=T1 boundary=controller-to-steward keys=script,stage,execute,interpreter,argv,path,symlink,lolbin -->
**Nothing a local unprivileged user controls influences what the steward executes.**

- **Why:** the steward runs privileged, and endpoints are assumed to be where attackers already are.
  Anything a local user can steer is a privilege escalation.
- **Check:** in the script module and the steward client's staging path — staging directory
  permissions, the window between hash verification and execution, whether any path is opened
  without rejecting symlinks, and whether any argument reaches an interpreter inside a composed
  string rather than as its own argv element.
<!-- scenario:end -->

---

## Cross-cutting

<!-- scenario:begin id=TS-15 tier=T2 boundary=cross-cutting keys=audit,log,tamper,delete,forensic,append,immutable,redact -->
**The principal that writes an audit entry cannot alter or remove it.**

- **Why:** if the record is editable by the party being investigated, incident response fails and
  every other control becomes unverifiable after the fact.
- **Check:** in the audit manager's drain and batch-write path, its redaction rules, and the audit
  stores — can the writing principal delete or update an entry through any store path? What happens
  to a buffered batch on unclean shutdown? Does redaction ever remove actor identity?
<!-- scenario:end -->

---

## Extending this file

New trust boundaries get new scenarios; existing ones are not rewritten as code changes, because
none of them describes code. The inline `cfg` command path and the interactive remote-shell path are
each their own boundary and want their own scenarios once they exist.
