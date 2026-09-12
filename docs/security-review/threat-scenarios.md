# CFGMS threat scenarios

The product-level companion to [`methodology.md`](methodology.md). That document says what to
*call* a finding — attacker tiers, the CWE shortlist, the severity rubric. This one says what to
*go looking for*, in terms of this product's shape.

The distinction matters because a reviewer reasoning bottom-up from a file inventory produces
bottom-up guesses. Shown `pkg/session/token.go`, a model proposes weak token entropy. It does not
propose that a child tenant can resolve its parent's scope unless something tells it the tenant
model is a recursive path prefix. Scenarios are that something.

## Scenarios are normative, never descriptive

**Every scenario states a property that must hold, and why it matters if it does not.** None of
them describes what the code does today.

This is the rule that keeps the file alive. A scenario written as an observation — "this check is
missing", "this control was not found", "that work is recent" — is true for one commit and
misleading afterwards, and nobody trusts a document they have caught out. A scenario written as a
requirement stays correct whether the requirement is met, newly met, or regressed. It is the
*sweep* that reports the current state, every time it runs, against a catalogue that does not move.

So: no status, no "as of", no "not yet implemented", no issue numbers, no dates. If a sweep finds
that a required property does not hold, that is a **finding**, and findings go through triage into
their own issue. They never come back into this file.

## How this document is used

1. **A separate instruction to the planner.** The scenario list is given to the planner on its own,
   not folded into the lane methodology. The planner still receives no source: this file is prose
   the repository already ships.
2. **One or more dedicated steps per scenario — the scenario axis.** For each scenario the planner
   produces at least one `axis: scenario` step, pulling in whatever files bear on it **from
   anywhere in the repository**. That step is not about a package. It is about one thing going
   wrong. A finder lane working it stays as narrowly focused as it would on a package step, but
   focused on the risk instead of on a directory.
3. **Coverage becomes structural.** Because every scenario gets its own step by construction, a
   scenario cannot go unexamined. The check is an assertion that every id here has at least one
   step, not a gate that discovers a gap afterwards.
4. **Step id is the scenario id.** Two planner models produce a step with the same id for the same
   scenario, so their plans line up directly. What differs is which files each pulled in and what it
   asked — which makes file selection itself something to score.

**The planner chooses the files; this document does not.** A scenario says what must hold and
roughly where to look. Naming exact file sets here would go stale on every refactor and would
remove the most interesting part of the comparison.

This file is **not** part of `METHODOLOGY_CORE`, which is capped and refused by the loader above
that cap — the core is pasted into every step prompt, so each character there is paid roughly a
thousand times per sweep. Scenario text follows the severity-anchor model instead: a lane working a
scenario step receives that scenario and no others. The catalogue can therefore grow without bound,
and nothing here may ever be moved into the core.

## Editing rules

- One scenario per `scenario:begin` / `scenario:end` block. The markers are parsed; the prose
  between them is not.
- `id` is stable forever. It appears in coverage reports and in the regression corpus, so renaming
  one silently breaks both. Retire an id, never reuse it.
- `tier` is one of the `methodology.md` ladder: `T0`, `T1`, `T2`, `T3`, `P`.
- `boundary` is one of the trust boundaries named in `methodology.md`'s threat model.
- `keys` are lexical hints, used only as a fallback when no step assignment exists. Never the
  primary selection mechanism.
- **Must hold** is written as a requirement, in the present tense, with no hedging about whether it
  currently does.
- **Where to look** names packages and roles, not line numbers, and is a pointer for a planner
  rather than a contract. A wrong pointer costs one wasted lookup; a stale status claim costs the
  document's credibility.
- Name no real third-party vendor. Give no exploit-grade detail: a scenario says what must hold and
  why, never how to defeat it.

## Scenario format

**Must hold** — the requirement. **Why** — what is lost when it does not. **How it breaks** — the
shapes the violation takes, as a class rather than an instance. **Where to look** — packages and
roles. **Check** — the question a reviewer asks, which is what a planner turns into hypotheses.

---

## Boundary 1 — internet to REST/gRPC listener

<!-- scenario:begin id=TS-01 tier=T0 boundary=internet-listener keys=route,handler,api,rest,unauthenticated,middleware,permission -->
**Every administrative function requires authorisation, and the authorisation matches the object.**

- **Must hold:** no route that reads or changes tenant state is reachable without a permission check,
  and the resource and action demanded name the thing the handler actually touches.
- **Why:** an unauthorised administrative route exposes every tenant's configuration, fleet and
  secrets to a party with no credential at all. A permission that names the wrong object is the same
  defect wearing a check.
- **How it breaks:** a handler registered beside authorised ones inheriting nothing; a router whose
  middleware chain does not apply to a newly added subrouter; a wrapper naming a resource the
  handler does not act on.
- **Where to look:** the controller's HTTP API package — the permission middleware and the route
  registration files that call it.
- **Check:** enumerate registered routes and find any whose registration lacks the wrapper, or wraps
  a resource or action other than the one the handler operates on.
<!-- scenario:end -->

<!-- scenario:begin id=TS-02 tier=T0 boundary=internet-listener keys=tls,mtls,verify,handshake,quic,transport,certificate,chain -->
**No connection is usable unless the peer's certificate chain verified.**

- **Must hold:** every internal client path verifies the presented chain against the controller CA,
  and no error branch yields a working connection with verification reduced or skipped.
- **Why:** a steward that trusts a false controller accepts configuration and module bundles from it.
  One network party with no credential reaches the whole fleet.
- **How it breaks:** a verification callback that returns success unconditionally; a fallback path
  taken on handshake error; a minimum protocol version low enough to permit a downgrade.
- **Where to look:** the certificate package, and the QUIC transport adapter that builds client TLS
  configuration.
- **Check:** every TLS configuration construction on a client path — verification callback, minimum
  version, and whether any error branch produces a usable connection.
<!-- scenario:end -->

<!-- scenario:begin id=TS-03 tier=T0 boundary=internet-listener keys=input,validation,decode,parse,yaml,json,protobuf,deserialize,traversal -->
**Untrusted request content is validated before its first use, not after.**

- **Must hold:** a decoded value is validated at the boundary before it is used as a path, a query, a
  tenant identifier or a command argument.
- **Why:** validation that runs after first use is not a control. The damage is done by the use, and
  a later check only decides whether to report it.
- **How it breaks:** a body decoded straight into a structure passed onward; validation present in
  one handler and absent in its sibling; a path opened before it is confined.
- **Where to look:** the generated-message validators under the protobuf API definitions, and the
  controller handlers that are supposed to call them.
- **Check:** for each handler, is the decoded value validated before its first use? An unvalidated
  value reaching a file path, a store key or a tenant lookup is the finding, even where validation
  exists further down.
<!-- scenario:end -->

---

## Boundary 2 — enrolled steward to controller

<!-- scenario:begin id=TS-04 tier=T1 boundary=steward-to-controller keys=registration,enrollment,token,regtoken,join,pending,identity -->
**A registration token enrols exactly what it was issued for, exactly once.**

- **Must hold:** tokens are scoped, expiring and single-use; consumption is atomic with use; an
  approved registration binds to the identity that requested it.
- **Why:** anything that can enrol becomes a steward, receives configuration, and holds an identity
  other components trust. Enrolment is the widest door in the system.
- **How it breaks:** expiry enforced at issue but not at redemption; a token marked consumed after
  use rather than with it, leaving a replay window; an approval that does not compare the approving
  request against the identity recorded at request time.
- **Where to look:** the registration package — token generation, the token store, identity binding —
  and the registration and pending-registration stores in the storage providers.
- **Check:** is consumption atomic with use? Is expiry enforced at redemption? Can one token produce
  two identities? Does approval compare identities, or only tokens?
<!-- scenario:end -->

<!-- scenario:begin id=TS-05 tier=T1 boundary=steward-to-controller keys=secret,sops,keychain,config,distribute,fetch,scope,steward -->
**A steward receives only the secret material addressed to it.**

- **Must hold:** the scope of a configuration response derives from the authenticated identity of the
  connection, never from the request; decrypted material is never held where another recipient's
  request can reach it.
- **Why:** distributing secrets to endpoints is the product's core function, so this is a scoping
  property rather than a handler bug. One compromised endpoint reading its neighbours' secrets turns
  a single host compromise into a fleet compromise.
- **How it breaks:** a fetch scoped by a value the caller supplies; inheritance pulling an ancestor's
  secrets into a descendant's bundle; a shared decryption cache keyed by something a caller controls.
- **Where to look:** the controller's configuration transport handler, the fleet storage layer, and
  the secrets providers.
- **Check:** where does the scope for a response come from — the verified connection identity, or the
  request body? Is decrypted material cached, and under what key?
<!-- scenario:end -->

<!-- scenario:begin id=TS-06 tier=T1 boundary=steward-to-controller keys=log,sanitize,inject,steward,report,status,error -->
**Data reported by a steward is neutralised before the controller records it.**

- **Must hold:** every value that originated off-host is sanitised before it reaches a log line, an
  audit entry or an error message — including the text of errors returned from gRPC, store and decode
  calls.
- **Why:** a steward host may already be compromised. What it reports is attacker-controlled text,
  and the controller's log is what an operator reads to decide what happened.
- **How it breaks:** a sanitised identifier logged beside a bare error value. The error carries the
  caller's tainted input back out inside its message, so the sanitised field next to it proves
  nothing.
- **Where to look:** the logging package's sanitiser, and every controller-side handler that logs a
  steward-supplied value.
- **Check:** find log and audit calls mixing sanitised and unsanitised values in one statement.
<!-- scenario:end -->

---

## Boundary 3 — tenant admin to another tenant

<!-- scenario:begin id=TS-07 tier=T2 boundary=tenant-to-tenant keys=tenant,path,prefix,selector,scope,inherit,hierarchy -->
**Tenant scope comes from the authenticated principal and compares by path segment.**

- **Must hold:** tenant identity derives from the authenticated principal, never from a client-supplied
  path; scope comparison is segment-wise, never a bare string prefix.
- **Why:** a string prefix test makes one tenant's scope match another's whose name merely starts the
  same way. Sibling and ancestor isolation is the guarantee a multi-tenant platform sells.
- **How it breaks:** a joined path compared with a prefix test; a tenant path parsed out of a
  caller-supplied expression and then used to authorise rather than to filter within a scope already
  held.
- **Where to look:** the fleet selector's tenant-prefix parsing, the tenant stores in the storage
  providers, and the tenant store interface.
- **Check:** does any scope comparison use a string prefix on a joined path rather than comparing
  segments? Is a parsed selector prefix used to authorise, or only to filter inside a scope the
  principal already holds? The second is correct; the first is the defect.
<!-- scenario:end -->

<!-- scenario:begin id=TS-08 tier=T2 boundary=tenant-to-tenant keys=inherit,resolve,hierarchy,parent,child,config,merge,override -->
**Configuration inheritance resolves root to leaf, in every code path that resolves it.**

- **Must hold:** resolution runs root to leaf, and a descendant may narrow but never widen what an
  ancestor set. Every resolver agrees.
- **Why:** a resolver walking the other way lets a descendant read or override what sits above it,
  which is lateral movement up the tenant tree without any handler being wrong.
- **How it breaks:** one resolution path among several implemented in the opposite direction; a merge
  where the child's value wins on a key the parent is authoritative for.
- **Where to look:** the tenant stores and their interface, and the configuration resolution code in
  the config feature.
- **Check:** trace one key from a leaf tenant to root. Which end wins on conflict, and is it the same
  end in every path that resolves it? A single path resolving the other way is the defect.
<!-- scenario:end -->

---

## Boundary 4 — module publisher to the hosts that run the module

<!-- scenario:begin id=TS-09 tier=P boundary=publisher-to-host keys=signature,verify,publisher,bundle,ed25519,trust,key -->
**Signature verification fails closed, and cannot be disabled by anything the controller sends.**

- **Must hold:** every failure path in verification rejects; an absent signature is never treated as
  valid; unsafe publisher keys are refused outright; and the trust mode that skips verification is
  selectable only by local development configuration, never by a pushed value.
- **Why:** this is the control standing between an untrusted publisher and code execution on every
  endpoint that pulls the module. A trust mode reachable from the controller also removes the bound
  that makes controller compromise survivable.
- **How it breaks:** an error branch that returns success; a nil or empty signature short-circuiting
  the check; a bypass mode selectable from pushed configuration.
- **Where to look:** the module trust package — bundle signature verification, publisher key
  validation, trust identity — and the steward-side trust mode plumbing in the module runtime.
- **Check:** every success return in the verification path — is any reachable without a signature
  having been checked? Can the bypass mode be selected by anything other than local development
  configuration?
<!-- scenario:end -->

<!-- scenario:begin id=TS-10 tier=P boundary=publisher-to-host keys=version,rollback,downgrade,bundle,stale,cache,module -->
**A host never accepts a module older than the one it already runs.**

- **Must hold:** module installation compares versions and refuses a downgrade; the cache the
  controller serves from does not hand back a superseded bundle.
- **Why:** an old bundle passes every signature check by definition — it was genuinely signed. Without
  a monotonicity check, replaying one reintroduces whatever a newer version fixed, fleet-wide, using
  only material the attacker already has.
- **How it breaks:** installation that verifies the signature and nothing else; a cache keyed by
  module name rather than by name and version; an approval workflow that admits a version already
  superseded.
- **Where to look:** the installed-bundle handling in the module bundle package, and the controller's
  module cache and approval path.
- **Check:** is there a version comparison at install time, and is it ordered rather than
  equality-based? Can the cache serve a bundle older than the one a host already runs?
<!-- scenario:end -->

<!-- scenario:begin id=TS-11 tier=T3 boundary=publisher-to-host keys=resign,forward,signature,controller,intact,strip -->
**Publisher signatures reach the steward intact; the controller never re-signs.**

- **Must hold:** the controller verifies and forwards, never strips and re-signs. The publisher
  identity compiled into the steward binary is not influenced by any pushed configuration.
- **Why:** end-to-end signing is what makes independent steward verification mean anything. A
  controller that re-signs converts strict verification into "trust the controller", and removes the
  bound that makes controller compromise survivable.
- **How it breaks:** a serving path that rebuilds a bundle or produces a fresh signature object; a
  baked publisher identity read from a location a pushed configuration can reach.
- **Where to look:** the steward-binary publisher identity in the module trust package, and the
  controller's module serving path.
- **Check:** does any controller-side path construct a signature rather than copy one? Is the
  compiled-in publisher identity read from anywhere writable at runtime?
<!-- scenario:end -->

---

## Boundary 5 — controller to steward

<!-- scenario:begin id=TS-12 tier=T2 boundary=controller-to-steward keys=fleet,selector,filter,apply,push,scope,blast,bulk -->
**One action reaches only what the acting principal is authorised for, and no more than a bounded
number of endpoints.**

- **Must hold:** a fleet selector is intersected with the principal's authorised scope before it is
  resolved, not after; and a single operation has an upper bound on how many endpoints it changes.
- **Why:** this is the outcome that turns a management platform into a distribution channel. It is
  a missing bound rather than a code defect, which is why no single handler looks wrong. The bound
  is what makes a compromised admin session survivable.
- **How it breaks:** a selector resolved against the whole estate and filtered afterwards — the wider
  set still existed and may already have been acted on; an operation with no cap and no staged
  rollout.
- **Where to look:** the fleet selector package, and the controller-side fleet operation path that
  applies a resolved set.
- **Check:** at which step is the resolved set intersected with the caller's scope? Is there any
  ceiling on the size of a single operation, or any staging between a subset and the remainder?
<!-- scenario:end -->

<!-- scenario:begin id=TS-13 tier=T2 boundary=controller-to-steward keys=availability,converge,rollback,brick,recover,safe,config -->
**A steward refuses a configuration that would sever its own control-plane connection.**

- **Must hold:** convergence declines a change that disables the transport, credentials or network
  path the steward needs to receive the next configuration, and recovery does not itself depend on
  the controller being reachable.
- **Why:** losing remote access to an entire estate at once is catastrophic even with no
  confidentiality loss. Note that the resource-exhaustion class is scoped to a *lower-trust* party,
  so a tenant admin destroying their own estate falls outside it by definition and would otherwise
  go unexamined.
- **How it breaks:** a convergence loop that applies transport settings like any other key; a
  rollback path that needs to fetch the previous state from the controller it just cut off.
- **Where to look:** the steward convergence loop, and the configuration rollback feature.
- **Check:** can a converged configuration disable the transport needed for the next one? Is the
  refusal explicit, or is recovery assumed? Does rollback require controller reachability?
<!-- scenario:end -->

<!-- scenario:begin id=TS-14 tier=T1 boundary=controller-to-steward keys=script,stage,execute,interpreter,argv,path,symlink,lolbin -->
**Nothing a local unprivileged user controls can influence what the steward executes.**

- **Must hold:** content is staged to a declared path with a recorded hash and invoked against the
  on-disk file with arguments passed as separate argv elements; the staging path is not writable by
  unprivileged users and is not followed through a symlink; no command is composed at runtime.
- **Why:** the steward runs privileged. Anything a local user can steer is a local privilege
  escalation, and endpoints are assumed to be where attackers already are.
- **How it breaks:** a staging directory with permissive ownership; a file swapped between hash check
  and execution; a symlink at the staging path; an argument concatenated into a command string
  instead of passed as its own element.
- **Where to look:** the script module in the standard library, and the steward client's staging and
  transport path.
- **Check:** staging directory permissions; the window between verification and execution; whether
  any path is opened without rejecting symlinks; whether any argument reaches an interpreter inside a
  composed string.
<!-- scenario:end -->

---

## Cross-cutting

<!-- scenario:begin id=TS-15 tier=T2 boundary=cross-cutting keys=audit,log,tamper,delete,forensic,append,immutable,redact -->
**The principal that writes an audit entry cannot alter or remove it.**

- **Must hold:** audit records are append-only with respect to the writing principal, through every
  store path; buffered entries survive an unclean shutdown; redaction removes secret values and never
  actor identity.
- **Why:** if the record is editable by the party being investigated, incident response fails and
  every other control becomes unverifiable after the fact. This is the control that makes all the
  others auditable.
- **How it breaks:** an audit store exposing update or delete to the same principal that writes; a
  batch held in memory and lost on shutdown; redaction that strips the field naming who acted.
- **Where to look:** the audit manager's draining and batch-writing path, its redaction rules, and
  the audit stores in the storage providers.
- **Check:** can the writing principal delete or update an entry through any store path? What happens
  to a buffered batch on unclean shutdown? Does redaction ever remove actor identity?
<!-- scenario:end -->

---

## Extending this file

New surfaces get new scenarios; the existing ones do not get rewritten as the code changes, because
none of them describes the code. Add a scenario when a new trust boundary appears — the inline `cfg`
command path and the interactive remote-shell path are each their own boundary and each want their
own scenarios once they exist.

A sweep that finds a required property does not hold produces a **finding**, which goes through
triage into its own issue. It does not come back here as a note. This file states what must be true;
the sweep reports what is.
