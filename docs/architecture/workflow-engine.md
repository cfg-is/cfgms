# Workflow Engine

The workflow engine (`features/workflow`) runs multi-step workflows on the
controller. A workflow is defined in YAML (`Parser.ParseYAML`) or JSON (the
workflows REST API) and stored per tenant.

## Workflow fields

| Field | Purpose |
|-------|---------|
| `name` | Unique workflow identifier |
| `description`, `version` | Documentation and semantic version |
| `variables` | Free-form workflow-level variables available to steps |
| `inputs` | Declared, typed run parameters (see below) |
| `steps` | The execution flow |
| `timeout` | Maximum run time for the whole workflow |
| `on_failure` | Workflow-level failure action |
| `error_workflows` | Custom error-handling workflows |

## Inputs

A workflow declares the parameters a run accepts in `inputs`:

```yaml
workflow:
  name: patch-group
  inputs:
    - name: environment
      type: enum
      options: [staging, prod]
      default: staging
      description: Target environment
    - name: reason
      type: string
      required: true
    - name: dry_run
      type: bool
      default: true
  steps: [...]
```

Each `InputSpec` has `name`, `type` (`string`, `enum` or `bool`), `required`,
`default`, `options` (enum only) and `description`. The `GET` workflow response
carries the declaration so a client can render a run form.

### Declaration validation

`Parser.ValidateWorkflow` (and the REST create/update handlers) reject:

- duplicate input names, empty names, or names that are not identifiers;
- an unknown type;
- an `enum` without `options`, or `options` on a non-enum input;
- a `default` that does not match the type (an enum default must be an option);
- a name reserved by the engine (`tenant_id`, `execution_id`, `workflow`,
  `steps`, `variables`, `inputs`, ...), compared ignoring case, `_` and `-`.
  The authenticated tenant is carried on the execution from the request
  context and can never be supplied or overwritten by an input.

### Enforcement

`Engine.ExecuteWorkflow` is the single enforcement point. It calls
`Workflow.ResolveInputs` before an execution is created, so triggers and
sub-workflow steps — which start executions without the HTTP handler — are
covered too. `ResolveInputs` applies defaults for omitted optional inputs and
returns an `*InputsError` listing each offending field (missing required,
wrong type, enum value not in `options`). Values for names that are not
declared pass through unchanged, so free-form `variables` keep their meaning.

A rejected run never starts: the engine records an execution with status
`failed` and the error message, and returns it together with the error. The
run endpoint turns an `*InputsError` into a `400` with per-field errors (see
[REST API](../api/rest-api.md)). Error messages name the field and the rule,
never the supplied value. Input values are data: they flow only into the
existing variable and template substitution and are never evaluated as code.

## Approval steps

An `approval` step is a durable human gate. A run that reaches it stops, holds no
goroutine, and resumes only after a decision.

```yaml
- name: sign-off
  type: approval
  on_failure: stop            # stop (default) or continue, applied on rejection
  approval:
    message: Deploy to production?
    approver_permission: workflow:approve
    timeout: 4h
```

`message` and a positive `timeout` are required. `approver_permission` is recorded on the
approval for the decision endpoint to enforce.

### Top-level only

Approval steps must be top-level steps of the workflow. The parser rejects one inside a
sequential, parallel, conditional, loop, try (try, catch or finally), switch block or a
fallback step with `approval steps must be top-level`. The engine enforces the same rule
at run time for workflows that do not go through the parser. A resume replays the
top-level step list after the gate, which is why nesting is not supported. A workflow may
contain several gates.

### What happens at a gate

1. The engine writes a checkpoint and a pending approval record, sets the execution to
   `awaiting_approval`, and returns. If either write fails the run fails; a gate that
   cannot be resumed never looks like a waiting run.
2. The checkpoint holds the workflow snapshot, the gate's index, the variables, the step
   results and the ids of completed steps. It is encrypted by the secrets provider. The
   approval record keeps only the reference (`checkpoint_ref`), so the approval store never
   holds variables or step output. Checkpoint contents are never logged.
3. A decision is written to the approval store. `(*Engine).ResumeFromApproval(ctx,
   tenantID, approvalID)` then claims the approval with the store's compare-and-set
   (`ClaimResume`, with a lease), rebuilds the execution under the same execution id, and
   runs the steps after the gate in the background. When the tail finishes the approval is
   marked resumed and the checkpoint is deleted. `tenantID` is the tenant of the stored
   approval record.

On resume:

- Steps before the gate do not run again. Steps after it see the checkpointed variables.
  Variables and step output come back through JSON, so numbers are `float64`.
- The execution's tenant is taken from the approval record and injected as the
  authenticated tenant. It is never read from checkpointed variables.
- The run uses a context derived from the engine, not from the caller's request, so it
  outlives the decision request. `workflow.timeout` is not re-armed; each step keeps its own
  timeout.
- A rejection fails the run with the decider and justification as the recorded reason,
  unless the gate sets `on_failure: continue`, in which case the steps after it run and the
  gate stays recorded as failed.
- A timeout is a rejection: the approval expires and the run fails with a recorded reason.
  `on_failure: continue` does not apply to a timeout.
- Executions are node-local. The resuming node lists the run in its own executions;
  other nodes do not. Authorization of a decision reads the tenant and state from the
  approval record, never from the engine's execution map.

### Restart and recovery

`(*Engine).RecoverApprovals` runs when the controller starts and then every 30 seconds on
every node. It expires approvals past their deadline (`ExpireDue`) and fails their runs,
and resumes decided approvals whose claim is absent or older than the lease
(`ListUnresumed`). The store's compare-and-set decides which node acts on each approval.

- A node that dies mid-resume leaves its claim. Once the lease (default 10 minutes,
  `WithApprovalLease`) lapses, another node re-claims the approval and finishes the run
  from the checkpoint. A run cut short by controller shutdown is not marked resumed. The
  lease must be longer than the longest run of steps after a gate: a claim that lapses
  while those steps are still running lets another node run them again.
- A decided approval whose checkpoint cannot be restored (missing, unreadable, or an
  unsupported version) is marked resumed so it is not retried, and its run is recorded as
  `failed` with the reason and kept in the executions list. After a restart the run is
  recreated from the approval record so it does not disappear.
- Pending approvals need no recovery work: they live in the store, and a later decision
  resumes them.

An approval step needs the engine to be built with `WithApprovalStore` and a secrets
provider, and the run needs a tenant. Without them the run fails with a clear error.
Approval steps inside a workflow that another workflow calls are not supported: the called
run would stop at the gate while its caller waits for it.
