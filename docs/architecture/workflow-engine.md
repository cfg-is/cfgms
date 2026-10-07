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
