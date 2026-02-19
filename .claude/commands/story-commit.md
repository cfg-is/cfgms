---
name: story-commit
description: Commit changes with mandatory validation checks and story progress tracking
parameters:
  - name: message
    description: The commit message (optional - auto-generates from diff if omitted)
    required: false
  - name: story_number
    description: Story number for progress tracking (optional - auto-detects from branch)
    required: false
---

# Story Commit Command

Commit changes with all mandatory validation gates and intelligent story progress tracking.

## Execution Flow

### 1. Mandatory Validation Sequence (ALL BLOCKING)

Run each validation sequentially. Stop on first failure.

1. **Tests** (BLOCKING):
   ```bash
   make test
   ```
   100% pass rate required. Zero tolerance.

2. **Linting** (BLOCKING):
   ```bash
   make lint
   ```

3. **Secret Scanning** (BLOCKING):
   ```bash
   make security-precommit
   ```
   Scans ONLY staged files. Two-layer: gitleaks + truffleHog.

4. **Architecture Compliance** (BLOCKING):
   ```bash
   make check-architecture
   ```
   Catches central provider violations (TLS outside pkg/cert, storage outside pkg/storage, etc).

5. **Security Scanning** (BLOCKING):
   ```bash
   make security-scan
   ```
   Critical/high vulnerabilities block the commit.

If ANY step fails: report specific failures, block commit. User must fix and retry.

### 2. Commit Message Generation

**If message provided**: Use it directly, appending story reference and security review summary.

**If no message provided**: Auto-generate from `git diff --staged`:
- Analyze changed files and their purpose
- Generate conventional commit message format: `<scope>: <what changed> (Issue #NNN)`
- Include 3-5 bullet points of key modifications
- Append basic security review summary
- Append `Co-Authored-By: Claude <noreply@anthropic.com>`

### 3. Create Commit

```bash
git add [relevant files]
git commit -m "[message]"
```

### 4. Story Progress Report (invoke story-context skill)

After successful commit, use the story-context skill to:
- Auto-detect story number from branch name
- Fetch issue details and acceptance criteria
- Calculate and display progress (X/Y criteria, Z%)
- Show remaining work items
- Provide smart recommendation based on progress

## Error Handling

- **Validation fails**: Report which step failed with specific details. Block commit.
- **No staged changes**: Warn user, suggest files to stage based on `git status`.
- **GitHub unavailable**: Commit succeeds, progress tracking skipped with warning.
- **Not on story branch**: Commit succeeds, progress tracking skipped.
