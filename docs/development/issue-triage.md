# Issue Triage Process

This document describes how issues are triaged and prioritized in the CFGMS project.

## Triage Workflow

### New Issues

All new issues receive the `triage` label automatically through issue templates. During triage:

1. **Validate the issue** - Ensure it has sufficient information
2. **Categorize** - Apply appropriate component and type labels
3. **Prioritize** - Assign priority label based on impact
4. **Assign** - Assign to a milestone or project column if actionable
5. **Remove triage label** - Issue is now processed

### Label Categories

#### Type Labels
- `bug` - Something isn't working
- `enhancement` - New feature or improvement
- `question` - Needs clarification or guidance
- `documentation` - Documentation improvements

#### Priority Labels
- `priority/P0` - Critical - Production broken, security vulnerability
- `priority/P1` - High - Major functionality impacted
- `priority/P2` - Medium - Workaround available
- `good first issue` - Suitable for new contributors

#### Component Labels
- `controller` - Controller component
- `steward` - Steward component
- `api` - REST API
- `modules` - Module system
- `workflow` - Workflow engine
- `dna` - DNA monitoring
- `security` - Security-related

#### Status Labels
- `triage` - Awaiting initial review
- `help wanted` - Open for community contribution
- `duplicate` - Already reported
- `wontfix` - Won't be addressed

## Triage Criteria

### Priority Assignment

**P0 - Critical**
- Security vulnerabilities
- Data loss or corruption
- Complete feature failure in production
- Response time: Same day

**P1 - High**
- Major functionality broken
- No workaround available
- Affects multiple users
- Response time: 1-2 days

**P2 - Medium**
- Feature partially broken
- Workaround available
- Affects single user/edge case
- Response time: 1 week

### Good First Issue Criteria

Issues suitable for new contributors should:
- Have clear acceptance criteria
- Not require deep architectural knowledge
- Be self-contained (single file or small scope)
- Include pointers to relevant code
- Have existing tests as examples

Examples:
- Documentation improvements
- Adding tests for existing functionality
- Simple bug fixes with known causes
- CLI improvements

## Response Templates

### Insufficient Information
```markdown
Thanks for reporting this issue! To help us investigate, could you please provide:
- [ ] CFGMS version (`cfg version`)
- [ ] Operating system and version
- [ ] Steps to reproduce
- [ ] Relevant logs or error messages

Once you've added this information, we'll be able to look into it further.
```

### Duplicate Issue
```markdown
Thanks for reporting! This appears to be a duplicate of #XXX. I'm closing this issue, but please follow the linked issue for updates.

If you believe this is different, please reopen and explain how it differs.
```

### Won't Fix
```markdown
Thanks for the suggestion! After review, we've decided not to implement this because:
- [Reason]

If you'd like to discuss further, please open a discussion thread.
```

### Good First Issue
```markdown
This looks like a good first issue for new contributors!

**Getting Started:**
1. Read the [CONTRIBUTING.md](../CONTRIBUTING.md) guide
2. Look at the code in `[path/to/file]`
3. Review similar implementations in `[example/path]`

**Acceptance Criteria:**
- [ ] [Specific requirement]
- [ ] Tests added
- [ ] Documentation updated if needed

Let us know if you'd like to work on this!
```

## Weekly Triage Review

Maintainers should review the triage queue weekly:

1. Process all `triage` labeled issues
2. Review stale issues (no activity > 30 days)
3. Update priorities based on roadmap
4. Assign `good first issue` labels to appropriate items

## Security Issues

**Never discuss security vulnerabilities in public issues.**

Direct reporters to: https://github.com/cfg-is/cfgms/security/advisories/new

See [SECURITY.md](../../SECURITY.md) for the security disclosure policy.
