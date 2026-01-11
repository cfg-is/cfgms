# CLA Enforcement Guide for Maintainers

This guide explains how to verify and enforce the Contributor License Agreement (CLA) when reviewing Pull Requests.

## Quick Reference

**Before merging any PR with code changes:**

1. ✅ Verify contributor has signed CLA (name in CONTRIBUTORS.md)
2. ✅ Check CLA checklist is completed in PR
3. ✅ For first-time contributors, verify CONTRIBUTORS.md is included in the PR
4. ✅ For corporate contributors, verify authorization if needed

## Detailed Process

### 1. Check if Contributor Has Signed CLA

**For returning contributors:**

```bash
# Check if contributor is in CONTRIBUTORS.md
grep -i "contributor-github-username\|contributor-email" CONTRIBUTORS.md

# Or check by full name
grep -i "John Doe" CONTRIBUTORS.md
```

If their name is already in CONTRIBUTORS.md, they're covered for all future PRs.

**For first-time contributors:**

1. Check if CONTRIBUTORS.md is modified in the PR:
   ```bash
   gh pr diff <PR_NUMBER> --name-only | grep CONTRIBUTORS.md
   ```

2. If CONTRIBUTORS.md is in the PR, verify they added their name correctly:
   ```bash
   gh pr diff <PR_NUMBER> CONTRIBUTORS.md
   ```

3. Verify the format matches:
   ```markdown
   - [Full Name] <email@example.com> - YYYY-MM-DD
   ```

### 2. Verify PR Template CLA Section

Check that the contributor has completed the CLA section in the PR description:

- [ ] **I have signed the CLA** by adding my name to CONTRIBUTORS.md
- [ ] **I have read the CLA**: docs/legal/CLA.md

### 3. Handle Different Contributor Types

#### Individual Contributors (Most Common)

**Requirements:**
- Name added to Individual Contributors section in CONTRIBUTORS.md
- Email address included (can be privacy-protecting email)
- Date in YYYY-MM-DD format

**What to check:**
- Addition is in the Individual Contributors section (not Corporate)
- Format is correct
- Date is reasonable (not future dated)

**Example PR comment if CLA missing:**
```markdown
Thanks for your contribution! Before we can merge this PR, you'll need to sign our Contributor License Agreement (CLA).

**To sign the CLA:**
1. Read the CLA: [docs/legal/CLA.md](../docs/legal/CLA.md)
2. Add your name to [CONTRIBUTORS.md](../CONTRIBUTORS.md) in this PR:
   ```markdown
   - [Your Full Name] <your.email@example.com> - 2026-01-10
   ```
3. Update the CLA checklist in the PR description

See [docs/legal/README.md](../docs/legal/README.md) for more information.
```

#### Corporate Contributors

**Requirements:**
- Company added to Corporate Contributors section
- Authorized representative information
- May require proof of authorization

**What to check:**
- Addition is in Corporate Contributors section
- Includes authorization information
- Format: `- [Company Name] (authorized by [Name] <email>) - YYYY-MM-DD`

**If authorization unclear:**
```markdown
Thank you for contributing on behalf of [Company Name]!

For corporate contributions, we need to verify authorization. Could you please:

1. Confirm you are authorized to contribute on behalf of [Company Name]
2. Provide documentation if this is your first contribution (e.g., email from legal/manager)

See our corporate CLA guidance: [docs/legal/README.md#corporate-contributions](../docs/legal/README.md#corporate-contributions)
```

### 4. Documentation-Only PRs

**CLA is required for:**
- ✅ Code changes (Go files, scripts, etc.)
- ✅ Build configuration (Makefiles, workflows, etc.)
- ✅ Test files

**CLA is NOT required for:**
- ❌ Typo fixes in documentation
- ❌ README updates
- ❌ Markdown formatting fixes
- ❌ Comment updates

**Guideline:** If the PR could theoretically contain copyrightable expression (e.g., significant documentation additions), require CLA. For trivial changes (typos, formatting), use judgment.

**Example for trivial doc fix:**
```markdown
Thanks for fixing this typo! Since this is a trivial documentation fix, no CLA signature is required.

For future contributions with code or substantial documentation changes, you'll need to sign our CLA: [docs/legal/CLA.md](../docs/legal/CLA.md)
```

### 5. Handling CLA Issues

#### Contributor Refuses to Sign CLA

If a contributor doesn't want to sign the CLA:

1. Politely explain why we need it (dual-license model, copyright clarity)
2. Point them to the FAQ: [docs/legal/README.md#faq](../docs/legal/README.md#faq)
3. If they still refuse, close the PR with thanks

**Example response:**
```markdown
We understand CLAs aren't for everyone. CFGMS requires a CLA to support our dual-license model (Apache 2.0 + Elastic License 2.0).

If you'd prefer not to sign the CLA, we won't be able to merge this PR. However, we appreciate you reporting the issue/suggesting the improvement!

For questions about the CLA: [docs/legal/README.md](../docs/legal/README.md)
```

#### Incorrect CLA Format

If contributor signed CLA but format is wrong:

```markdown
Thank you for signing the CLA! However, the format isn't quite right. Could you please update your entry in CONTRIBUTORS.md to match this format:

```markdown
- [Your Full Name] <your.email@example.com> - 2026-01-10
```

See the existing entries in CONTRIBUTORS.md for examples.
```

#### Missing Date

```markdown
Almost there! Could you please add the date to your CLA signature in CONTRIBUTORS.md? Format: YYYY-MM-DD

Example: `- [Your Name] <email@example.com> - 2026-01-10`
```

#### CLA Signed But Not Checked in PR

```markdown
I see you've signed the CLA (your name is in CONTRIBUTORS.md) - thank you!

Could you please check the CLA box in the PR description? This helps us track that you're aware of the CLA requirement.
```

### 6. Automated CLA Verification (Future)

**Note:** Currently CLA verification is manual. In the future, we may implement automated checking via:

- **CLA Assistant Bot** - Automatically checks CONTRIBUTORS.md and comments on PRs
- **GitHub Actions** - Workflow that verifies CLA signature
- **Status Check** - Required check that fails if CLA not signed

When automation is implemented, this guide will be updated.

### 7. CLA Verification Checklist for Reviewers

Before approving any PR with code changes:

- [ ] Contributor name is in CONTRIBUTORS.md (or added in this PR)
- [ ] Format is correct (name, email, date)
- [ ] Entry is in correct section (Individual vs Corporate)
- [ ] CLA checklist in PR description is completed
- [ ] For corporate contributions, authorization verified if needed
- [ ] For first-time contributors, added helpful comment welcoming them

## Special Cases

### Multiple Contributors on One PR

If a PR has multiple authors (co-authored commits):

1. **All authors must sign the CLA**
2. Each author should add their name to CONTRIBUTORS.md
3. Verify all commit authors are in CONTRIBUTORS.md

**Example comment:**
```markdown
This PR has multiple authors. Each contributor needs to sign the CLA:

**Contributors identified:**
- @user1 ✅ (already signed)
- @user2 ❌ (needs to sign)
- @user3 ❌ (needs to sign)

@user2 @user3 please add your names to CONTRIBUTORS.md to sign the CLA.
```

### Bot/Automated Contributions

For automated PRs (Dependabot, Renovate, etc.):

- **Dependency updates**: No CLA required (automated, no original work)
- **Automated formatting/linting**: No CLA required
- **Generated code from templates**: Case-by-case basis

### Contributions from Former Employees

If a contributor previously signed CLA while at Company A, then contributes individually:

- They're covered by their original CLA signature
- No need to sign again
- Optional: They can add individual entry if desired

## Resources for Maintainers

- **Full CLA Text**: [docs/legal/CLA.md](CLA.md)
- **CLA FAQ**: [docs/legal/README.md#faq](README.md#faq)
- **Contributor Guide**: [CONTRIBUTING.md](../../CONTRIBUTING.md)
- **License Information**: [LICENSING.md](../../LICENSING.md)

## Questions?

If you're unsure whether a contribution requires a CLA signature:

1. **General rule**: If it contains copyrightable expression (code, substantial docs), require CLA
2. **Trivial changes**: Use judgment (typo fixes usually don't need CLA)
3. **When in doubt**: Require CLA (safer)

For complex cases or legal questions, consult with project leadership.

---

**Last Updated:** 2026-01-10
**Version:** 1.0
