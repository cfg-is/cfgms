## Track 2 Artifact 5: Follow-up issues to file

Two follow-up issues per Epic #1716 "Out of Scope" + #1751 AC. File them on `cfg-is/cfgms` (or on the cfg.is-website repo if/when one exists, for the first one).

---

### Issue 1: cfg.is website AGPL-3.0 update

**Title:** `website: update cfg.is for AGPL-3.0 relicense (badge, license page, "Why AGPL" explainer)`

**Body:**

```markdown
## Parent Epic

#1716 — Migrate Licensing Model to AGPL-3.0 Single License

## Goal

The cfg.is marketing site (separate repo / hosting) reflects the new licensing model. Visitors evaluating cfgms see AGPL-3.0 prominently, understand what it means for their use case, and have a clear path to the commercial-embedding license if they need it.

## Trigger

Filed as the follow-up from #1751 (AGPL-3.0 governance tag, merged 2026-05-24). The codebase, README, LICENSE, and GitHub repo metadata are all already AGPL-3.0. The website is the last user-facing surface that still shows the old licensing model.

## Files / pages in scope

(Update with actual cfg.is repo layout when this is picked up. Likely candidates:)

- License badge in the site header / hero
- `/pricing` or `/license` page — replace the dual-license explainer with the single AGPL-3.0 model + commercial-license sidebar
- Footer license claim
- `robots.txt` / sitemap if license URLs change
- New page: **"Why AGPL-3.0?"** — a public-facing version of the Epic #1716 strategic rationale. Three audiences (self-hosting MSPs, SaaS hosts, proprietary embedders) explained with concrete what-it-means guidance.

## Acceptance Criteria

- [ ] License badge shows AGPL-3.0 across all pages
- [ ] License/pricing page is rewritten for the single-license model
- [ ] "Why AGPL?" explainer page exists, linked from license page and homepage
- [ ] `mailto:licensing@cfg.is` contact path is present on the license page
- [ ] No remaining references to "Apache 2.0", "Elastic License", "Elastic-2.0", or "dual license" anywhere on the site
- [ ] Site deploys cleanly to production

## Out of Scope

- Building the commercial-license intake form / Stripe / contract automation — separate issue (see Issue 2 below when filed).
- Trademark policy page.
- Blog/announcement post — separate effort.
```

**Filing command:**

```bash
gh issue create -R cfg-is/cfgms \
  --title "website: update cfg.is for AGPL-3.0 relicense (badge, license page, \"Why AGPL\" explainer)" \
  --body-file <(sed -n '/^### Issue 1:/,/^---$/p' docs/governance/agpl-migration-playbook/05-followup-issues.md | sed '1d;$d') \
  --label "epic-1716,governance"
```

---

### Issue 2: Commercial-license intake process

**Title:** `governance: define commercial-license intake process (inquiry path, contract template, pricing framework)`

**Body:**

```markdown
## Parent Epic

#1716 — Migrate Licensing Model to AGPL-3.0 Single License

## Goal

When a third party emails `licensing@cfg.is` to inquire about embedding CFGMS in a proprietary product, there is a documented, repeatable process that takes them from inquiry to signed commercial license without ad-hoc back-and-forth or re-inventing terms each time.

## Trigger

Filed as the follow-up from #1751 and Epic #1716 ("Out of Scope: Building or marketing the commercial license offering. Defining the commercial-license intake process. Flagged as immediate follow-up."). The relicense to AGPL-3.0 means the public repository is no longer compatible with proprietary embedding — every such inquiry must route through this commercial-license track. The track does not exist yet.

## Scope

### 1. Inquiry intake

- [ ] `licensing@cfg.is` mailbox is monitored (define cadence: 1 business day target).
- [ ] First-response template: confirms receipt, asks 5-7 qualification questions (company, use case, scope of embedding, deployment scale, distribution model, target timeline, prior eval).

### 2. Qualification

- [ ] Define decision tree: which inquiries warrant a commercial license vs which can be served by AGPL (e.g. a self-hosting MSP doesn't need a commercial license; an RMM embedding cfg components in a proprietary CLI does).
- [ ] Decline policy: how to courteously redirect inquiries that don't need a commercial license.

### 3. Contract template

- [ ] Outbound commercial license template, modeled after CIPP's `LICENSE.CustomLicenses.md` pattern (per Epic #1716).
- [ ] Customizable fields: licensee identity, scope of grant (which components), distribution rights, sublicensing, term, fees, audit rights, IP indemnity carve-outs.
- [ ] Plain-language summary sheet — what AGPL obligations are waived, what stays.

### 4. Pricing framework

- [ ] Internal pricing model: per-seat, per-deployment, per-revenue-share, or hybrid.
- [ ] Tiers: startup / mid-market / enterprise.
- [ ] Public price disclosure decision: do we publish ranges on cfg.is, or always negotiate privately? Argument for transparency vs argument for sales process flexibility.

### 5. Execution path

- [ ] DocuSign (or equivalent) workflow.
- [ ] Payment intake: invoice (Stripe Invoice), wire, or annual ACH — define defaults by tier.
- [ ] Onboarding: once signed, how does the licensee actually get the artifact (still the public AGPL build, just with private license terms covering their use)? Or do they get a separately-signed binary? Decision needed.

### 6. Renewals and termination

- [ ] Default term + renewal logic.
- [ ] Termination triggers + obligations (e.g. lose embedding rights, source-modifications obligations revert to AGPL).

## Acceptance Criteria

- [ ] `docs/legal/commercial-license-process.md` exists with the full intake flow documented
- [ ] Contract template lives in a private repo / location with access controls
- [ ] Pricing framework documented internally
- [ ] Decision tree exists for "AGPL is sufficient" vs "commercial license needed"
- [ ] `licensing@cfg.is` first-response template is ready to deploy
- [ ] Signed off by founder before first commercial inquiry is processed

## Out of Scope

- Building a sales team / hiring a sales engineer — this issue defines the *process*; the people who run it are a separate decision.
- Public marketing of the commercial license — separate from defining the inbound intake.
- Building self-serve commercial licensing (Stripe checkout for the license itself) — premature for current deal volume; defer until inquiry volume justifies automation.
```

**Filing command:**

```bash
gh issue create -R cfg-is/cfgms \
  --title "governance: define commercial-license intake process (inquiry path, contract template, pricing framework)" \
  --body-file <(sed -n '/^### Issue 2:/,/^---$/p' docs/governance/agpl-migration-playbook/05-followup-issues.md | sed '1d;$d') \
  --label "epic-1716,governance,legal"
```

---

### Note on labels

Both filing commands assume `epic-1716` and `governance` labels exist. If they don't:

```bash
gh label create epic-1716 --color BFD4F2 --description "Sub-tasks of Epic #1716 (AGPL-3.0 migration)"
gh label create governance --color D4C5F9 --description "Project governance, legal, licensing"
gh label create legal --color C5DEF5 --description "Legal / contractual / compliance work"
```
