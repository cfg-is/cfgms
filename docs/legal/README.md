# CFGMS Legal Documentation

This directory contains legal documents related to contributing to and using the CFGMS project.

## Documents

### [Contributor License Agreement (CLA.md)](CLA.md)

The formal legal agreement that contributors must accept before their contributions can be merged.

**Quick Summary** (not legal advice - read the full CLA):

When you contribute to CFGMS, you agree to:
1. **Assign copyright** to Jordan Ritz (current copyright holder)
2. **Allow dual-licensing** of your contributions under both Apache 2.0 (OSS) and Elastic License 2.0 (commercial)
3. **Future transfer** to cfg.is entity when it's formed
4. **Certify** that your contribution is original work and doesn't violate anyone else's rights

**Why do we need this?**
- CFGMS has both open source (Apache 2.0) and commercial (Elastic 2.0) components
- Clear copyright ownership is needed to enforce license terms
- Protects both contributors and the project from legal issues

**How to sign:**
Add your name to [CONTRIBUTORS.md](../../CONTRIBUTORS.md) in your first Pull Request.

---

## Why a CLA?

### Dual-License Model

CFGMS uses a dual-license model:

**Apache License 2.0** (Open Source)
- Core platform features
- Standard modules and plugins
- Development tools
- Located in: `cmd/`, `pkg/`, `features/`, `api/`

**Elastic License 2.0** (Source-Available, Commercial)
- High-availability features
- Enterprise management capabilities
- Advanced failover and clustering
- Located in: `commercial/ha/`

The CLA ensures contributions can be used under both licenses as appropriate.

### Copyright Assignment

Why assign copyright instead of just granting a license?

1. **License Enforcement**: Only the copyright holder can enforce license violations (e.g., if someone violates the "no hosted service" restriction in Elastic License 2.0)

2. **Dual-License Management**: Allows flexibility to include contributions in either Apache 2.0 or Elastic 2.0 components

3. **Future Entity Formation**: Simplifies transfer when cfg.is becomes a legal entity

4. **Legal Certainty**: Clear ownership prevents ambiguity about who controls the code

### Similar Projects

Many dual-license and commercial open source projects use CLAs with copyright assignment:

- **Elasticsearch** (Apache 2.0 + Elastic License) - Uses CLA
- **MongoDB** (SSPL) - Uses CLA
- **GitLab** (MIT + Enterprise) - Uses CLA
- **Sentry** (BSL + Enterprise) - Uses CLA

---

## Frequently Asked Questions

### Do I need a lawyer to sign the CLA?

No, but you should read and understand it. If your employer has policies about contributing to open source, check with them first.

### What if my employer owns my code?

If your employer has rights to code you write, you need their permission to contribute. Options:

1. Get a written waiver from your employer
2. Have your employer sign the corporate CLA
3. Contribute on your own time with your own resources (check local laws)

### Can I still use my contributions elsewhere?

**This depends on local laws.** In some jurisdictions, copyright assignment may be exclusive. In others, you may retain rights to use your work.

**If you're concerned about this:**
- Consult a lawyer in your jurisdiction
- Consider whether CFGMS's dual-license model aligns with your goals
- Note that open source components remain Apache 2.0 licensed (permissive)

### What happens when cfg.is is formed?

When cfg.is becomes a legal entity:
1. Jordan Ritz will assign all copyrights to cfg.is
2. cfg.is becomes the new copyright holder
3. Your CLA remains valid - rights automatically transfer
4. You don't need to sign anything new

### Can the CLA be changed?

Yes, the copyright holder can update the CLA. If changes are made:
- A new version will be published
- Contributions after the change use the new version
- Your existing contributions remain under the version you signed

### What if I don't want to sign?

That's okay! You can still:
- Use CFGMS (under Apache 2.0 for OSS components, Elastic 2.0 for commercial)
- Report bugs and issues
- Participate in discussions
- Fork the project (under the respective licenses)

You just can't have your code merged into the official repository without signing the CLA.

---

## Corporate Contributions

### If You're Contributing for Your Company

**Step 1: Check Authorization**
- Review your employment agreement
- Check your company's IP policies
- Consult with your legal/engineering management

**Step 2: Get Approval**
Most companies have a process for open source contributions. Common requirements:
- Manager approval
- Legal team review
- IP review for proprietary information

**Step 3: Sign the CLA**
Have an authorized representative add your company to the Corporate Contributors section in [CONTRIBUTORS.md](../../CONTRIBUTORS.md).

**Step 4: Document Authorization**
We may request documentation proving you're authorized to contribute on behalf of your employer.

---

## Contact

**Questions about the CLA:**
- Open an issue with the `legal` label
- Email: jordan@cfg.is (when available)

**Legal Advice:**
We cannot provide legal advice. Consult your own attorney for questions about how the CLA applies to your specific situation.

---

## Disclaimer

**Nothing in these documents constitutes legal advice.** The explanations provided here are for informational purposes only. The formal [CLA.md](CLA.md) document is the binding legal agreement.

If you have questions about your legal rights or obligations, consult an attorney licensed in your jurisdiction.

---

**Last Updated:** 2026-01-10
