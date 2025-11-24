# Email & URL Infrastructure Inventory

This document provides a complete inventory of all email addresses and URLs referenced in CFGMS documentation that require infrastructure setup.

**Story**: #248 - Review and Create All Referenced Email Addresses & Web Pages
**Date**: 2025-11-20

---

## Email Addresses

### Required Email Addresses (@cfg.is)

| Email | Purpose | Priority | Files Referenced | Status |
|-------|---------|----------|------------------|--------|
| `security@cfg.is` | Security vulnerability reporting | **Critical** | SECURITY.md, docs/product/roadmap.md | ⏳ Pending |
| `licensing@cfg.is` | Commercial licensing inquiries | **High** | README.md, LICENSING.md, docs/product/roadmap.md | ⏳ Pending |
| `conduct@cfg.is` | Code of conduct violations | **High** | CODE_OF_CONDUCT.md, SECURITY.md | ⏳ Pending |
| `security-announce@cfg.is` | Security announcements mailing list | **Medium** | SECURITY.md | ⏳ Pending |
| `noreply@cfg.is` | Automated system emails (git commits) | **Low** | docs/security/sensitive-data-scan-results.md | ⏳ Pending |

### Email Configuration Requirements

**security@cfg.is**
- Must support PGP encryption for secure vulnerability reports
- Needs monitoring for rapid response (SLA: same day for critical)
- Consider ProtonMail or similar security-focused provider

**licensing@cfg.is**
- Standard business email
- May need CRM integration for lead tracking

**conduct@cfg.is**
- Confidential handling required
- Limited access (maintainers only)

**security-announce@cfg.is**
- Mailing list functionality required
- Subscribe/unsubscribe management
- Consider Mailchimp, Buttondown, or similar

**noreply@cfg.is**
- Outbound only
- Used for automated notifications

---

## Web URLs

### cfg.is Domain

| URL | Purpose | Priority | Files Referenced | Status |
|-----|---------|----------|------------------|--------|
| `https://cfg.is` | Main website | **High** | ARCHITECTURE.md | ⏳ Pending |
| `https://cfg.is/security/` | Security subscription page | **Critical** | SECURITY.md | ⏳ Pending |
| `https://cfg.is/security/pgp-key.asc` | PGP public key for encrypted reports | **Critical** | SECURITY.md | ⏳ Pending |
| `https://docs.cfg.is` | Documentation site | **High** | ARCHITECTURE.md, README.md | ⏳ Pending |

### Application Portal (User-Configurable)

**Note**: The application portal URL is configurable and depends on your deployment.

| URL Pattern | Purpose | Priority | Files Referenced | Status |
|-------------|---------|----------|------------------|--------|
| `https://portal.<your-domain>.com` | Controller web UI & API | **Critical** | Various docs use `portal.example.com` | ⏳ User configures |
| `https://portal.<your-domain>.com/admin/callback` | M365 OAuth callback | **Critical** | docs/M365_INTEGRATION_GUIDE.md | ⏳ User configures |

**For cfg.is hosted beta**:

- `https://portal.cfg.is` - Production controller portal
- `https://portal.cfg.is/admin/callback` - OAuth callback

---

## Priority Assessment

### Critical (Must have before launch)

1. `security@cfg.is` - Required for responsible disclosure
2. `https://cfg.is/security/` - Security subscription page
3. `https://cfg.is/security/pgp-key.asc` - PGP key for encrypted reports
4. User's OAuth callback URL - `https://portal.<your-domain>.com/admin/callback` (user-configurable, see M365 Integration Guide)

### High (Should have before launch)

1. `licensing@cfg.is` - Commercial inquiries
2. `conduct@cfg.is` - Code of conduct enforcement
3. `https://cfg.is` - Main website (can be simple landing page)
4. `https://docs.cfg.is` - Documentation (can redirect to GitHub initially)

### Medium (Can be added post-launch)

1. `security-announce@cfg.is` - Mailing list

### Low (Nice to have)

1. `noreply@cfg.is` - Automated emails

---

## Infrastructure Recommendations

### Email Provider Options

**Option 1: Google Workspace** (Recommended for team)
- Professional email with calendar, docs
- Easy team management
- $6-12/user/month

**Option 2: Zoho Mail** (Budget-friendly)
- Free tier for small teams
- Professional features
- Good alternative to Google

**Option 3: ProtonMail** (Security-focused)
- End-to-end encryption
- Good for security@cfg.is specifically
- May use alongside other provider

### Mailing List Options

**Option 1: Buttondown** (Simple, developer-friendly)
- Markdown support
- API access
- Free tier available

**Option 2: Mailchimp** (Feature-rich)
- Advanced analytics
- Templates
- Free tier for small lists

### Web Hosting Options

**Option 1: Cloudflare Pages** (Recommended)
- Free SSL
- Global CDN
- Easy deployment from Git
- Custom domains

**Option 2: GitHub Pages** (Simple)
- Free for public repos
- Easy Markdown sites
- Custom domains with SSL

**Option 3: Netlify** (Full-featured)
- Automatic deploys
- Forms, functions
- Free tier generous

---

## PGP Key Setup

For `security@cfg.is`, a PGP key must be generated:

```bash
# Generate key pair
gpg --full-generate-key
# Choose: RSA and RSA, 4096 bits, no expiration

# Export public key
gpg --armor --export security@cfg.is > pgp-key.asc

# Upload to keyserver
gpg --keyserver keys.openpgp.org --send-keys [KEY_ID]
```

The public key should be:
1. Published at `https://cfg.is/security/pgp-key.asc`
2. Fingerprint listed in SECURITY.md
3. Uploaded to public keyservers

---

## Implementation Checklist

### Phase 1: Critical Infrastructure ✅ COMPLETE

- [x] Register/configure cfg.is domain (already owned)
- [x] Set up email provider with Zoho Mail (current provider)
- [x] Create security@cfg.is with PGP support
- [x] Generate and publish PGP key (Fingerprint: B489 6960 2965 C241 E851  71F9 258D 1EDC F411 6969)
- [x] Create https://cfg.is/security/ page (ready to deploy in website/ directory)
- [x] Host pgp-key.asc file (ready to deploy in website/security/)

### Phase 2: Core Email Addresses ✅ COMPLETE

- [x] Create licensing@cfg.is
- [x] Create conduct@cfg.is
- [x] Set up email forwarding/monitoring (shared inboxes configured in Zoho)
- [x] Document access credentials securely (to be stored in password manager)

### Phase 3: Web Presence 🚧 IN PROGRESS

- [x] Create https://cfg.is landing page (created in website/index.html)
- [ ] Deploy website to Cloudflare Pages
- [ ] Set up https://docs.cfg.is (or redirect to GitHub)
- [ ] Configure SSL certificates (auto-provisioned by Cloudflare)
- [ ] Test all URLs

### Phase 4: Extended Infrastructure ⏳ DEFERRED

- [ ] Set up security-announce@cfg.is mailing list (future story)
- [ ] Create noreply@cfg.is for automation (future story)

### Phase 5: User-Specific Configuration (Self-Hosters)

**Note**: The following items are user-configurable and documented in integration guides:

- [ ] Configure OAuth callback URL in M365 app registration (e.g., `https://portal.yourcompany.com/admin/callback`)
- [ ] Update CFGMS configuration with chosen domain/subdomain
- [ ] Configure DNS records for chosen domain
- [ ] Set up SSL certificates for application portal

---

## Documentation Updates Required

After infrastructure is set up, update these files with verified information:

1. **SECURITY.md** - Verify all security contact information
2. **CODE_OF_CONDUCT.md** - Verify conduct@cfg.is is correct
3. **LICENSING.md** - Verify licensing@cfg.is is correct
4. **README.md** - Verify docs.cfg.is and licensing email
5. **docs/M365_INTEGRATION_GUIDE.md** - Verify OAuth callback URL

---

## Notes

- Example emails in docs (admin@contoso.com, etc.) are intentionally placeholder examples
- jrdn@ritzmob.com appears in some docs - may need to be replaced with official contact
- git@github.com is standard GitHub SSH - no action needed
