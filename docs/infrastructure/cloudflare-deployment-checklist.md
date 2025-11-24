# Cloudflare Pages Deployment Checklist

**Story:** #248 - Email & Web Infrastructure Setup
**Date:** 2025-11-23

This checklist walks through deploying cfg.is to Cloudflare Pages.

---

## Prerequisites

- [x] Cloudflare account (free tier is sufficient)
- [x] cfg.is domain ownership
- [x] Website files created in `website/` directory
- [x] PGP key generated and uploaded to keyserver

---

## Phase 1: Cloudflare Account Setup

### Step 1.1: Create/Login to Cloudflare Account

1. Go to https://dash.cloudflare.com
2. Sign up or login
3. Verify email address if new account

**Status:** ⏳ Pending

### Step 1.2: Add cfg.is Domain to Cloudflare

1. In dashboard, click "Add a Site"
2. Enter domain: `cfg.is`
3. Choose plan: **Free** (sufficient for our needs)
4. Click "Add Site"

**Status:** ⏳ Pending

### Step 1.3: Update Nameservers

Cloudflare will provide 2 nameservers like:
```
alexa.ns.cloudflare.com
brad.ns.cloudflare.com
```

1. Login to your domain registrar (where you registered cfg.is)
2. Find DNS/Nameserver settings
3. Replace existing nameservers with Cloudflare nameservers
4. Save changes

**Wait time:** 10-30 minutes for DNS propagation (can be up to 24 hours)

**Status:** ⏳ Pending

**Nameservers provided:**
```
(Fill in after Cloudflare provides them)
```

---

## Phase 2: Cloudflare Pages Setup

### Step 2.1: Create Pages Project

1. In Cloudflare dashboard, go to "Workers & Pages" (left sidebar)
2. Click "Create application" → "Pages"
3. Choose deployment method

**Status:** ⏳ Pending

### Option A: GitHub Integration (Recommended)

**Pros:** Auto-deployment on git push, version history, easy rollbacks

**Steps:**
1. Click "Connect to Git"
2. Authorize Cloudflare to access GitHub
3. Select repository: `cfg-is/cfgms`
4. Configure build:
   - **Project name:** `cfgis` (or your choice)
   - **Production branch:** `main`
   - **Build command:** (leave empty - we're deploying pre-built static files)
   - **Build output directory:** `website`
   - **Root directory (advanced):** `website`
5. Click "Save and Deploy"

First deployment will start automatically.

**Status:** ⏳ Pending

### Option B: Direct Upload (Alternative)

**Pros:** Quick, no GitHub integration needed
**Cons:** Manual uploads for updates

**Steps:**
1. Click "Upload assets"
2. Name your project: `cfgis`
3. Navigate to `/home/jrdn/git/cfg.is/cfgms/website/`
4. Drag and drop ALL files and folders
5. Click "Deploy site"

**Status:** ⏳ Pending (if not using GitHub integration)

---

## Phase 3: Custom Domain Configuration

### Step 3.1: Add Custom Domain to Pages Project

1. After deployment completes, go to your Pages project
2. Click "Custom domains" tab
3. Click "Set up a custom domain"
4. Enter: `cfg.is` (apex domain)
5. Click "Continue"

Cloudflare will automatically:
- Create DNS records (CNAME or A/AAAA records)
- Provision SSL certificate (can take 1-5 minutes)
- Configure HTTPS

**Status:** ⏳ Pending

### Step 3.2: Verify SSL Certificate

1. Wait for "Active" status on custom domain
2. Test in browser: https://cfg.is
3. Click padlock icon to verify SSL certificate is valid

**Expected result:** Valid SSL certificate issued by Cloudflare

**Status:** ⏳ Pending

---

## Phase 4: docs.cfg.is Redirect Setup

### Step 4.1: Create Redirect Rule

1. In Cloudflare dashboard → "Rules" → "Redirect Rules"
2. Click "Create rule"
3. Rule name: `docs-redirect`
4. Configure:
   - **When incoming requests match:**
     - Field: `Hostname`
     - Operator: `equals`
     - Value: `docs.cfg.is`
   - **Then:**
     - Type: `Dynamic`
     - Expression: `concat("https://github.com/cfg-is/cfgms/blob/main/", http.request.uri.path)`
     - Status code: `302` (Temporary Redirect - can change to 301 later)
5. Click "Deploy"

**Alternative (simpler):** Static redirect to `https://github.com/cfg-is/cfgms/blob/main/README.md`

**Status:** ⏳ Pending

### Step 4.2: Create DNS Record for docs.cfg.is

1. Cloudflare dashboard → "DNS" → "Records"
2. Add record:
   - **Type:** `CNAME`
   - **Name:** `docs`
   - **Target:** `cfg.is` (or your Pages project URL)
   - **Proxy status:** Proxied (orange cloud)
3. Save

**Status:** ⏳ Pending

---

## Phase 5: Verification & Testing

### Step 5.1: Test All URLs

Test the following URLs in browser (incognito/private mode):

- [ ] https://cfg.is - Should load landing page
- [ ] https://www.cfg.is - Should redirect to https://cfg.is (auto-configured by Cloudflare)
- [ ] https://cfg.is/security/ - Should load security page
- [ ] https://cfg.is/security/pgp-key.asc - Should download/display PGP key
- [ ] https://docs.cfg.is - Should redirect to GitHub README

**Status:** ⏳ Pending

### Step 5.2: Verify SSL Certificates

Run SSL test for all domains:

```bash
# Test main domain
openssl s_client -connect cfg.is:443 -servername cfg.is < /dev/null 2>/dev/null | openssl x509 -noout -subject -dates

# Test docs subdomain
openssl s_client -connect docs.cfg.is:443 -servername docs.cfg.is < /dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

**Expected:** Valid Cloudflare SSL certificates with future expiration dates

**Status:** ⏳ Pending

### Step 5.3: Test PGP Email Workflow (End-to-End)

1. Download public key from website:
   ```bash
   curl https://cfg.is/security/pgp-key.asc > /tmp/test-pgp-key.asc
   gpg --import /tmp/test-pgp-key.asc
   ```

2. Create test message:
   ```bash
   echo "Test security report" > /tmp/test-message.txt
   ```

3. Encrypt with downloaded key:
   ```bash
   gpg --encrypt --armor --recipient security@cfg.is /tmp/test-message.txt
   ```

4. Verify you can decrypt with your private key:
   ```bash
   gpg --decrypt /tmp/test-message.txt.asc
   ```

**Expected:** Successful encryption/decryption

**Status:** ⏳ Pending

### Step 5.4: Check for Broken Links

Verify all links in documentation still work:

```bash
# From cfgms repo root
cd docs
grep -r "https://cfg.is" .
grep -r "https://docs.cfg.is" .
grep -r "https://portal.example.com" .
```

Check that:
- cfg.is links point to actual deployed pages
- docs.cfg.is links work
- example.com placeholders are clearly marked as examples

**Status:** ⏳ Pending

---

## Phase 6: Analytics & Monitoring (Optional)

### Step 6.1: Enable Web Analytics

1. Cloudflare dashboard → "Analytics" → "Web Analytics"
2. Enable for cfg.is
3. View traffic, performance metrics

**Status:** ⏳ Pending (optional)

### Step 6.2: Set Up Email Monitoring

Configure email monitoring for security inbox:

- [ ] Set up email client (Thunderbird/Mailvelope) on work machine
- [ ] Configure desktop/mobile notifications for security@cfg.is
- [ ] Test receiving encrypted email
- [ ] Document monitoring procedures for team

**Status:** ⏳ Pending (can be post-launch)

---

## Phase 7: Documentation Updates

### Step 7.1: Update Email Inventory with Final Status

Update `docs/infrastructure/email-url-inventory.md`:

- Mark all items as ✅ Complete
- Add actual deployment dates
- Document any deviations from plan

**Status:** ⏳ Pending

### Step 7.2: Commit Website Files

```bash
cd /home/jrdn/git/cfg.is/cfgms

# Check what we're committing
git status

# Add website files
git add website/
git add docs/infrastructure/cloudflare-deployment-checklist.md

# Commit
git commit -m "feat: Add cfg.is website with landing page and security page

- Create main landing page with feature grid
- Deploy security page for vulnerability reporting
- Include PGP public key for encrypted reports
- Add Cloudflare Pages deployment documentation
- Add deployment checklist for infrastructure setup

Story: #248"

# Push to develop branch
git push origin feature/story-248-email-web-infrastructure
```

**Status:** ⏳ Pending

---

## Success Criteria

All of the following must be complete:

- [x] Email addresses created (security@, licensing@, conduct@cfg.is)
- [x] PGP key generated and uploaded to keyserver
- [x] Website files created in `website/` directory
- [ ] Cloudflare account set up with cfg.is domain
- [ ] DNS configured and propagated
- [ ] Main landing page deployed to https://cfg.is
- [ ] Security page deployed to https://cfg.is/security/
- [ ] PGP key accessible at https://cfg.is/security/pgp-key.asc
- [ ] docs.cfg.is redirect configured
- [ ] All URLs tested with valid SSL
- [ ] Documentation updated
- [ ] Changes committed to git

---

## Troubleshooting

### DNS Not Propagating

**Symptoms:** Domain doesn't resolve after updating nameservers

**Solutions:**
- Wait longer (can take up to 24 hours, usually 30 minutes)
- Check nameserver propagation: https://www.whatsmydns.net
- Verify nameservers are correctly entered at registrar

### SSL Certificate Not Provisioning

**Symptoms:** "Your connection is not private" error

**Solutions:**
- Wait 5-10 minutes for certificate provisioning
- Ensure DNS is fully propagated first
- Check Cloudflare SSL/TLS settings (should be "Full" or "Full (strict)")
- Disable "Always Use HTTPS" temporarily, then re-enable

### Pages Build Failing (GitHub Integration)

**Symptoms:** Deployment shows "Failed"

**Solutions:**
- Check build log for errors
- Verify root directory is set to `website`
- Ensure build command is empty (we're deploying static files)
- Try direct upload method instead

### 404 Not Found on Subpages

**Symptoms:** https://cfg.is works but https://cfg.is/security/ returns 404

**Solutions:**
- Verify `security/index.html` exists in deployment
- Check Cloudflare Pages deployment preview to see what files were deployed
- Re-deploy if files are missing

---

## Next Steps After Deployment

1. **Monitor security inbox** for vulnerability reports
2. **Set up mailing list** for security-announce@cfg.is (deferred to future story)
3. **Add signup forms** when ready (using Cloudflare Workers/Edge Functions)
4. **Consider Cloudflare Analytics** for traffic insights
5. **Plan v1.0 launch** announcement on website

---

**Date Started:** 2025-11-23
**Date Completed:** _____________
**Deployed By:** _____________
**Notes:**
