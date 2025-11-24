# CFGMS Website (cfg.is)

This directory contains the static website for https://cfg.is hosted on Cloudflare Pages.

## Structure

```
website/
├── index.html              # Main landing page
├── security/
│   ├── index.html         # Security policy and vulnerability reporting
│   └── pgp-key.asc        # PGP public key for encrypted security reports
└── README.md              # This file
```

## Deployment

### Cloudflare Pages Setup

1. **Login to Cloudflare Dashboard**
   - Go to https://dash.cloudflare.com
   - Navigate to "Workers & Pages"

2. **Create New Pages Project**
   - Click "Create application" → "Pages"
   - Choose deployment method:

#### Option A: GitHub Integration (Recommended)
   - Connect to GitHub repository: `cfg-is/cfgms`
   - Configure build settings:
     - **Build command:** (leave empty)
     - **Build output directory:** `website`
     - **Root directory:** `website`
   - Click "Save and Deploy"

#### Option B: Direct Upload
   - Choose "Direct Upload"
   - Upload contents of this `website/` directory
   - Deploy

3. **Configure Custom Domain**
   - In your Pages project → "Custom domains"
   - Add `cfg.is` (apex domain)
   - Cloudflare will automatically provision SSL certificate
   - DNS records will be created automatically

4. **DNS Configuration**
   - If cfg.is is not already on Cloudflare:
     - Add site in Cloudflare dashboard
     - Update nameservers at registrar to Cloudflare nameservers
     - Wait for DNS propagation (10-30 minutes)

### Subdomain Setup (docs.cfg.is)

For `docs.cfg.is`, create a redirect:

1. **In Cloudflare Dashboard** → "Rules" → "Redirect Rules"
2. Create rule:
   - **If:** Hostname equals `docs.cfg.is`
   - **Then:** Dynamic redirect to `https://github.com/cfg-is/cfgms/blob/main/README.md`
   - **Status code:** 302 (Temporary) initially, 301 (Permanent) when stable

Alternatively, use Cloudflare Pages for a dedicated docs site later.

## Local Testing

Open `index.html` in a browser, or use a simple HTTP server:

```bash
# Python 3
cd website
python3 -m http.server 8000

# Then visit http://localhost:8000
```

## Updates

### Updating Security Page

The security page source is in `docs/security/security-page-draft.html`. To update:

```bash
cp docs/security/security-page-draft.html website/security/index.html
git add website/security/index.html
git commit -m "docs: Update security page"
git push
```

If using GitHub integration, Cloudflare Pages will auto-deploy on push to main/develop.

### Updating PGP Key

If the PGP key needs to be rotated:

```bash
# Export new public key
gpg --armor --export security@cfg.is > docs/security/pgp-key.asc

# Copy to website
cp docs/security/pgp-key.asc website/security/pgp-key.asc

# Update fingerprint in security page
# Edit docs/security/security-page-draft.html with new fingerprint
# Then copy to website as shown above

# Commit and push
git add website/security/pgp-key.asc website/security/index.html
git commit -m "security: Rotate PGP key"
git push
```

## URLs

- **Main site:** https://cfg.is
- **Security page:** https://cfg.is/security/
- **PGP public key:** https://cfg.is/security/pgp-key.asc
- **Documentation:** https://docs.cfg.is (redirects to GitHub)

## Maintenance

- **SSL Certificates:** Auto-renewed by Cloudflare
- **DNS:** Managed in Cloudflare dashboard
- **Analytics:** Available in Cloudflare Pages dashboard
- **Edge Functions:** Can be added in `functions/` directory if needed

## Future Enhancements

When ready to add signup forms or subscription management:

1. Create `functions/` directory for Cloudflare Workers
2. Add form submission handlers as Edge Functions
3. Integrate with Stripe for payment processing
4. Use Cloudflare D1 for database storage
5. See Cloudflare Pages documentation: https://developers.cloudflare.com/pages/
