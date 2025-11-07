# CFGMS Security Documentation

## Local Credential Setup

CFGMS uses a hybrid approach for local development credentials:
- **Configuration** (client IDs, tenant IDs, domains) stored in `.env.local` (gitignored)
- **Secrets** (client secrets, API keys) stored in OS keychain (encrypted)

### Quick Start

1. **Copy the example configuration:**
   ```bash
   cp .env.local.example .env.local
   ```

2. **Edit `.env.local` with your Azure credentials:**
   - Get your Azure App Registration details from Azure Portal
   - Fill in `M365_CLIENT_ID`, `M365_TENANT_ID`, `M365_TENANT_DOMAIN`
   - **IMPORTANT**: Leave `M365_CLIENT_SECRET=USE_KEYCHAIN` (placeholder - never use actual secret)

3. **Store your client secret securely in OS keychain:**
   ```bash
   ./scripts/migrate-credentials-to-keychain.sh
   ```

   **You will be prompted to enter your client secret securely.**

   This will:
   - Prompt for your client secret (hidden input)
   - Store it in OS-encrypted keychain
   - Never write the secret to disk in plaintext

4. **Load credentials for testing:**
   ```bash
   source ./scripts/load-credentials-from-keychain.sh
   ```

5. **Run tests:**
   ```bash
   go test ./features/modules/m365/...
   ```

**SECURITY PRINCIPLE**: Client secrets are NEVER stored in plaintext files, even temporarily. The keychain is the ONLY acceptable storage location for secrets in development.

### Why This Approach?

**Security Benefits:**
- Client secrets stored in OS-encrypted keychain (AES-256 on Linux, AES-128 on macOS)
- Protected by your login password
- Never stored in plaintext on disk
- Automatically cleared when you log out

**Developer Benefits:**
- Easy setup from `.env.local.example`
- All config in one place (`.env.local`)
- Works with standard OAuth2 workflows
- CI/CD compatible (uses environment variables)

### OAuth2 Security Model

In OAuth2:
- **Public values** (safe in `.env.local`):
  - Client ID
  - Tenant ID
  - Redirect URLs
  - Domains

- **Private values** (stored in keychain):
  - Client Secret
  - Refresh Tokens
  - API Keys

This is why we can safely keep client IDs and tenant IDs in `.env.local` - they appear in browser URLs during OAuth flows anyway!

### For OSS Contributors

If you don't need M365 integration:
- Skip the credential setup
- Tests will be skipped when credentials aren't available
- Set `ALLOW_SKIP_INTEGRATION=true` for permissive mode

### Related Documentation

- [Test Credential Security](./test-credential-security.md) - Security practices for test credentials
- [Certificate Security](./certificate-security.md) - Development certificate management
- [Sensitive Data Scan Results](./sensitive-data-scan-results.md) - Repository security audit

### Platform Support

- **Linux**: GNOME Keyring (via `secret-tool`)
- **macOS**: Keychain Access (via `security` command)
- **Windows**: Not yet supported (use `.env.local` only)

---

**Security Note**: Never commit `.env.local` to git. It's already in `.gitignore`, but always verify before pushing!
