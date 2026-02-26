# ACME Module

## Purpose and scope

The ACME Module provides automated TLS certificate management via the ACME protocol (RFC 8555). It uses the lego library to interact with ACME-compatible servers such as Let's Encrypt for certificate issuance and renewal. Supports both HTTP-01 and DNS-01 challenge types with Cloudflare, Route53, and Azure DNS providers.

## Configuration options

The module accepts configuration in YAML format:

```yaml
state: present              # "present" or "absent"
domains:                    # SANs; first is primary domain
  - api.example.com
  - "*.api.example.com"
email: admin@example.com    # ACME account email
challenge_type: dns-01      # "http-01" or "dns-01"
dns_provider: cloudflare    # "cloudflare", "route53", "azure_dns"
dns_credential_key: acme/cf # Key in CFGMS secrets store
key_type: ec256             # "rsa2048", "rsa4096", "ec256", "ec384"
renewal_threshold_days: 30  # Days before expiry to trigger renewal
staging: false              # Use Let's Encrypt staging environment
http_bind_address: ":80"    # Bind address for HTTP-01 challenges
cert_store_path: ""         # Override default certificate store path
```

## Usage examples

1. DNS-01 with Cloudflare (wildcard support):

    ```yaml
    resources:
      - name: api-certificate
        module: acme
        resource_id: api.example.com
        config:
          state: present
          domains: [api.example.com, "*.api.example.com"]
          email: admin@example.com
          challenge_type: dns-01
          dns_provider: cloudflare
          dns_credential_key: acme/cloudflare-api-token
    ```

2. HTTP-01 for single domain:

    ```yaml
    resources:
      - name: web-certificate
        module: acme
        resource_id: www.example.com
        config:
          state: present
          domains: [www.example.com]
          email: admin@example.com
          challenge_type: http-01
    ```

## Known limitations

1. DNS-01 currently supports three providers: Cloudflare, Route53, Azure DNS
2. HTTP-01 requires port 80 to be accessible from the internet
3. Wildcard certificates require DNS-01 challenge type
4. Rate limits apply per Let's Encrypt policies (50 certs/domain/week)
5. Integration tests require a running Pebble ACME test server

## Security considerations

1. Private keys are stored with 0600 permissions; parent directories use 0700
2. DNS credentials are retrieved from the CFGMS secrets store (encrypted at rest)
3. Environment variables for DNS providers are set/unset under mutex to prevent concurrent credential pollution
4. ACME account keys use ECDSA P-256
5. Staging mode available for testing without hitting production rate limits
