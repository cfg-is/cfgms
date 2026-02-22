# CFGMS Quick Start Guide

**Get productive with CFGMS in under 10 minutes!**

CFGMS is flexible - you can use it three different ways. Pick the one that matches your needs:

## Table of Contents

- [Option A: Standalone Steward](#option-a-standalone-steward) (5 minutes) - **Start here if you're new!**
- [Option B: Standalone Controller](#option-b-standalone-controller-cloud-apis) (10 minutes) - Cloud automation only
- [Option C: Controller + Stewards](#option-c-controller--stewards-full-platform) (15 minutes) - Fleet management

---

## Option A: Standalone Steward

**Perfect for**: Learning CFGMS, single-server management, edge devices, development

**Time**: 5 minutes

### What You'll Learn

- Run CFGMS without any server infrastructure
- Create local configuration files
- Manage files, directories, and packages
- See immediate results

### Prerequisites

- Go 1.25+ installed
- Linux, macOS, or Windows

### Step 1: Get CFGMS

```bash
# Clone the repository
git clone https://github.com/cfg-is/cfgms.git
cd cfgms

# Build the steward
make build-steward
```

### Step 2: Create Your First Configuration

```bash
# Create config directory
sudo mkdir -p /etc/cfgms

# Create a simple configuration file
sudo tee /etc/cfgms/config.yaml > /dev/null <<EOF
steward:
  id: quickstart-steward

resources:
  # Create a file
  - name: hello-file
    module: file
    config:
      path: /tmp/hello-cfgms.txt
      content: |
        Hello from CFGMS!
        This file was created by CFGMS standalone mode.
        No controller, no network, no complexity!
      state: present
      mode: "0644"

  # Create a directory
  - name: test-directory
    module: directory
    config:
      path: /tmp/cfgms-test
      state: present
      mode: "0755"

  # Create a second file in that directory
  - name: info-file
    module: file
    config:
      path: /tmp/cfgms-test/info.txt
      content: "CFGMS standalone mode is working!"
      state: present
EOF
```

### Step 3: Run CFGMS

```bash
# Run steward in standalone mode
sudo ./bin/cfgms-steward -config /etc/cfgms/config.yaml
```

You should see:
```
INFO: Starting CFGMS Steward in standalone mode
INFO: Loading configuration from /etc/cfgms/config.yaml
INFO: Applying configuration...
INFO: [file] Creating /tmp/hello-cfgms.txt
INFO: [directory] Creating /tmp/cfgms-test
INFO: [file] Creating /tmp/cfgms-test/info.txt
INFO: Configuration applied successfully (3 changes)
```

### Step 4: Verify It Worked

```bash
# Check the file was created
cat /tmp/hello-cfgms.txt

# Check the directory
ls -la /tmp/cfgms-test/

# Read the info file
cat /tmp/cfgms-test/info.txt
```

### Step 5: Make a Change

```bash
# Modify the configuration
sudo tee /etc/cfgms/config.yaml > /dev/null <<EOF
steward:
  id: quickstart-steward

resources:
  - name: hello-file
    module: file
    config:
      path: /tmp/hello-cfgms.txt
      content: "Updated content! CFGMS detects changes."
      state: present
EOF

# Run again
sudo ./bin/cfgms-steward -config /etc/cfgms/config.yaml
```

CFGMS will detect the change and update only what's needed!

### What's Next?

- Try more modules: `package`, `service`, `firewall`
- Learn about [YAML templating](docs/architecture/template-engine-design.md)
- Explore [module documentation](docs/modules/)

---

## Option B: Standalone Controller (Cloud APIs)

**Perfect for**: M365 automation, cloud management, no endpoint agents needed

**Time**: 10 minutes

### What You'll Learn

- Run the workflow engine
- Execute workflows against cloud APIs
- Manage Microsoft 365 resources
- No endpoint agents required

### Prerequisites

- Go 1.25+ installed
- (Optional) Microsoft 365 sandbox for testing - [Setup guide](docs/CSP_SANDBOX_SETUP_GUIDE.md)

### Step 1: Build the Controller

```bash
# Clone if you haven't already
git clone https://github.com/cfg-is/cfgms.git
cd cfgms

# Build controller and CLI
make build-controller build-cli
```

### Step 2: Create Minimum Configuration

The controller requires a storage provider. Create a minimum configuration file:

```bash
# Create config file
cat > controller.yaml <<EOF
storage:
  provider: git
  config:
    repository_path: ./data/cfgms-storage
    branch: main
    auto_init: true

certificate:
  enable_cert_management: true
  auto_generate: true
  ca_path: ./certs/ca

logging:
  provider: file
  level: INFO
  file:
    directory: ./logs
EOF
```

### Step 3: Start the Controller

```bash
# Create required directories
mkdir -p ./data ./certs ./logs

# Start controller (reads controller.yaml from current directory)
./bin/controller

# You should see:
# INFO: Initializing storage provider: git
# INFO: Starting MQTT broker
# INFO: Controller ready
```

### Step 4: Create a Simple Workflow

```bash
# Create a workflow file
cat > example-workflow.yaml <<EOF
name: hello-workflow
description: Simple example workflow

steps:
  - name: greet
    action: log
    params:
      message: "Hello from CFGMS workflow engine!"
      level: "INFO"

  - name: show-time
    action: log
    params:
      message: "Current time: {{ now }}"
      level: "INFO"
EOF
```

### Step 5: Run the Workflow

```bash
# In another terminal
./bin/cfg workflow run example-workflow.yaml

# You should see:
# Running workflow: hello-workflow
# Step 1/2: greet - OK
# Step 2/2: show-time - OK
# Workflow completed successfully
```

### Step 6: Try an M365 Workflow (Optional)

If you have M365 credentials:

```bash
# Create M365 workflow
cat > m365-workflow.yaml <<EOF
name: m365-user-check
description: Check M365 users

steps:
  - name: list-users
    module: entra_user
    action: list
    params:
      filter: "startswith(displayName, 'Test')"

  - name: log-count
    action: log
    params:
      message: "Found {{ steps.list-users.count }} test users"
EOF

# Run it
./bin/cfg workflow run m365-workflow.yaml
```

### What's Next?

- Explore [workflow debugging](docs/architecture/workflow-debug-system.md)
- Learn about [M365 integration](docs/M365_INTEGRATION_GUIDE.md)
- Check out [workflow modules](docs/architecture/modules/README.md)

---

## Option C: Controller + Stewards (Full Platform)

**Perfect for**: Fleet management, MSP operations, enterprise scale

**Time**: 15 minutes

### What You'll Learn

- Set up centralized management
- Auto-register stewards with automatic certificates
- Push configurations to multiple endpoints
- Monitor fleet health

### Prerequisites

- Go 1.25+ installed
- At least 2 machines (or VMs) for testing
- Network connectivity between machines

### Step 1: Build Everything

```bash
# Clone if you haven't already
git clone https://github.com/cfg-is/cfgms.git
cd cfgms

# Build all components
make build
```

### Step 2: Start the Controller

First, create the controller configuration (same as Option B):

```bash
# Create config file
cat > controller.yaml <<EOF
storage:
  provider: git
  config:
    repository_path: ./data/cfgms-storage
    branch: main
    auto_init: true

certificate:
  enable_cert_management: true
  auto_generate: true
  ca_path: ./certs/ca

logging:
  provider: file
  level: INFO
  file:
    directory: ./logs

mqtt:
  enabled: true
  listen_addr: "0.0.0.0:1883"
  enable_tls: true

quic:
  enabled: true
  listen_addr: "0.0.0.0:4433"
EOF

# Create required directories and start controller
mkdir -p ./data ./certs ./logs
./bin/controller

# You should see:
# INFO: Initializing storage provider: git
# INFO: Starting MQTT broker
# INFO: Controller ready
```

### Step 3: Create Registration Token

Registration tokens allow stewards to authenticate with the controller:

```bash
# In another terminal, create a registration token
# Note: cfgcli token management will be available in a future release
# For now, tokens are created via direct API calls:

curl -X POST http://localhost:9080/api/v1/admin/registration-tokens \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "default",
    "group": "production",
    "validity_days": 7,
    "single_use": false
  }'

# Returns:
# {"token": "cfgms_reg_abc123xyz..."}

# Save this token for the next step
```

### Step 4: Register First Steward

```bash
# On the controller machine (for testing)
# Use the token from Step 3
./bin/cfgms-steward -regtoken cfgms_reg_abc123xyz...

# You should see:
# INFO: Registering with controller via MQTT+QUIC
# INFO: Certificate obtained
# INFO: Connected to controller
# INFO: Steward ready
```

### Step 5: Register Second Steward (Different Machine)

```bash
# On another machine
# Use the same token (if single_use was false)
./bin/cfgms-steward -regtoken cfgms_reg_abc123xyz...

# Same automatic process!
```

### Step 6: List Your Fleet

```bash
# On controller machine
./bin/cfg steward list

# Output:
# HOSTNAME         STATUS   LAST SEEN        PLATFORM
# test-steward-1   healthy  2s ago           linux/amd64
# test-steward-2   healthy  5s ago           linux/arm64
```

### Step 7: Push Configuration to Fleet

```bash
# Create fleet-wide configuration
cat > fleet-config.yaml <<EOF
# Apply to all stewards
targets:
  - all

resources:
  - name: motd-file
    module: file
    config:
      path: /etc/motd
      content: |
        ========================================
        Managed by CFGMS Controller
        Last updated: {{ now }}
        ========================================
      state: present

  - name: log-directory
    module: directory
    config:
      path: /var/log/cfgms
      state: present
      mode: "0755"
EOF

# Apply to entire fleet
./bin/cfg config apply fleet-config.yaml

# Output:
# Applying configuration to 2 stewards...
# test-steward-1: OK (2 changes)
# test-steward-2: OK (2 changes)
# Fleet configuration applied successfully
```

### Step 8: Check Steward Health

```bash
# Get detailed status
./bin/cfg steward status test-steward-1

# Output:
# Hostname: test-steward-1
# Status: healthy
# Platform: linux/amd64
# CPU: 15%
# Memory: 512MB / 4GB
# Uptime: 5m 32s
# Last config: 1m ago (2 changes)
# Drift detected: No
```

### What's Next?

- Learn about [multi-tenancy](docs/guides/configuration-inheritance.md)
- Set up [production certificates](docs/development/security-setup.md)
- Explore [DNA and drift detection](docs/architecture/rollback-design.md)
- Scale to [50,000+ stewards](docs/architecture/ha-commercial-split.md)

---

## Comparison: Which Mode Should I Use?

| Feature | Standalone Steward | Standalone Controller | Controller + Stewards |
|---------|-------------------|----------------------|----------------------|
| **Setup Time** | 5 minutes | 10 minutes | 15 minutes |
| **Server Required** | No | Yes (1) | Yes (1) |
| **Network Required** | No | No | Yes |
| **Endpoint Management** | Yes (local) | No | Yes (centralized) |
| **Cloud APIs (M365, AWS)** | No | Yes | Yes |
| **Fleet Management** | No | No | Yes |
| **Drift Detection** | Local only | No | Yes |
| **Certificate Management** | None | Auto | Auto (like Salt) |
| **Multi-Tenant** | No | Yes | Yes |
| **Scale** | 1 device | N/A | 50,000+ devices |
| **Best For** | Learning, edge | Cloud automation | MSP operations |

## Common Questions

### Q: Do I need to choose one mode?

**A**: No! You can mix them. For example:
- Controller for M365 automation
- Standalone stewards on edge devices without network
- Fleet-managed stewards for your main infrastructure

### Q: Can I switch modes later?

**A**: Yes! Start with standalone steward to learn, then add a controller when you need centralized management.

### Q: Do I really not need to manage certificates?

**A**: In development mode, certificates are auto-generated and auto-approved (like `salt-key -A`). For production, you can use external PKI or manually approve registrations.

### Q: How is this different from Ansible/Salt/Chef?

**A**:
- **Like Ansible**: Standalone steward mode works the same way
- **Like Salt**: Auto-certificate management, master-minion architecture
- **Unique**: Workflow engine for cloud APIs, DNA/drift detection, MSP multi-tenancy

## Environment Variables in Configuration

CFGMS supports explicit environment variable references in configuration files using shell-style syntax. This provides better security than implicit environment variable usage.

### Basic Syntax

```yaml
steward:
  id: ${HOSTNAME}                           # Expands to hostname env var
  log_dir: ${CFGMS_LOG_DIR:-/var/log/cfgms} # Default if unset
  controller_url: https://fixed.example.com # Literal value (no env var)

resources:
  - name: app-config
    module: file
    config:
      path: /etc/myapp/config.json
      content: |
        {
          "api_key": "${API_KEY}",
          "environment": "${ENVIRONMENT:-production}"
        }
```

### Syntax Options

| Pattern | Behavior |
|---------|----------|
| `${VAR}` | Expands to VAR value. **Fails at startup if VAR is unset** |
| `${VAR:-default}` | Uses default if VAR is unset. Safe for optional values |
| `${VAR:=default}` | Sets VAR to default if unset, then expands |

### Security Benefits

1. **Audit Trail**: `cat config.yaml` shows exactly which values come from env vars
2. **Attack Surface**: Attacker must modify both config file AND env var to hijack settings
3. **Fail-Safe**: Missing required env vars cause immediate startup failure (no silent hijacking)

### Example: Database Configuration

```yaml
logging:
  provider: timescale
  config:
    host: ${CFGMS_TIMESCALE_HOST:-localhost}
    port: ${CFGMS_TIMESCALE_PORT:-5432}
    database: ${CFGMS_TIMESCALE_DATABASE:-cfgms}
    username: ${CFGMS_TIMESCALE_USER:-cfgms}
    password: ${CFGMS_TIMESCALE_PASSWORD}   # Required - must be set
```

With this configuration:
- `host`, `port`, `database`, `username` use sensible defaults if not set
- `password` (`CFGMS_TIMESCALE_PASSWORD`) is required and will fail startup if missing

### Migration from Implicit Env Vars

If you were previously relying on implicit environment variables like `CFGMS_LOG_DIR`:

**Before** (implicit, no longer supported):
```bash
export CFGMS_LOG_DIR=/custom/log/path
./bin/cfgms-steward  # Would pick up env var implicitly
```

**After** (explicit, recommended):
```yaml
# In your config.yaml or hostname.cfg:
logging:
  config:
    directory: ${CFGMS_LOG_DIR:-/var/log/cfgms}
```

This makes your configuration self-documenting and more secure.

---

## Troubleshooting

### "Permission denied" when writing to /etc/cfgms

```bash
# Use sudo for system paths
sudo ./bin/cfgms-steward -config /etc/cfgms/config.yaml

# Or use a user-writable path:
mkdir -p ~/.cfgms
# Create config at ~/.cfgms/config.yaml then run:
./bin/cfgms-steward -config ~/.cfgms/config.yaml
```

### "Controller not reachable"

```bash
# Check controller is running
curl http://localhost:9080/api/v1/health

# Check firewall allows port 9080
sudo ufw allow 9080
```

### "Certificate error"

```bash
# In development mode, controller auto-approves registrations
# Make sure controller is running in dev mode (default)

# For production, manually approve:
./bin/cfg cert requests list
./bin/cfg cert requests approve <steward-hostname>
```

## Next Steps

After completing this quick start:

1. **Read the documentation**:
   - [ARCHITECTURE.md](ARCHITECTURE.md) - System design
   - [DEVELOPMENT.md](DEVELOPMENT.md) - Detailed setup guide
   - [CONTRIBUTING.md](CONTRIBUTING.md) - Contributing to CFGMS

2. **Try advanced features**:
   - [M365 Integration](docs/M365_INTEGRATION_GUIDE.md)
   - [Workflow Debugging](docs/architecture/workflow-debug-system.md)
   - [Multi-Tenancy](docs/guides/configuration-inheritance.md)

3. **Get involved**:
   - [GitHub Issues](https://github.com/cfg-is/cfgms/issues) - Report bugs or request features
   - [GitHub Discussions](https://github.com/cfg-is/cfgms/discussions) - Ask questions
   - [Roadmap](docs/product/roadmap.md) - See what's coming

---

**Welcome to CFGMS! We're excited to see what you build.** 🚀
