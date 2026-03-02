# CFGMS Home Lab Deployment Checklist

**Story #391**: This checklist ensures all prerequisites and deployment steps are validated before deploying CFGMS to your home lab environment.

**Last Updated**: 2026-02-28
**CFGMS Version**: v0.9.x

## Pre-Deployment Checklist

### Infrastructure Requirements

- [ ] **Controller VM** provisioned (Debian 12+ or Ubuntu 22.04+ recommended)
  ```bash
  cat /etc/os-release  # Verify OS
  ```

- [ ] **Steward VM(s)** provisioned (Linux, Windows, or macOS)
  - See [platform-support.md](platform-support.md) for supported platforms

- [ ] **Sufficient Resources** available on host machines:
  - **CPU**: Minimum 2 cores, recommended 4+ cores
  - **RAM**: Minimum 4GB, recommended 8GB+
  - **Disk**: Minimum 20GB free space, recommended 50GB+
  ```bash
  df -h /              # Disk space
  free -h              # Memory
  nproc                # CPU cores
  ```

- [ ] **Network Ports** available on controller (not already in use):
  - `9080`: REST API
  - `1883`: MQTT broker (embedded in controller)
  - `4433`: QUIC data plane
  ```bash
  # Check if ports are available on controller
  sudo ss -tlnp | grep -E '9080|1883'
  sudo ss -ulnp | grep 4433
  ```

- [ ] **Firewall Rules** configured on controller:
  ```bash
  sudo ufw allow 9080/tcp   # REST API
  sudo ufw allow 1883/tcp   # MQTT control plane
  sudo ufw allow 4433/udp   # QUIC data plane
  ```

### Repository and Build

- [ ] **CFGMS Repository** cloned and up to date
  ```bash
  git clone https://github.com/cfg-is/cfgms.git
  cd cfgms
  git checkout main
  git pull origin main
  ```

- [ ] **Go Environment** configured (version 1.25+ required)
  ```bash
  go version  # Should show go1.25 or later
  ```

- [ ] **All Tests Passing** before deployment
  ```bash
  make test-complete  # MUST pass 100%
  ```

- [ ] **Binaries Built** successfully
  ```bash
  make build  # Creates: bin/controller, bin/cfgms-steward, bin/cfg
  ```

### Security Prerequisites

- [ ] **Certificate Management** configured
  - Decision: Use auto-generated certificates (recommended for home lab)
  - OR: Bring your own CA and certificates (advanced)

- [ ] **Storage Backend** selected
  - Decision: Git with SOPS encryption (recommended)
  - OR: Database backend (PostgreSQL/TimescaleDB)

- [ ] **Secrets Management** planned
  - All secrets will be encrypted at rest
  - No cleartext credentials in configuration files
  - Environment variables or OS keychain for sensitive data

## Deployment Checklist

### Step 1: Controller Deployment

- [ ] **Binary Deployed** to controller VM
  ```bash
  scp bin/controller user@controller-vm:/usr/local/bin/cfgms-controller
  ssh user@controller-vm "chmod +x /usr/local/bin/cfgms-controller"
  ```

- [ ] **Configuration Created** at `/etc/cfgms/controller.cfg`
  ```bash
  sudo mkdir -p /etc/cfgms /var/lib/cfgms/storage /var/lib/cfgms/certs /var/log/cfgms
  # See home-lab-deployment-guide.md Step 3b for full config
  ```

- [ ] **systemd Service Installed** and started
  ```bash
  # See home-lab-deployment-guide.md Step 3c for service file
  sudo systemctl daemon-reload
  sudo systemctl enable cfgms-controller
  sudo systemctl start cfgms-controller
  ```

- [ ] **Controller Health Verified**
  ```bash
  # Check service is running
  sudo systemctl status cfgms-controller

  # Check REST API responds
  curl http://localhost:9080/api/v1/health

  # Check logs for successful startup
  sudo journalctl -u cfgms-controller --no-pager -n 30
  # Look for: "Certificate manager initialized", "MQTT broker started",
  # "QUIC server listening on :4433", "REST API server listening on :9080"
  ```

- [ ] **Certificates Auto-Generated** (if using auto-generation)
  ```bash
  sudo journalctl -u cfgms-controller | grep "Certificate manager initialized"
  sudo journalctl -u cfgms-controller | grep "Generated server certificate"
  ```

### Step 2: Steward Deployment

- [ ] **Registration Token Created**
  ```bash
  curl -X POST http://localhost:9080/api/v1/admin/registration-tokens \
    -H "Content-Type: application/json" \
    -d '{"tenant_id": "default", "group": "production", "validity_days": 7}'
  # Save the token from the response
  ```

- [ ] **Steward Binary Deployed** to steward VM
  ```bash
  scp bin/cfgms-steward user@steward-vm:/usr/local/bin/cfgms-steward
  ssh user@steward-vm "chmod +x /usr/local/bin/cfgms-steward"
  ```

- [ ] **systemd Service Installed** and started
  ```bash
  # See home-lab-deployment-guide.md Step 5b for service file
  sudo systemctl daemon-reload
  sudo systemctl enable cfgms-steward
  sudo systemctl start cfgms-steward
  ```

- [ ] **Steward Registration Verified**
  ```bash
  sudo journalctl -u cfgms-steward | grep "Registration successful"
  sudo journalctl -u cfgms-steward | grep "Steward ID:"
  ```

- [ ] **MQTT Connection Verified**
  ```bash
  sudo journalctl -u cfgms-steward | grep "MQTT.*connected"
  sudo journalctl -u cfgms-controller | grep "steward.*connected"
  ```

### Step 3: E2E Validation

- [ ] **Upload Test Configuration**
  ```bash
  # Upload a simple test config (file module creating a test file)
  # Verify it appears in controller's storage backend
  ```

- [ ] **Verify Config Sync** via QUIC
  ```bash
  sudo journalctl -u cfgms-steward | grep "QUIC.*connected"
  sudo journalctl -u cfgms-steward | grep "Config.*fetched"
  sudo journalctl -u cfgms-steward | grep "signature.*verified"
  ```

- [ ] **Verify Module Execution**
  ```bash
  sudo journalctl -u cfgms-steward | grep "module.*executed"
  ```

- [ ] **Verify Status Reporting**
  ```bash
  sudo journalctl -u cfgms-controller | grep "config.*status"
  ```

- [ ] **Run E2E Tests** (validates full flow programmatically)
  ```bash
  cd test/integration/mqtt_quic
  go test -v -run TestRegistration -timeout 60s
  go test -v -run TestConfigSync -timeout 60s
  go test -v -run TestModuleExecution -timeout 60s
  go test -v -run TestHeartbeatFailover -timeout 60s
  go test -v -run TestMultiTenant -timeout 60s
  go test -v -run TestTLSSecurity -timeout 60s
  ```

### Step 4: Production Readiness

- [ ] **Security Hardening** applied:
  - [ ] Firewall rules configured (ports 9080, 1883, 4433 only)
  - [ ] TLS certificate verification enabled (default)
  - [ ] SOPS encryption keys secured
  - [ ] Registration tokens have appropriate expiry

- [ ] **Backup Strategy** implemented:
  - [ ] Git repository backed up (if using git storage)
  - [ ] Database backed up (if using database storage)
  - [ ] Certificate backup stored securely

- [ ] **Monitoring** configured:
  - [ ] Log aggregation (optional but recommended)
  - [ ] Health check monitoring (`curl http://controller:9080/api/v1/health`)
  - [ ] Disk space monitoring
  - [ ] systemd service restart policy verified

- [ ] **Documentation** created for your deployment:
  - [ ] Network diagram showing all components
  - [ ] Credentials storage location documented
  - [ ] Backup/restore procedures documented
  - [ ] Troubleshooting runbook created

## Post-Deployment Validation

### Functional Tests

- [ ] **Create Simple Config** for steward
- [ ] **Verify Config Sync** completes successfully
- [ ] **Verify Module Execution** (file, directory, script modules)
- [ ] **Verify Status Reporting** back to controller
- [ ] **Test Config Updates** (modify config, verify steward receives update)
- [ ] **Test Idempotency** (apply same config twice, verify no changes)

### Resilience Tests

- [ ] **Controller Restart Recovery**
  ```bash
  sudo systemctl restart cfgms-controller
  # Wait 15 seconds
  # Verify steward reconnects automatically
  sudo journalctl -u cfgms-steward --no-pager -n 20
  ```

- [ ] **Steward Restart Recovery**
  ```bash
  sudo systemctl restart cfgms-steward
  # Wait 10 seconds
  # Verify steward re-registers and reconnects
  sudo journalctl -u cfgms-steward --no-pager -n 20
  ```

- [ ] **Network Interruption Recovery** (optional - advanced)
  ```bash
  # Temporarily block network to controller from steward
  # Verify steward reconnects when connectivity restored
  ```

## Troubleshooting Quick Reference

### Common Issues

**Issue**: Controller fails to start
- Check: `sudo journalctl -u cfgms-controller --no-pager -n 50`
- Check: Ports 9080, 1883, 4433 available (`sudo ss -tlnp`)
- Check: Sufficient disk space for certificate generation

**Issue**: Steward cannot register
- Check: Registration token is valid and not expired
- Check: Controller is reachable from steward (`curl http://controller-vm:9080/api/v1/health`)
- Check: MQTT port 1883 is accessible (`nc -zv controller-vm 1883`)

**Issue**: QUIC connection fails
- Check: Port 4433/UDP is accessible from steward
- Check: Certificates are generated and valid
- Check: Controller logs for QUIC server startup

**Issue**: Config sync times out
- Check: Configuration is uploaded to controller
- Check: Steward received sync_config command
- Check: Signature verification passes
- Check: Module executor is initialized

**Issue**: Status reports not received
- Check: Controller is running
- Check: Steward can publish to MQTT (check steward logs)
- Check: Controller is subscribed to status topics
- Check: No MQTT authentication errors

## Success Criteria

Your home lab deployment is ready when:

- All services start without errors (`systemctl status` shows active)
- Controller and steward communicate via MQTT (port 1883)
- Config sync completes via QUIC (port 4433) in < 10 seconds
- Modules execute successfully
- Status reports are received by controller
- E2E tests pass (TestRegistration, TestConfigSync, TestModuleExecution, TestHeartbeatFailover, TestMultiTenant, TestTLSSecurity)
- System recovers from component restarts
- Logs show no errors or warnings

## Next Steps

After successful deployment:

1. **Scale Up**: Add more stewards to your environment
2. **Configure Modules**: Set up file, directory, and script modules for your needs
3. **Integrate M365**: Connect Microsoft 365 directory services (if applicable)
4. **Enable Monitoring**: Set up logging provider (file or TimescaleDB)
5. **Plan Maintenance**: Schedule regular backups and updates

---

**Need Help?**
- See: [Home Lab Deployment Guide](home-lab-deployment-guide.md)
- See: [Quick Start Guide](../../QUICK_START.md)
- See: [E2E Testing Guide](../testing/e2e-testing-guide.md)
