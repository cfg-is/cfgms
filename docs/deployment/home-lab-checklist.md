# CFGMS Home Lab Deployment Checklist

**Story #378**: This checklist ensures all prerequisites and deployment steps are validated before deploying CFGMS to your home lab environment.

**Last Updated**: 2026-02-12
**CFGMS Version**: v0.9.x

## Pre-Deployment Checklist

### Infrastructure Requirements

- [ ] **Docker Engine** installed and running (version 20.10+ recommended)
  ```bash
  docker --version
  docker ps  # Should show running containers or empty list
  ```

- [ ] **Docker Compose** installed (version 2.0+ with `docker compose` command)
  ```bash
  docker compose version
  ```

- [ ] **Sufficient Resources** available on host machine:
  - **CPU**: Minimum 2 cores, recommended 4+ cores
  - **RAM**: Minimum 4GB, recommended 8GB+
  - **Disk**: Minimum 20GB free space, recommended 50GB+
  ```bash
  # Check available resources
  df -h /var/lib/docker  # Disk space
  free -h                # Memory
  nproc                  # CPU cores
  ```

- [ ] **Network Ports** available and not in use:
  - `8080`: Controller REST API (HTTPS)
  - `9090`: Controller gRPC
  - `4433`: Controller QUIC (config sync)
  - `1883`: MQTT broker (non-TLS)
  - `1886`: MQTT broker (TLS)
  ```bash
  # Check if ports are available
  sudo lsof -i :8080
  sudo lsof -i :9090
  sudo lsof -i :4433
  sudo lsof -i :1883
  sudo lsof -i :1886
  ```

### Repository and Build

- [ ] **CFGMS Repository** cloned and up to date
  ```bash
  git clone https://github.com/cfg-is/cfgms.git
  cd cfgms
  git checkout main
  git pull origin main
  ```

- [ ] **Go Environment** configured (version 1.23+ required)
  ```bash
  go version  # Should show go1.23 or later
  ```

- [ ] **All Tests Passing** before deployment
  ```bash
  make test-complete  # MUST pass 100%
  ```

- [ ] **Binaries Built** successfully
  ```bash
  make build  # Should create ./bin/controller and ./bin/steward
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

### Step 1: Initial Deployment

- [ ] **Start Core Infrastructure** (controller + MQTT broker)
  ```bash
  docker compose up -d controller mqtt-broker
  ```

- [ ] **Verify Controller Health**
  ```bash
  # Wait 10-15 seconds for controller to initialize
  docker logs controller | grep "Controller started"

  # Check controller is listening
  curl -k https://localhost:8080/health  # Should return 200 OK
  ```

- [ ] **Verify MQTT Broker Health**
  ```bash
  docker logs mqtt-broker | grep "started"

  # Test MQTT connectivity (requires mosquitto-clients)
  mosquitto_pub -h localhost -p 1883 -t "test/topic" -m "test" -d
  ```

- [ ] **Certificates Auto-Generated** (if using auto-generation)
  ```bash
  docker logs controller | grep "Certificate manager initialized"
  docker logs controller | grep "Generated server certificate"
  ```

### Step 2: Steward Deployment

- [ ] **Registration Token Created**
  ```bash
  # Via REST API or CLI (depends on your setup)
  # Store token securely - it's used for steward registration
  ```

- [ ] **Start First Steward** (test deployment)
  ```bash
  docker compose up -d steward-standalone
  ```

- [ ] **Verify Steward Registration**
  ```bash
  docker logs steward-standalone | grep "Registration successful"
  docker logs steward-standalone | grep "Steward ID:"
  ```

- [ ] **Verify MQTT Connection**
  ```bash
  docker logs steward-standalone | grep "MQTT.*connected"
  docker logs controller | grep "steward.*connected"
  ```

### Step 3: E2E Validation

- [ ] **Upload Test Configuration**
  ```bash
  # Upload a simple test config (file module creating a test file)
  # Verify it appears in controller's storage backend
  ```

- [ ] **Publish MQTT Commands** (connect_quic + sync_config)
  ```bash
  # Use MQTT client to publish commands
  # OR use controller's REST API to trigger config sync
  ```

- [ ] **Verify Config Sync** via QUIC
  ```bash
  # Check steward logs for:
  docker logs steward-standalone | grep "QUIC.*connected"
  docker logs steward-standalone | grep "Config.*fetched"
  docker logs steward-standalone | grep "signature.*verified"
  ```

- [ ] **Verify Module Execution**
  ```bash
  # Check steward logs for module execution
  docker logs steward-standalone | grep "module.*executed"

  # Verify test file was created
  docker exec steward-standalone ls -la /test-workspace/
  ```

- [ ] **Verify Status Reporting**
  ```bash
  # Check controller logs for status report receipt
  docker logs controller | grep "config.*status"
  docker logs controller | grep "steward.*OK"
  ```

- [ ] **Run E2E Tests** (validates full flow programmatically)
  ```bash
  cd test/integration/mqtt_quic
  go test -v -run TestE2EFlowDiagnostic
  go test -v -run TestConfigStatusReporting
  ```

### Step 4: Production Readiness

- [ ] **Security Hardening** applied:
  - [ ] Changed default passwords/tokens
  - [ ] Firewall rules configured (if applicable)
  - [ ] TLS certificate verification enabled
  - [ ] SOPS encryption keys secured

- [ ] **Backup Strategy** implemented:
  - [ ] Git repository backed up (if using git storage)
  - [ ] Database backed up (if using database storage)
  - [ ] Certificate backup stored securely

- [ ] **Monitoring** configured:
  - [ ] Log aggregation (optional but recommended)
  - [ ] Health check monitoring
  - [ ] Disk space monitoring
  - [ ] Container restart policy set

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

### Performance Tests

- [ ] **Measure Config Sync Latency**
  - Expected: < 5 seconds for small configs
  - Check logs for timing information

- [ ] **Measure MQTT Message Delivery**
  - Expected: < 1 second for command delivery
  - Use MQTT client to test round-trip time

- [ ] **Verify Resource Usage**
  ```bash
  # Check container resource usage
  docker stats controller steward-standalone mqtt-broker

  # Expected:
  # - Controller: < 200MB RAM, < 5% CPU (idle)
  # - Steward: < 100MB RAM, < 2% CPU (idle)
  # - MQTT: < 50MB RAM, < 1% CPU
  ```

### Resilience Tests

- [ ] **Controller Restart Recovery**
  ```bash
  docker restart controller
  # Wait 15 seconds
  # Verify steward reconnects automatically
  docker logs steward-standalone | tail -20
  ```

- [ ] **Steward Restart Recovery**
  ```bash
  docker restart steward-standalone
  # Wait 10 seconds
  # Verify steward re-registers and reconnects
  docker logs steward-standalone | tail -20
  ```

- [ ] **MQTT Broker Restart Recovery**
  ```bash
  docker restart mqtt-broker
  # Wait 10 seconds
  # Verify both controller and steward reconnect
  ```

- [ ] **Network Interruption Recovery** (optional - advanced)
  ```bash
  # Temporarily disable network on steward container
  # Verify it reconnects when network restored
  ```

## Troubleshooting Quick Reference

### Common Issues

**Issue**: Controller fails to start
- Check: Docker logs for error messages
- Check: Port 8080, 9090, 4433 available
- Check: Sufficient disk space for certificate generation

**Issue**: Steward cannot register
- Check: Registration token is valid and not expired
- Check: Controller is reachable from steward
- Check: MQTT broker is running and accessible

**Issue**: QUIC connection fails
- Check: Port 4433 is accessible from steward
- Check: Certificates are generated and valid
- Check: Controller logs for QUIC server startup

**Issue**: Config sync times out
- Check: Configuration is uploaded to controller
- Check: Steward received sync_config command
- Check: Signature verification passes (Story #378 fix)
- Check: Module executor is initialized

**Issue**: Status reports not received
- Check: MQTT broker is running
- Check: Steward can publish to MQTT
- Check: Controller is subscribed to status topic
- Check: No MQTT authentication errors

## Success Criteria

Your home lab deployment is ready when:

- ✅ All containers start without errors
- ✅ Controller and steward can communicate via MQTT
- ✅ Config sync completes via QUIC in < 10 seconds
- ✅ Modules execute successfully
- ✅ Status reports are received by controller
- ✅ E2E tests pass 100%
- ✅ System recovers from component restarts
- ✅ Logs show no errors or warnings

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
- See: [Troubleshooting Guide](../troubleshooting/connectivity.md)
- See: [E2E Testing Guide](../testing/e2e-testing-guide.md)
