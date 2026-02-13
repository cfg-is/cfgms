# CFGMS Connectivity Troubleshooting Guide

**Story #378**: Comprehensive troubleshooting procedures for MQTT+QUIC connectivity and E2E flow issues.

**Last Updated**: 2026-02-12
**CFGMS Version**: v0.9.x

## Overview

This guide helps diagnose and resolve connectivity issues in CFGMS deployments, focusing on the MQTT+QUIC hybrid communication architecture.

## Table of Contents

1. [Quick Diagnostic](#quick-diagnostic)
2. [MQTT Connectivity Issues](#mqtt-connectivity-issues)
3. [QUIC Connectivity Issues](#quic-connectivity-issues)
4. [Certificate and TLS Issues](#certificate-and-tls-issues)
5. [Config Sync Issues](#config-sync-issues)
6. [Performance Issues](#performance-issues)
7. [Advanced Debugging](#advanced-debugging)

## Quick Diagnostic

**Run this first to identify the problem area:**

```bash
# 1. Check all containers are running
docker ps

# Expected output should show:
# - controller (or controller-standalone)
# - mqtt-broker
# - steward (or steward-standalone)

# 2. Check for errors in logs
docker compose logs | grep -i error

# 3. Run E2E diagnostic test
cd test/integration/mqtt_quic
go test -v -run TestE2EFlowDiagnostic

# This will show exactly which phase fails (1-8)
```

### Diagnostic Test Output Interpretation

```
📡 Phase 1 PASS: MQTT connection established
🌐 Phase 2 PASS: REST API accessible
📤 Phase 3 PASS: Configuration uploaded
📬 Phase 4 PASS: Subscribed to config status
🔗 Phase 5 PASS: QUIC connection command published
🔄 Phase 6 PASS: Config sync command published
📥 Phase 7 PASS: Status report received
⚙️  Phase 8 PASS: Module executed and file created
```

**If Phase 1-2 fail**: [MQTT Connectivity Issues](#mqtt-connectivity-issues)
**If Phase 3-4 fail**: [REST API / Config Upload Issues](#rest-api-issues)
**If Phase 5-6 fail**: [MQTT Command Delivery Issues](#mqtt-command-issues)
**If Phase 7 fails**: [QUIC / Signature / Executor Issues](#config-sync-issues)
**If Phase 8 fails**: [Module Execution Issues](#module-execution-issues)

## MQTT Connectivity Issues

### Issue: "MQTT connection timeout"

**Symptoms**:
- Steward logs show "Failed to connect to MQTT broker"
- Controller logs show "MQTT client disconnected"
- Diagnostic test Phase 1 fails

**Root Causes & Solutions**:

**1. MQTT Broker Not Running**

```bash
# Check if mqtt-broker container is running
docker ps | grep mqtt-broker

# If not running, start it
docker compose up -d mqtt-broker

# Wait 5 seconds and check logs
docker logs mqtt-broker

# Should see: "mochi mqtt server started" and "listening on :1886"
```

**2. Port Not Accessible**

```bash
# Check if port 1886 is listening
sudo lsof -i :1886

# Expected: mqtt-broker process listening

# If port conflict exists, change MQTT port in docker-compose.yml
# or stop conflicting process
```

**3. Network Isolation (Docker)**

```bash
# Verify containers are on same network
docker network ls
docker network inspect cfgms_default

# All CFGMS containers should be in "cfgms_default" or similar network

# If not, recreate network
docker compose down
docker compose up -d
```

**4. Firewall Blocking Connections**

```bash
# Check firewall status (Linux)
sudo ufw status

# Allow MQTT ports if needed
sudo ufw allow 1883/tcp
sudo ufw allow 1886/tcp

# Or disable firewall temporarily for testing
sudo ufw disable
```

**5. TLS Certificate Issues**

```bash
# Check controller has valid certificates
docker logs controller | grep "Certificate manager initialized"
docker logs controller | grep "Generated.*certificate"

# Check steward has certificates from registration
docker logs steward-standalone | grep "Registration successful"

# If certificates missing, verify registration flow:
docker logs steward-standalone | grep -i "registration"
```

### Issue: "MQTT authentication failed"

**Symptoms**:
- Logs show "authentication failed" or "not authorized"
- Connection attempts immediately rejected

**Solutions**:

```bash
# 1. Check MQTT broker authentication settings
docker exec mqtt-broker ps aux | grep mqtt

# 2. Verify steward has valid client certificates
docker exec steward-standalone ls -la /etc/cfgms/certs/

# Expected: client.pem, client-key.pem, ca.pem

# 3. Check certificate fingerprints match
docker logs controller | grep "Fingerprint"
docker logs steward-standalone | grep "Fingerprint"

# Steward's CA fingerprint should match controller's CA fingerprint
```

## QUIC Connectivity Issues

### Issue: "QUIC connection failed" or "timeout connecting to QUIC server"

**Symptoms**:
- Steward logs show "Failed to establish QUIC connection"
- Diagnostic test Phase 7 fails (never receives status report)
- Story #378 signature verification failures

**Root Causes & Solutions**:

**1. QUIC Port Not Accessible**

```bash
# From steward container, test QUIC port connectivity
docker exec steward-standalone sh -c "nc -zv controller-standalone 4433"

# Expected: "Connection to controller-standalone 4433 port [tcp/*] succeeded!"

# If connection fails:
# - Check controller is running
# - Check port 4433 is exposed in docker-compose.yml
# - Check no firewall blocking port 4433
```

**2. Controller QUIC Server Not Started**

```bash
# Check controller logs for QUIC server startup
docker logs controller | grep -i "quic"

# Expected: "QUIC server listening on :4433" or similar

# If not found:
# - Controller may have failed to start QUIC server
# - Check for errors in controller startup
# - Verify QUIC configuration in controller config
```

**3. mTLS Handshake Failure**

```bash
# Check steward has valid client certificates
docker logs steward-standalone | grep -i "certificate"

# Check controller accepts steward's certificate
docker logs controller | grep "QUIC.*client.*connected"

# If handshake fails:
# - Verify steward registered successfully
# - Check client cert issued by controller's CA
# - Verify CA certificate valid
```

**4. Story #378: Certificate Mismatch** (CRITICAL)

**Symptoms**:
- QUIC connects but signature verification fails
- Steward logs show "signature verification failed"
- Config fetch succeeds but executor rejects config

**Root Cause**: Controller using different certificates for signing vs registration

**Solution**:
```bash
# Verify you're running CFGMS v0.9.x with Story #378 fix
git log --oneline | grep "378"

# Should see commit: "bugfix: fix signature verification by tracking signer certificate serial"

# If not present, pull latest changes:
git pull origin develop

# Rebuild and redeploy:
make build
docker compose down
docker compose up -d
```

**Verification**:
```bash
# Check controller logs show same certificate serial for signer and registration
docker logs controller | grep "signerCertSerial"

# Should see consistent serial number throughout
```

## Certificate and TLS Issues

### Issue: "x509: certificate signed by unknown authority"

**Symptoms**:
- Steward cannot connect to controller
- TLS handshake fails
- Certificate validation errors in logs

**Solutions**:

```bash
# 1. Verify CA certificate is present and valid
docker exec controller ls -la /etc/cfgms/certs/
# Expected: ca.pem, ca-key.pem, server.pem, server-key.pem

# 2. Check steward has controller's CA cert
docker exec steward-standalone ls -la /etc/cfgms/certs/
# Expected: ca.pem (should match controller's ca.pem)

# 3. Verify CA fingerprints match
docker exec controller openssl x509 -in /etc/cfgms/certs/ca.pem -noout -fingerprint -sha256
docker exec steward-standalone openssl x509 -in /etc/cfgms/certs/ca.pem -noout -fingerprint -sha256

# Fingerprints MUST be identical

# 4. If mismatched, steward needs to re-register
docker compose down steward-standalone
docker compose up -d steward-standalone
# This triggers new registration with current CA
```

### Issue: "certificate has expired" or "certificate is not yet valid"

**Symptoms**:
- TLS errors mentioning expiration
- Connections fail with time-related errors

**Solutions**:

```bash
# 1. Check certificate validity
docker exec controller openssl x509 -in /etc/cfgms/certs/server.pem -noout -dates

# Shows: "notBefore" and "notAfter" dates

# 2. Verify system time is correct
docker exec controller date
docker exec steward-standalone date
date  # Host system time

# Times should match closely (within a few seconds)

# 3. If time is wrong, sync time:
# On Linux:
sudo ntpdate pool.ntp.org
# Or:
sudo timedatectl set-ntp true

# 4. If certificates expired, regenerate them:
docker compose down
rm -rf /path/to/cert/storage  # BE CAREFUL - backs up first!
docker compose up -d
```

## Config Sync Issues

### Issue: "Timeout waiting for config status report" (Story #378)

**Symptoms**:
- E2E tests timeout at 30+ seconds
- Steward never publishes status report
- Diagnostic test fails at Phase 7

**Root Cause**: This was the exact issue fixed in Story #378

**Diagnostic Steps**:

```bash
# 1. Check QUIC connection established
docker logs steward-standalone | grep -i "quic.*connect"

# 2. Check config fetch attempt
docker logs steward-standalone | grep -i "config.*fetch"

# 3. Check signature verification
docker logs steward-standalone | grep -i "signature"

# 4. If signature verification fails, check certificate serial
docker logs controller | grep "signerCertSerial"
docker logs steward-standalone | grep "certificate.*serial"

# 5. Verify Story #378 fix is applied
docker logs controller | grep "GetSignerCertSerial"
# Should show function being called during API server initialization
```

**Solution**: Apply Story #378 fix (certificate serial tracking)

```bash
# Pull latest code with fix
git fetch origin
git checkout bugfix/story-378-signature-cert-mismatch
# OR if merged:
git checkout develop
git pull

# Rebuild and redeploy
make build
docker compose down
docker compose up -d

# Verify fix worked
cd test/integration/mqtt_quic
go test -v -run TestConfigStatusReporting
# Should PASS in < 10 seconds
```

### Issue: "Config uploaded but never fetched by steward"

**Symptoms**:
- Config upload succeeds (REST API returns 200)
- Steward never receives or fetches config
- No QUIC activity in logs

**Diagnostic Steps**:

```bash
# 1. Verify config actually stored
# For git storage:
docker exec controller ls -la /data/git-storage/

# For database storage:
docker exec timescale psql -U cfgms -c "SELECT id, steward_id FROM configurations;"

# 2. Check steward received sync_config command
docker logs steward-standalone | grep "sync_config"

# 3. Check MQTT command was published
docker logs mqtt-broker | grep "cfgms/steward/.*/commands"
```

**Solutions**:

**A. Manual trigger (if auto-sync not working)**:

```bash
# Publish connect_quic command manually
mosquitto_pub -h localhost -p 1883 \
  -t "cfgms/steward/$STEWARD_ID/commands" \
  -m '{"command_id":"manual-1","type":"connect_quic","timestamp":"2026-02-12T20:00:00Z","params":{"quic_address":"controller-standalone:4433","session_id":"manual-session"}}'

# Wait 2 seconds, then publish sync_config
mosquitto_pub -h localhost -p 1883 \
  -t "cfgms/steward/$STEWARD_ID/commands" \
  -m '{"command_id":"manual-2","type":"sync_config","timestamp":"2026-02-12T20:00:05Z","params":{"version":"manual-v1"}}'
```

**B. Check steward is subscribed to commands topic**:

```bash
docker logs steward-standalone | grep "Subscribed to"

# Expected: "Subscribed to cfgms/steward/$STEWARD_ID/commands"

# If not subscribed:
# - Steward MQTT client may have failed to connect
# - Check MQTT connectivity (see above section)
```

## Module Execution Issues

### Issue: "Module execution failed" or "Module not found"

**Symptoms**:
- Config sync completes but modules fail
- Status report shows ERROR
- Diagnostic test Phase 8 fails

**Diagnostic Steps**:

```bash
# 1. Check which module failed
docker logs steward-standalone | grep -i "module.*failed"

# 2. Check if module is registered
docker logs steward-standalone | grep "Registered module"

# Expected modules: file, directory, script

# 3. Check module execution logs
docker logs steward-standalone | grep -A 5 "Executing module"

# 4. Verify workspace is accessible
docker exec steward-standalone ls -la /test-workspace/
docker exec steward-standalone df -h /test-workspace/
```

**Solutions**:

**A. File module fails**:

```bash
# Check permissions on workspace
docker exec steward-standalone stat /test-workspace/

# Should be writable by steward process

# Check if path is absolute
# Bad: path: "test.txt"
# Good: path: "/test-workspace/test.txt"
```

**B. Directory module fails**:

```bash
# Check parent directory exists
# If creating /test-workspace/foo/bar, ensure /test-workspace/foo exists
# Or use ensure_parent: true in config

# Check permissions allow directory creation
docker exec steward-standalone touch /test-workspace/test-perm
# If this fails, workspace not writable
```

**C. Module not registered**:

```bash
# Modules should auto-register on steward startup
# Check steward logs for module registration:
docker logs steward-standalone | head -50

# Should see:
# "Registered module: file"
# "Registered module: directory"
# "Registered module: script"

# If not registered, steward startup failed
# Check for errors in steward initialization
```

## Performance Issues

### Issue: "Config sync takes > 10 seconds"

**Target**: Config sync should complete in < 5 seconds for small configs

**Diagnostic**:

```bash
# Run diagnostic test and check phase timings
go test -v -run TestE2EFlowDiagnostic | grep "Phase.*PASS"

# Example output:
# Phase 7 PASS: Status report received (2.60s)  ← GOOD
# Phase 7 PASS: Status report received (15.2s)  ← SLOW

# Check resource usage
docker stats controller steward-standalone mqtt-broker

# High CPU or memory usage indicates performance issue
```

**Solutions**:

```bash
# 1. Check for resource constraints
docker stats
# Controller/Steward using > 80% CPU? Add resources.

# 2. Check disk I/O (for git storage)
docker exec controller df -h
docker exec controller iostat -x 1 5  # If available

# High iowait %? Disk performance issue.

# 3. Check network latency between containers
docker exec steward-standalone ping -c 5 controller-standalone

# High latency? Network issue.

# 4. Profile slow operations
docker logs controller | grep -E "took|duration|elapsed"
docker logs steward-standalone | grep -E "took|duration|elapsed"
```

### Issue: "E2E tests timeout in CI but pass locally"

**Root Cause**: CI environment slower than local (resource contention)

**Solutions**:

```bash
# Use CI-specific timeout configuration
# In test code:
timeouts := CIE2ETimeouts()  # Uses more conservative timeouts

# Or via environment variable:
CFGMS_E2E_MODE=ci go test -v -timeout 30m

# Verify CI resources are sufficient:
# - Minimum 4 vCPUs
# - Minimum 8GB RAM
# - Fast SSD storage
```

## Advanced Debugging

### Enable Debug Logging

**Controller**:
```bash
# Edit docker-compose.yml or set environment variable:
CFGMS_LOG_LEVEL=debug docker compose up -d controller

# Restart to apply
docker restart controller

# View debug logs
docker logs -f controller | grep DEBUG
```

**Steward**:
```bash
CFGMS_LOG_LEVEL=debug docker compose up -d steward-standalone

docker logs -f steward-standalone | grep DEBUG
```

### Packet Capture (MQTT)

```bash
# Capture MQTT traffic
sudo tcpdump -i any port 1886 -w /tmp/mqtt-capture.pcap

# In another terminal, run your test
go test -v -run TestConfigStatusReporting

# Stop tcpdump (Ctrl+C)

# Analyze with Wireshark or:
tcpdump -r /tmp/mqtt-capture.pcap -A | less
```

### QUIC Connection Tracing

```bash
# Enable QUIC debugging (requires code change or debug build)
CFGMS_QUIC_DEBUG=true docker compose up -d controller steward-standalone

# View QUIC-specific logs
docker logs controller | grep QUIC
docker logs steward-standalone | grep QUIC
```

### Health Check Endpoints

```bash
# Controller health
curl -k https://localhost:8080/health
# Expected: {"status":"healthy"} or similar

# Controller metrics (if enabled)
curl -k https://localhost:8080/metrics
# Prometheus-format metrics

# Check specific component health
curl -k https://localhost:8080/api/v1/health/mqtt
curl -k https://localhost:8080/api/v1/health/storage
curl -k https://localhost:8080/api/v1/health/quic
```

## Getting Help

If issues persist after following this guide:

1. **Collect diagnostic information**:
   ```bash
   # Run full diagnostic
   cd test/integration/mqtt_quic
   go test -v -run TestE2EFlowDiagnostic > /tmp/diagnostic.log 2>&1

   # Collect logs
   docker compose logs > /tmp/cfgms-logs.txt

   # System info
   docker version > /tmp/system-info.txt
   docker compose version >> /tmp/system-info.txt
   uname -a >> /tmp/system-info.txt
   ```

2. **Create GitHub issue** with:
   - Diagnostic test output (`/tmp/diagnostic.log`)
   - Container logs (`/tmp/cfgms-logs.txt`)
   - System information (`/tmp/system-info.txt`)
   - Description of issue and steps to reproduce

3. **Check existing issues**:
   - https://github.com/cfg-is/cfgms/issues
   - Search for similar problems and solutions

## References

- **E2E Testing Guide**: [docs/testing/e2e-testing-guide.md](../testing/e2e-testing-guide.md)
- **Home Lab Deployment**: [docs/deployment/home-lab-deployment-guide.md](../deployment/home-lab-deployment-guide.md)
- **MQTT+QUIC Strategy**: [docs/testing/mqtt-quic-testing-strategy.md](../testing/mqtt-quic-testing-strategy.md)
- **Story #378 Analysis**: `/tmp/story-378-root-cause.md` (development artifact)
