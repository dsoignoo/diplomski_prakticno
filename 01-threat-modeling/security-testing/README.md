# Security Testing Framework

## Overview

This framework provides **measurable validation** that security controls effectively mitigate the threats identified in our threat model. We use a combination of automated attack simulations, manual penetration testing, and continuous monitoring to demonstrate security improvements.

## Testing Philosophy

### Before/After Methodology

Each security control is tested using a **baseline vs. hardened** comparison:

1. **Baseline Test** - Demonstrate vulnerability exists in default configuration
2. **Implement Control** - Deploy security mitigation (Phase 02-13)
3. **Post-Mitigation Test** - Prove attack is now blocked or detected
4. **Metrics Collection** - Measure improvement (MTTD, MTTR, attack success rate)

### Testing Pyramid

```
         ┌─────────────────────────┐
         │   Manual Penetration    │  (Quarterly)
         │      Testing (PTaaS)    │
         └─────────────────────────┘
                     △
                     │
         ┌───────────────────────────┐
         │  Automated Red Team       │  (Weekly)
         │  Attack Simulations       │
         └───────────────────────────┘
                     △
                     │
    ┌────────────────────────────────────┐
    │  Continuous Validation Tests       │  (Every commit)
    │  (Policy enforcement, scanning)    │
    └────────────────────────────────────┘
```

## Testing Categories

### 1. Policy Enforcement Tests (Shift-Left)

**Purpose:** Prevent vulnerabilities before deployment

**Tools:**
- OPA Gatekeeper (policy violations)
- Trivy (image vulnerabilities)
- KubeLinter (manifest best practices)
- Git pre-commit hooks (secret detection)

**Examples:**
```bash
# Test: Privileged pod should be rejected
kubectl apply -f test-manifests/privileged-pod.yaml
# Expected: Error from admission controller

# Test: Unsigned image should be rejected (Binary Authorization)
kubectl run test --image=nginx:unsigned
# Expected: Image signature verification failed

# Test: High CVE image should be rejected
kubectl apply -f test-manifests/vulnerable-image.yaml
# Expected: Blocked by Trivy policy
```

**Automation:** Run in CI/CD pipeline before every deployment

---

### 2. Attack Simulation Tests (Red Team)

**Purpose:** Prove attacks are blocked or detected

**Tools:**
- Atomic Red Team (MITRE ATT&CK tests)
- Peirates (Kubernetes penetration testing)
- kube-hunter (cluster vulnerability scanner)
- Custom exploit scripts

**Test Suites:**

#### Suite A: Container Escape Attempts
```bash
# Test 1: Privileged container escape
./simulations/container-escape/privileged-escape.sh

# Test 2: CAP_SYS_ADMIN abuse
./simulations/container-escape/cap-sys-admin.sh

# Test 3: Writable host path mount
./simulations/container-escape/hostpath-escape.sh

# Expected Results:
# - Baseline: All tests succeed (escape to host)
# - Hardened: All tests blocked by PSS or detected by Falco within 30s
```

#### Suite B: Secret Exfiltration Attempts
```bash
# Test 4: Kubernetes secret access
./simulations/secret-exfiltration/k8s-secrets.sh

# Test 5: PostgreSQL credential theft
./simulations/secret-exfiltration/postgres-access.sh

# Test 6: GCP metadata API access
./simulations/secret-exfiltration/gcp-metadata.sh

# Expected Results:
# - Baseline: All secrets successfully exfiltrated
# - Hardened: RBAC blocks access, NetworkPolicy blocks connections, Falco alerts
```

#### Suite C: Lateral Movement Attempts
```bash
# Test 7: Pod-to-pod unauthorized access
./simulations/lateral-movement/frontend-to-database.sh

# Test 8: Service account token abuse
./simulations/lateral-movement/token-theft.sh

# Test 9: DNS tunneling exfiltration
./simulations/lateral-movement/dns-exfil.sh

# Expected Results:
# - Baseline: All lateral movement succeeds
# - Hardened: NetworkPolicies block, Falco detects anomalous connections
```

#### Suite D: Supply Chain Attacks
```bash
# Test 10: Unsigned image deployment
./simulations/supply-chain/unsigned-image.sh

# Test 11: Malicious artifact upload
./simulations/supply-chain/artifact-tamper.sh

# Test 12: Vulnerable dependency introduction
./simulations/supply-chain/vulnerable-dep.sh

# Expected Results:
# - Baseline: All malicious artifacts accepted
# - Hardened: Binary Authorization blocks, Trivy fails build, Cosign verification fails
```

---

### 3. Detection Validation Tests

**Purpose:** Verify security events are detected and alerted

**Tools:**
- Falco (runtime detection)
- Prometheus Alertmanager
- SIEM (Elasticsearch/Splunk)
- Kubernetes audit logs

**Test Matrix:**

| Attack Technique | Detection Method | MTTD Target | Alert Channel |
|------------------|------------------|-------------|---------------|
| Container escape attempt | Falco rule | <30 seconds | PagerDuty |
| Unauthorized secret access | K8s audit log | <60 seconds | Slack |
| Privilege escalation | Falco + SIEM correlation | <2 minutes | SIEM dashboard |
| Credential theft | Anomaly detection (UEBA) | <5 minutes | Security team email |
| Data exfiltration | NetFlow analysis | <10 minutes | SOC ticket |
| Crypto mining | CPU spike + network pattern | <5 minutes | Auto-terminate pod |

**Validation Process:**
```bash
# Trigger attack
./trigger-attack.sh container-escape

# Wait for detection
./wait-for-alert.sh falco "Container escape detected" --timeout 60s

# Verify alert fired
./check-alert.sh --source falco --severity critical --count 1

# Measure MTTD
echo "Mean Time to Detect: 23 seconds" >> metrics/mttd.log
```

---

### 4. Resilience & Recovery Tests

**Purpose:** Validate incident response and recovery procedures

**Scenarios:**

#### Scenario 1: Compromised Pod Response
```bash
# Simulate compromised pod
kubectl label pod front-xxxx compromised=true

# Expected automated response:
# 1. NetworkPolicy quarantine applied (10s)
# 2. Pod evicted and replaced (30s)
# 3. Forensic snapshot captured (60s)
# 4. Incident ticket created in Jira
# 5. Root cause analysis triggered

# Validate:
./validate-incident-response.sh --scenario compromised-pod
```

#### Scenario 2: Secrets Rotation After Breach
```bash
# Simulate leaked database password
./simulations/breach/leak-db-password.sh

# Expected response:
# 1. Vault detects unauthorized access (MTTD <5min)
# 2. Automatic secret rotation triggered (5min)
# 3. All services restart with new credentials (10min)
# 4. Leaked credential revoked (immediate)

# Validate:
./validate-secret-rotation.sh --leaked-secret postgres-password
```

#### Scenario 3: Cluster-Wide Rollback
```bash
# Deploy malicious update
kubectl apply -f malicious-deployment.yaml

# Expected response:
# 1. Binary Authorization blocks deployment (immediate)
# 2. If bypassed, Falco detects malicious behavior (30s)
# 3. Automated rollback to previous version (2min)
# 4. Post-incident review triggered

# Validate:
./validate-rollback.sh --deployment controller
```

---

## Security Metrics Dashboard

### Key Performance Indicators (KPIs)

| Metric | Baseline | Phase 1 | Phase 2 | Phase 3 | Target |
|--------|----------|---------|---------|---------|--------|
| **Attack Success Rate** | 100% | 60% | 30% | 10% | <5% |
| **MTTD (Mean Time to Detect)** | Never | 30min | 5min | 1min | <2min |
| **MTTR (Mean Time to Respond)** | Never | 4 hours | 1 hour | 15min | <30min |
| **False Positive Rate** | N/A | 40% | 20% | 10% | <5% |
| **Policy Compliance** | 20% | 50% | 80% | 95% | >95% |
| **Vulnerable Images** | 85% | 50% | 20% | 5% | <5% |
| **MITRE ATT&CK Coverage** | 15% | 45% | 70% | 90% | >85% |
| **Incident Response Time** | Never | 8 hours | 2 hours | 30min | <1 hour |

### Automated Metrics Collection

```bash
# Run full security assessment
./collect-metrics.sh --phase baseline

# Output: metrics/baseline-report.json
{
  "timestamp": "2025-01-13T10:00:00Z",
  "phase": "baseline",
  "attack_simulations": {
    "container_escape": {"success": true, "detected": false, "mttd": null},
    "secret_exfiltration": {"success": true, "detected": false, "mttd": null},
    "lateral_movement": {"success": true, "detected": false, "mttd": null}
  },
  "vulnerability_scan": {
    "total_images": 15,
    "vulnerable_images": 13,
    "critical_cves": 47,
    "high_cves": 203
  },
  "policy_compliance": {
    "pss_restricted": 0,
    "network_policies": 0,
    "rbac_least_privilege": 2
  }
}

# Compare against hardened state
./compare-metrics.sh baseline phase3
# Output: Improvement report with charts
```

---

## Testing Tools & Setup

### Tool Installation

```bash
# 1. Attack simulation tools
cd 01-threat-modeling/security-testing/tools
./install-tools.sh

# Installs:
# - Peirates (K8s pentesting)
# - kube-hunter (vulnerability scanner)
# - Atomic Red Team (MITRE ATT&CK)
# - kubectl-who-can (RBAC auditing)
# - kubeaudit (security auditing)
# - Trivy CLI (vulnerability scanning)

# 2. Detection validation tools
./install-detection-tools.sh

# Installs:
# - falcoctl (Falco rule testing)
# - promtool (Prometheus alert testing)
# - elastalert-test (SIEM alert testing)

# 3. Metrics collection
./install-metrics-tools.sh

# Installs:
# - kube-bench (CIS benchmark)
# - kubesec (risk scoring)
# - polaris (best practices)
```

### Lab Environment Setup

```bash
# Create isolated testing namespace
kubectl create namespace security-testing
kubectl label namespace security-testing testing=true

# Deploy vulnerable test targets
kubectl apply -f test-targets/ -n security-testing

# Test targets include:
# - Privileged pod
# - Pod with hostPath mount
# - Pod with overprivileged ServiceAccount
# - Vulnerable application (OWASP Juice Shop)

# Deploy attack pod
kubectl apply -f attack-pod.yaml -n security-testing
kubectl exec -it attack-pod -n security-testing -- /bin/bash

# Now inside attack pod, run simulations:
./run-simulations.sh --suite all
```

---

## Continuous Security Testing (CI/CD Integration)

### GitHub Actions Workflow

```yaml
# .github/workflows/security-testing.yml
name: Security Testing

on:
  push:
    branches: [main, develop]
  pull_request:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  policy-enforcement:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run KubeLinter
        run: |
          kubectl apply --dry-run=server -f k8s-manifests/ | \
          kube-linter lint -

      - name: Scan images with Trivy
        run: |
          for image in $(grep 'image:' k8s-manifests/*.yaml | awk '{print $2}'); do
            trivy image --severity HIGH,CRITICAL --exit-code 1 $image
          done

      - name: Check for secrets
        run: |
          trufflehog git file://. --fail

  attack-simulation:
    runs-on: ubuntu-latest
    needs: policy-enforcement
    steps:
      - name: Setup test cluster
        run: |
          kind create cluster --config test-cluster-config.yaml

      - name: Deploy Semaphore baseline
        run: |
          kubectl apply -f k8s-manifests/

      - name: Run attack simulations
        run: |
          cd 01-threat-modeling/security-testing
          ./run-all-simulations.sh --output results/

      - name: Validate detections
        run: |
          ./validate-detections.sh --expected-alerts 12

      - name: Generate report
        run: |
          ./generate-report.sh --format html > attack-simulation-report.html

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-test-results
          path: results/

  metrics-collection:
    runs-on: ubuntu-latest
    needs: attack-simulation
    steps:
      - name: Collect security metrics
        run: |
          ./collect-metrics.sh --phase ${{ github.ref_name }}

      - name: Compare with baseline
        run: |
          ./compare-metrics.sh baseline ${{ github.ref_name }}

      - name: Update dashboard
        run: |
          curl -X POST https://grafana.internal/api/dashboards/security-metrics \
            -d @metrics/results.json
```

---

## Testing Schedule

### Continuous (Every Commit)
- ✅ Policy enforcement (Gatekeeper, KubeLinter)
- ✅ Image vulnerability scanning (Trivy)
- ✅ Secret detection (TruffleHog)
- ✅ RBAC auditing (kubectl-who-can)

### Daily (Automated)
- 🔄 Full attack simulation suite (30 tests)
- 🔄 Vulnerability scanning (kube-hunter)
- 🔄 Configuration drift detection (kube-bench)
- 🔄 Metrics collection and comparison

### Weekly (Semi-Automated)
- 🔄 Red team attack scenarios (manual + automated)
- 🔄 Detection rule effectiveness review
- 🔄 False positive analysis
- 🔄 Security metrics review

### Monthly (Manual)
- 👤 Penetration testing exercises
- 👤 Incident response drills
- 👤 Security control effectiveness review
- 👤 Threat model updates

### Quarterly (External)
- 🏢 Third-party penetration testing
- 🏢 Compliance audits (CIS, NIST)
- 🏢 Red team engagement
- 🏢 Security architecture review

---

## Attack Simulation Scenarios

### Full Test Suite

```bash
# Run all attack simulations
cd 01-threat-modeling/security-testing
./run-all-simulations.sh

# Output:
# ========================================
# Security Testing Suite - Execution Report
# ========================================
#
# Phase: Baseline
# Timestamp: 2025-01-13 10:30:00
#
# [CONTAINER ESCAPE TESTS]
# ✓ Test 1: Privileged container escape    SUCCESS (0s) ❌ NOT DETECTED
# ✓ Test 2: CAP_SYS_ADMIN abuse            SUCCESS (2s) ❌ NOT DETECTED
# ✓ Test 3: Hostpath escape                BLOCKED (PSS admission controller)
#
# [SECRET EXFILTRATION TESTS]
# ✓ Test 4: K8s secret enumeration         SUCCESS (1s) ❌ NOT DETECTED
# ✓ Test 5: PostgreSQL direct access       SUCCESS (3s) ❌ NOT DETECTED
# ✓ Test 6: GCP metadata API access        SUCCESS (1s) ❌ NOT DETECTED
#
# [LATERAL MOVEMENT TESTS]
# ✓ Test 7: Frontend → Database            SUCCESS (2s) ❌ NOT DETECTED
# ✓ Test 8: ServiceAccount token theft     SUCCESS (1s) ❌ NOT DETECTED
# ✓ Test 9: DNS tunneling exfil            SUCCESS (5s) ❌ NOT DETECTED
#
# [SUPPLY CHAIN TESTS]
# ✓ Test 10: Unsigned image deploy         SUCCESS (0s) ❌ NOT DETECTED
# ✓ Test 11: Malicious artifact upload     SUCCESS (2s) ❌ NOT DETECTED
# ✓ Test 12: Vulnerable dependency         SUCCESS (build) ❌ NOT DETECTED
#
# ========================================
# SUMMARY
# ========================================
# Total Tests:        12
# Attacks Succeeded:  12 (100%)
# Attacks Blocked:    0 (0%)
# Attacks Detected:   0 (0%)
# Mean Time to Detect: N/A
#
# ⚠️  CRITICAL: All attacks succeeded without detection!
# Recommendation: Implement security controls (Phase 02-13)
```

---

## Expected Results by Phase

### Phase 00: Baseline (Current)
```
Attack Success Rate:     100% ❌
MTTD:                    Never ❌
Policy Compliance:       20% ❌
Vulnerable Images:       85% ❌
MITRE ATT&CK Coverage:   15% ❌
```

### Phase 1: Infrastructure + Pod Security (02, 05)
```
Attack Success Rate:     60% ⚠️  (Container escape blocked)
MTTD:                    30 minutes ⚠️  (Manual log review)
Policy Compliance:       50% ⚠️
Vulnerable Images:       50% ⚠️  (Scanning implemented)
MITRE ATT&CK Coverage:   45% ⚠️
```

### Phase 2: Network + Secrets + Detection (04, 06, 08)
```
Attack Success Rate:     30% 🟡 (Lateral movement blocked)
MTTD:                    5 minutes 🟡 (Falco automated alerts)
Policy Compliance:       80% 🟡
Vulnerable Images:       20% 🟡 (Build-time blocking)
MITRE ATT&CK Coverage:   70% 🟡
```

### Phase 3: Full Stack (All phases)
```
Attack Success Rate:     10% ✅ (Only advanced persistent threats)
MTTD:                    1 minute ✅ (Multi-signal correlation)
Policy Compliance:       95% ✅
Vulnerable Images:       5% ✅ (Automatic remediation)
MITRE ATT&CK Coverage:   90% ✅
```

---

## Validation Checklist

Before considering a phase "complete", validate:

### Infrastructure Security (Phase 02)
- [ ] Node OS hardening (CIS benchmark score >90%)
- [ ] Workload Identity functional (metadata API returns pod SA)
- [ ] Shielded nodes enabled (integrity monitoring active)
- [ ] Auto-upgrade enabled (tested failover during upgrade)
- [ ] Private cluster (API server inaccessible from internet)

### Pod Security Standards (Phase 05)
- [ ] Privileged pods rejected (tested with sample pod)
- [ ] Host namespace access blocked (hostPID, hostNetwork, hostIPC)
- [ ] Root user blocked (runAsNonRoot enforced)
- [ ] Capabilities dropped (only NET_BIND_SERVICE allowed)
- [ ] Read-only root filesystem enforced

### Network Policies (Phase 08)
- [ ] Default deny applied (tested with netcat)
- [ ] Pod-to-pod segmentation (frontend can't reach DB)
- [ ] Egress restrictions (only whitelisted domains)
- [ ] DNS allowed (pods can resolve internal services)
- [ ] Monitoring exemptions (Prometheus can scrape all pods)

### Runtime Security (Phase 06)
- [ ] Falco deployed (rules loaded, alerts firing)
- [ ] Container escape detected (<30s MTTD)
- [ ] Shell spawn detected (interactive shell in prod pod)
- [ ] Suspicious file access detected (/etc/shadow read)
- [ ] Network anomaly detected (unexpected egress)

### Secrets Management (Phase 04)
- [ ] External Secrets Operator syncing (Vault → K8s)
- [ ] Secret rotation working (automated every 90 days)
- [ ] Old secrets revoked (validated in Vault)
- [ ] Workload Identity used (no static credentials)
- [ ] Secret access audited (logged in Vault)

---

## Reporting

### Weekly Security Report
```bash
./generate-report.sh --period weekly --format pdf

# Includes:
# - Attack simulation results
# - Detection effectiveness (MTTD, false positives)
# - Vulnerability trending
# - Policy compliance status
# - Top 5 security risks
# - Remediation recommendations
```

### Executive Dashboard (Grafana)
- **Security Posture Score**: 85/100 (target: >90)
- **Active Alerts**: 2 critical, 5 high, 12 medium
- **Vulnerability Trend**: ↓ 40% reduction this month
- **Attack Success Rate**: 12% (target: <10%)
- **MITRE ATT&CK Heatmap**: 28/31 techniques covered

---

## References

- **MITRE ATT&CK Evaluations**: https://attackevals.mitre-engenuity.org/
- **Atomic Red Team**: https://github.com/redcanaryco/atomic-red-team
- **Kubernetes Goat (Training)**: https://github.com/madhuakula/kubernetes-goat
- **Peirates**: https://github.com/inguardians/peirates
- **kube-hunter**: https://github.com/aquasecurity/kube-hunter
- **Falco Rules**: https://github.com/falcosecurity/rules
- **CIS Kubernetes Benchmark**: https://www.cisecurity.org/benchmark/kubernetes

---

## Next Steps

1. **Set up baseline testing environment**:
   ```bash
   cd 01-threat-modeling/security-testing
   ./setup-testing-env.sh
   ```

2. **Run baseline attack simulations**:
   ```bash
   ./run-all-simulations.sh --phase baseline
   ```

3. **Collect baseline metrics**:
   ```bash
   ./collect-metrics.sh --phase baseline --output metrics/baseline.json
   ```

4. **Implement Phase 02 security controls**

5. **Re-run attack simulations**:
   ```bash
   ./run-all-simulations.sh --phase phase1
   ```

6. **Compare metrics**:
   ```bash
   ./compare-metrics.sh baseline phase1
   ```

This creates a measurable feedback loop proving security improvements at each phase!
