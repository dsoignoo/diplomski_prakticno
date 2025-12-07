# Security Testing Quick Start Guide

## Overview

This guide will help you quickly set up and run security testing to validate your Semaphore deployment security controls.

## Prerequisites

- kubectl configured with access to your GKE cluster
- jq installed (`sudo apt-get install jq` or `brew install jq`)
- Trivy installed (optional, for vulnerability scanning)
- Access to deploy test pods in the cluster

## Quick Start: 5-Minute Security Assessment

### 1. Collect Baseline Metrics

```bash
cd 01-threat-modeling/security-testing

# Collect current security metrics
./collect-metrics.sh baseline

# This will output:
# - Vulnerability scan results
# - Pod security compliance
# - Network policy coverage
# - RBAC configuration
# - Secrets management status
# - Overall security score (0-100)
```

**Expected output:**
```
Collecting security metrics for phase: baseline
  [1/8] Scanning container images for vulnerabilities...
  [2/8] Checking Pod Security Standards compliance...
  [3/8] Checking NetworkPolicy coverage...
  [4/8] Auditing RBAC configuration...
  [5/8] Checking secrets management...
  [6/8] Checking runtime security (Falco)...
  [7/8] Checking observability stack...
  [8/8] Running attack simulations...

✓ Metrics collected successfully
  Output: metrics/baseline-20250113-103000.json

Security Score: 23/100
  - Vulnerability Management: 3/20
  - Pod Security:            8/20
  - Network Segmentation:    0/20
  - RBAC Configuration:      7/15
  - Secrets Management:      5/15
  - Runtime Security:        0/10
```

---

### 2. Run Attack Simulations

```bash
# Run all attack simulations (takes ~5 minutes)
./run-all-simulations.sh baseline

# Or run specific test categories:
./run-all-simulations.sh baseline --category container-escape
./run-all-simulations.sh baseline --category secret-exfiltration
./run-all-simulations.sh baseline --category lateral-movement
./run-all-simulations.sh baseline --category supply-chain
```

**Expected baseline results (before hardening):**
```
========================================
Security Testing Suite - Execution Report
========================================

Phase: baseline
Timestamp: 2025-01-13 10:30:00

[CONTAINER ESCAPE TESTS]
  Test 1: Privileged container escape...    SUCCESS (0s)
    ✗ NOT DETECTED
  Test 2: CAP_SYS_ADMIN abuse...            BLOCKED
    ✓ Blocked by: Pod Security Standards
  Test 3: Hostpath escape...                SUCCESS (1s)
    ✗ NOT DETECTED

[SECRET EXFILTRATION TESTS]
  Test 4: K8s secret enumeration...         SUCCESS (1s)
    ✗ NOT DETECTED
  Test 5: PostgreSQL direct access...       SUCCESS (3s)
    ✗ NOT DETECTED
  ...

========================================
SUMMARY
========================================
Total Tests:        12
Attacks Succeeded:  10 (83%)
Attacks Blocked:    2 (17%)
Attacks Detected:   0 (0%)
Mean Time to Detect: N/A

⚠️  CRITICAL: 83% of attacks succeeded without detection!
Recommendation: Implement security controls (Phase 02-13)
```

---

### 3. Implement Security Controls

Follow the implementation phases in order:

```bash
# Phase 02: Infrastructure Security
cd ../../02-infrastructure-security
# Follow README.md instructions

# Phase 05: Pod Security Standards
cd ../05-pod-security-standards
kubectl apply -f pod-security-policies/

# Phase 08: Network Policies
cd ../08-network-policies
kubectl apply -f 00-default-deny.yaml
kubectl apply -f component-specific/

# ... continue with other phases
```

---

### 4. Re-run Tests After Each Phase

```bash
cd 01-threat-modeling/security-testing

# Collect metrics after Phase 02
./collect-metrics.sh phase2

# Run attack simulations
./run-all-simulations.sh phase2

# Compare against baseline
./compare-metrics.sh metrics/baseline-*.json metrics/phase2-*.json
```

**Expected Phase 2 results (after infrastructure + PSS):**
```
========================================
SUMMARY
========================================
Total Tests:        12
Attacks Succeeded:  7 (58%)    ← Improvement!
Attacks Blocked:    5 (42%)    ← Container escapes blocked
Attacks Detected:   0 (0%)
Mean Time to Detect: N/A

⚠️  WARNING: More than 50% of attacks succeeded
Recommendation: Continue implementing security controls
```

---

### 5. Track Progress Over Time

```bash
# Generate comparison report
./compare-metrics.sh \
  metrics/baseline-20250113-103000.json \
  metrics/phase3-20250120-140000.json

# Output shows improvements:
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OVERALL SECURITY SCORE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Security Score: 23/100 → 87/100 (+64 points improvement)
#
# Baseline: [▰▰▰▰▰▰▰▰▰▰▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱] 23%
# Current:  [▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▱▱▱▱▱▱▱] 87%
```

---

## Individual Test Scripts

### Test Container Escape Prevention

```bash
cd simulations/container-escape

# Test 1: Privileged pod
./privileged-escape.sh

# Test 2: CAP_SYS_ADMIN abuse
./cap-sys-admin.sh

# Test 3: Host path mount
./hostpath-escape.sh
```

### Test Secret Exfiltration Prevention

```bash
cd simulations/secret-exfiltration

# Test Kubernetes secret access
./k8s-secrets.sh

# Test PostgreSQL direct access
./postgres-access.sh

# Test GCP metadata API access
./gcp-metadata.sh

# Test Redis cache access
./redis-access.sh
```

### Test Network Segmentation

```bash
cd simulations/lateral-movement

# Test frontend → database connection (should be blocked)
./frontend-to-database.sh

# Test service account token theft
./token-theft.sh

# Test DNS tunneling exfiltration
./dns-exfil.sh
```

### Test Supply Chain Security

```bash
cd simulations/supply-chain

# Test unsigned image deployment
./unsigned-image.sh

# Test artifact tampering detection
./artifact-tamper.sh

# Test vulnerable dependency detection
./vulnerable-dep.sh
```

---

## Continuous Testing (CI/CD Integration)

### GitHub Actions

Add to `.github/workflows/security-testing.yml`:

```yaml
name: Security Testing

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup kubectl
        uses: azure/setup-kubectl@v3

      - name: Configure GKE access
        run: |
          gcloud auth activate-service-account --key-file=${{ secrets.GKE_SA_KEY }}
          gcloud container clusters get-credentials ${{ secrets.GKE_CLUSTER }} --region ${{ secrets.GKE_REGION }}

      - name: Run security tests
        run: |
          cd 01-threat-modeling/security-testing
          ./run-all-simulations.sh ${{ github.ref_name }}

      - name: Collect metrics
        run: |
          ./collect-metrics.sh ${{ github.ref_name }}

      - name: Fail if security score < 80
        run: |
          SCORE=$(jq '.security_score' metrics/*.json | tail -1)
          if [ $SCORE -lt 80 ]; then
            echo "Security score ${SCORE}/100 is below threshold"
            exit 1
          fi
```

---

## Interpreting Results

### Security Score Breakdown

| Score | Rating | Status | Action Required |
|-------|--------|--------|-----------------|
| 90-100 | Excellent | ✅ | Maintain current controls |
| 70-89 | Good | 🟡 | Minor improvements needed |
| 50-69 | Fair | ⚠️ | Significant gaps exist |
| 30-49 | Poor | 🔴 | Critical vulnerabilities |
| 0-29 | Critical | 💀 | Immediate action required |

### Attack Success Rate Targets

| Phase | Target Success Rate | Status |
|-------|---------------------|--------|
| Baseline | N/A | 🔴 100% (all attacks succeed) |
| Phase 1 | <60% | 🟡 Container escapes blocked |
| Phase 2 | <30% | 🟢 Lateral movement blocked |
| Phase 3 | <10% | ✅ Only advanced persistent threats |

### Mean Time to Detect (MTTD) Targets

| Phase | MTTD Target | Detection Method |
|-------|-------------|------------------|
| Baseline | Never | ❌ No detection |
| Phase 1 | <30 minutes | Manual log review |
| Phase 2 | <5 minutes | Falco automated alerts |
| Phase 3 | <1 minute | Multi-signal correlation |

---

## Troubleshooting

### "No pods found" error

```bash
# Ensure Semaphore is deployed
kubectl get pods -n default

# If no pods exist, deploy Semaphore first
cd ../../semaphore
helm install semaphore ./helm-chart
```

### "Permission denied" errors

```bash
# Ensure your kubectl has cluster-admin access
kubectl auth can-i create pods --all-namespaces

# Or create a service account for testing
kubectl create serviceaccount security-tester
kubectl create clusterrolebinding security-tester \
  --clusterrole=cluster-admin \
  --serviceaccount=default:security-tester
```

### Trivy not found

```bash
# Install Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

### Tests timing out

```bash
# Increase timeout in test scripts
export TEST_TIMEOUT=300  # 5 minutes

# Or skip long-running tests
./run-all-simulations.sh baseline --quick
```

---

## Viewing Results

### JSON Output

```bash
# View detailed metrics
cat metrics/baseline-20250113-103000.json | jq .

# Extract specific metrics
jq '.vulnerability_scanning' metrics/baseline-*.json
jq '.attack_simulations.attacks_succeeded' metrics/phase2-*.json
```

### Generate HTML Report

```bash
# Install dependencies
pip install jinja2 matplotlib

# Generate report
./generate-html-report.sh metrics/baseline-*.json

# Open in browser
xdg-open reports/security-report.html
```

---

## Next Steps

After completing security testing:

1. **Document Findings** - Record vulnerabilities discovered in each phase
2. **Prioritize Fixes** - Use risk scores to prioritize P0 threats
3. **Implement Controls** - Follow phase-by-phase implementation guide
4. **Re-test** - Validate each control with attack simulations
5. **Automate** - Integrate into CI/CD for continuous validation
6. **Monitor** - Set up alerting for security score regressions

---

## Resources

- **Main Threat Model**: `01-threat-modeling/README.md`
- **Attack Trees**: `01-threat-modeling/attack-trees/`
- **Test Scripts**: `01-threat-modeling/security-testing/simulations/`
- **Metrics History**: `01-threat-modeling/security-testing/metrics/`

---

## Support

If you encounter issues:

1. Check the logs: `results/<timestamp>/test-*.json`
2. Review the main testing README: `README.md`
3. Verify cluster access: `kubectl cluster-info`
4. Ensure all prerequisites are installed

For thesis-specific questions, consult your advisor or security team.
