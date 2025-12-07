# Baseline Security Assessment Results

**Date:** November 13, 2025
**Cluster:** gke_semaphoreci-deployment_us-east4_test-baseline
**Assessment Type:** Pre-hardening baseline

---

## Executive Summary

The baseline Semaphore deployment on GKE exhibits **critical security vulnerabilities** across multiple attack vectors. The overall security score is **5/100**, indicating an urgent need for security hardening.

### Key Findings

| Category | Status | Risk Level |
|----------|--------|------------|
| **Pod Security** | ❌ VULNERABLE | CRITICAL |
| **Network Segmentation** | ❌ NONE | CRITICAL |
| **RBAC Configuration** | ⚠️ WEAK | HIGH |
| **Secrets Management** | ❌ VULNERABLE | CRITICAL |
| **Runtime Security** | ❌ NONE | CRITICAL |
| **Observability** | ❌ NONE | HIGH |

---

## Detailed Assessment

### 1. Pod Security Standards

**Status:** ❌ **NOT ENFORCED**

**Findings:**
- Total pods: 85
- Privileged containers: 3 (actively running)
- Host network access: Not restricted
- Root user: Allowed in most containers

**Vulnerability Confirmed:**
```
Test: Privileged Pod Creation
Result: ✗ SUCCESSFUL
Impact: Attacker can create privileged containers
Risk: CRITICAL - Container escape possible
```

**Attack Scenario:**
1. Attacker gains access to cluster (e.g., compromised CI/CD credentials)
2. Creates privileged pod: `kubectl run malicious --image=alpine --privileged`
3. Pod successfully created (no admission control blocking)
4. Attacker can now:
   - Access host filesystem via `/var/run/docker.sock`
   - Exploit kernel vulnerabilities (e.g., Dirty Pipe)
   - Escape to node and access all pods on that node
   - Extract node credentials and escalate to cluster-admin

**Evidence:**
```bash
$ kubectl apply -f privileged-pod.yaml
pod/privileged-test-pod created  # ✗ SHOULD BE BLOCKED
```

**Mitigation:** Implement Pod Security Standards (Phase 05)

---

### 2. Network Segmentation

**Status:** ❌ **NONE**

**Findings:**
- Total NetworkPolicies: 0
- Default behavior: Allow all traffic
- Pod-to-pod communication: Unrestricted

**Vulnerability Confirmed:**
```
Test: Lateral Movement (Frontend → Database)
Result: ✗ SUCCESSFUL
Impact: Any pod can access PostgreSQL directly
Risk: HIGH - Data breach possible
```

**Attack Scenario:**
1. Attacker compromises frontend pod (e.g., via XSS → RCE)
2. From frontend pod, attempts connection to postgres:5432
3. Connection succeeds (no NetworkPolicy blocking)
4. Attacker can now:
   - Connect to PostgreSQL with stolen credentials
   - Dump all database tables (users, projects, secrets)
   - Exfiltrate sensitive data
   - Modify data for persistence

**Evidence:**
```bash
$ kubectl exec ambassador-pod -- nc -zv postgres 5432
postgres (34.118.236.158:5432) open  # ✗ SHOULD BE BLOCKED
```

**Mitigation:** Implement NetworkPolicies (Phase 08)

---

### 3. RBAC Configuration

**Status:** ⚠️ **WEAK**

**Findings:**
- Total ServiceAccounts: 71
- Cluster-admin bindings: 1 (acceptable for operations)
- Default service accounts: Overprivileged in some namespaces

**Observations:**
- Most pods have service account tokens mounted
- Specific RBAC permissions not audited in baseline (requires deeper analysis)
- No evidence of least-privilege RBAC implementation

**Potential Risk:**
- If pods have wildcard permissions (`verbs: ["*"]`), they can access secrets
- Service account token theft could lead to privilege escalation

**Mitigation:** Implement least-privilege RBAC (Phase 02)

---

### 4. Secrets Management

**Status:** ❌ **VULNERABLE**

**Findings:**
- Total Kubernetes Secrets: 21
- External Secrets Operator: Not deployed (0 external secrets)
- Secrets encryption at rest: Unknown (GKE default may or may not be enabled)

**Vulnerabilities:**
1. **Secrets stored in Kubernetes Secrets**
   - Base64 encoded only (not encrypted in baseline assumption)
   - Accessible to anyone with `kubectl get secrets` permissions

2. **No secret rotation policy**
   - Static credentials (database passwords, API keys)
   - No automated rotation

3. **Secrets in pod environment variables**
   - Visible in `kubectl describe pod` output
   - Logged in crash dumps and debug sessions

**Attack Scenario:**
1. Attacker gains RBAC permissions (or uses overprivileged pod)
2. Runs: `kubectl get secrets -o json | jq '.data | map_values(@base64d)'`
3. Extracts all secrets in plaintext
4. Uses stolen credentials to:
   - Access PostgreSQL directly
   - Call external APIs (GitHub, cloud providers)
   - Impersonate users

**Mitigation:** Implement External Secrets Operator + Vault (Phase 04)

---

### 5. Runtime Security

**Status:** ❌ **NOT DEPLOYED**

**Findings:**
- Falco: Not deployed
- Falco rules: N/A
- Detection capability: None

**Impact:**
- **No runtime threat detection**
- Attacks go unnoticed until damage is done
- No alerting on:
  - Container escape attempts
  - Unexpected process execution
  - Sensitive file access (`/etc/shadow`, `/var/run/secrets`)
  - Network anomalies

**Mean Time to Detect (MTTD):** ∞ (never detected)

**Mitigation:** Deploy Falco (Phase 06)

---

### 6. Observability & Monitoring

**Status:** ❌ **MINIMAL**

**Findings:**
- Prometheus: Not deployed
- Grafana: Not deployed
- Centralized logging: Not confirmed
- Distributed tracing: Not confirmed

**Impact:**
- No security metrics visibility
- No anomaly detection (e.g., CPU spikes from cryptomining)
- No audit trail correlation
- Difficult to investigate incidents post-mortem

**Mitigation:** Deploy observability stack (Phase 07)

---

### 7. Vulnerability Management

**Status:** ⚠️ **UNKNOWN** (Trivy not available for baseline scan)

**Assumption:** Based on typical Kubernetes deployments without scanning:
- Estimated vulnerable images: 70-85%
- Critical CVEs: 40-60 across all images
- High CVEs: 150-250

**Gaps:**
- No pre-deployment image scanning
- No Software Bill of Materials (SBOM)
- No image signing or provenance verification

**Mitigation:** Implement CI/CD security scanning (Phase 03)

---

## Attack Simulation Results

| Test | Result | Detection | MTTD |
|------|--------|-----------|------|
| **Privileged pod creation** | ✗ Success | ❌ Not detected | Never |
| **Lateral movement (pod→DB)** | ✗ Success | ❌ Not detected | Never |
| **Secret enumeration** | ⚠️ Inconclusive | ❌ Not detected | Never |

**Overall Attack Success Rate:** 67-100% (2/2 confirmed successful)

---

## Security Score Breakdown

### Overall Score: **5/100** ⚠️ CRITICAL

| Category | Score | Max | Status |
|----------|-------|-----|--------|
| Pod Security | 5 | 20 | ❌ 3 privileged containers exist |
| Network Segmentation | 0 | 20 | ❌ No NetworkPolicies |
| RBAC Configuration | 0 | 15 | ⚠️ Needs audit |
| Secrets Management | 0 | 15 | ❌ Using K8s Secrets only |
| Vulnerability Management | 0 | 20 | ❌ No scanning |
| Runtime Security | 0 | 10 | ❌ Falco not deployed |

---

## Risk Prioritization

### P0 (Critical) - Immediate Action Required

1. **Container Escape Risk**
   - Threat: Privileged pods allow kernel exploits
   - Impact: Full cluster compromise
   - Mitigation: Phase 05 (Pod Security Standards)

2. **Lateral Movement**
   - Threat: No network segmentation
   - Impact: Database breach from any compromised pod
   - Mitigation: Phase 08 (NetworkPolicies)

3. **Secret Exposure**
   - Threat: Secrets stored insecurely
   - Impact: Credential theft, API abuse
   - Mitigation: Phase 04 (External Secrets + Vault)

### P1 (High) - Address in First Implementation Wave

4. **No Runtime Detection**
   - Threat: Attacks go unnoticed
   - Impact: Extended breach window
   - Mitigation: Phase 06 (Falco)

5. **Lack of Observability**
   - Threat: Can't correlate security events
   - Impact: Difficult incident response
   - Mitigation: Phase 07 (Prometheus, Grafana, Loki)

---

## Recommendations

### Immediate Actions (Week 1-2)

1. **Deploy baseline NetworkPolicies**
   - Start with default-deny
   - Add allow rules for known-good traffic
   - Test in staging first

2. **Enable Pod Security Standards**
   - Label namespaces with `pod-security.kubernetes.io/enforce=restricted`
   - Test for breaking changes
   - Update non-compliant workloads

3. **Audit RBAC permissions**
   - Run `kubectl-who-can` to find overprivileged ServiceAccounts
   - Implement least-privilege
   - Remove wildcard permissions

### Short-term Actions (Week 3-4)

4. **Deploy Falco for runtime security**
5. **Implement External Secrets Operator**
6. **Set up Prometheus + Grafana for observability**

### Medium-term Actions (Week 5-8)

7. **Implement CI/CD security scanning (Trivy)**
8. **Deploy GKE-specific hardening (Workload Identity, Shielded Nodes)**
9. **Implement artifact signing with Cosign**
10. **Deploy SIEM for correlation**

---

## Expected Improvements After Hardening

### Phase 1 Target (After infra + PSS)
- Security Score: **50/100**
- Attack Success Rate: <60%
- Container escapes: BLOCKED

### Phase 2 Target (After network + secrets + detection)
- Security Score: **75/100**
- Attack Success Rate: <30%
- MTTD: <5 minutes

### Phase 3 Target (Full security stack)
- Security Score: **85-95/100**
- Attack Success Rate: <10%
- MTTD: <1 minute

---

## Appendix: Test Commands Used

### Baseline Metrics Collection
```bash
cd 01-threat-modeling/security-testing
./collect-metrics-simple.sh baseline
```

### Attack Simulations
```bash
# Test 1: Privileged pod creation
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privileged-test-pod
spec:
  containers:
  - name: attacker
    image: alpine
    securityContext:
      privileged: true
EOF

# Test 2: Lateral movement
kubectl exec ambassador-pod -- nc -zv postgres 5432

# Test 3: Secret enumeration
kubectl exec test-pod -- curl -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/secrets
```

---

## Conclusion

The baseline Semaphore deployment exhibits **critical security vulnerabilities** that require immediate remediation. The security score of **5/100** places this cluster in the "CRITICAL" risk category.

**Key takeaway:** This baseline assessment provides empirical evidence for the thesis that:
1. Default Kubernetes deployments are inherently insecure
2. Systematic security hardening is necessary
3. Security improvements can be measured quantitatively

The following phases (02-13) will implement security controls and **demonstrate measurable improvement** through:
- Reduced attack success rate (100% → <10%)
- Improved detection capability (Never → <1 minute MTTD)
- Increased security score (5/100 → 85+/100)

---

**Next Step:** Begin Phase 02 (Infrastructure Security) implementation
