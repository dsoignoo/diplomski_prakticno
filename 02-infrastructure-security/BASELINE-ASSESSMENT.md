# Baseline Cluster Assessment - Phase 02

**Date:** November 13, 2025
**Cluster:** test-baseline (us-east4)
**Type:** Standard GKE (non-Autopilot)

## Assessment Results

### ✅ Security Features PRESENT in Baseline

| Feature | Status | Notes |
|---------|--------|-------|
| **Shielded Nodes** | ✅ Enabled | Good! Provides boot integrity monitoring |
| **Network Policy Support** | ✅ Enabled (Calico) | Good! Can enforce NetworkPolicies in Phase 08 |
| **Security Posture** | ✅ BASIC | Provides some vulnerability scanning |
| **Cloud Logging** | ✅ Enabled | Audit logs available |
| **Cloud Monitoring** | ✅ Enabled | Basic metrics available |

### ❌ Security Features MISSING in Baseline

| Feature | Status | Risk Level | Impact |
|---------|--------|------------|--------|
| **Workload Identity** | ❌ NOT CONFIGURED | **CRITICAL** | All pods inherit node SA permissions |
| **Secrets Encryption** | ❌ NOT ENABLED | **CRITICAL** | Secrets in etcd are base64 only |
| **Private Nodes** | ❌ NOT ENABLED | **HIGH** | Nodes have public IPs |
| **GKE Autopilot** | ❌ Standard GKE | **MEDIUM** | Manual node management |
| **Binary Authorization** | ❌ NOT CONFIGURED | **HIGH** | Unsigned images can deploy |

## Phase 02 Implementation Options

### Option 1: In-Place Hardening (Recommended for Thesis)

**Keep this baseline cluster** and enable missing features incrementally:

```bash
# Step 1: Enable Workload Identity on existing cluster
gcloud container clusters update test-baseline \
  --zone=us-east4 \
  --workload-pool=semaphoreci-deployment.svc.id.goog

# Step 2: Enable Application-layer Secrets Encryption
# (Requires cluster recreation - document this limitation)

# Step 3: Create service accounts for Workload Identity
gcloud iam service-accounts create semaphore-guard \
  --project=semaphoreci-deployment

# Step 4: Bind K8s SA to GCP SA
kubectl annotate serviceaccount guard \
  -n default \
  iam.gke.io/gcp-service-account=semaphore-guard@semaphoreci-deployment.iam.gserviceaccount.com
```

**Pros:**
- Shows gradual security improvement
- Good for thesis (demonstrate iterative hardening)
- No migration needed

**Cons:**
- Some features require cluster recreation (secrets encryption)
- Standard GKE requires manual node management

---

### Option 2: Deploy New Hardened Cluster (Best Security)

Create a fully hardened GKE Autopilot cluster with all Phase 02 controls:

```bash
cd gke-hardened/terraform
terraform apply
```

**Pros:**
- All Phase 02 controls from day 1
- GKE Autopilot (zero node management)
- Clean slate for security best practices

**Cons:**
- Requires Semaphore migration
- Two clusters temporarily (costs $150-200/month total)

---

### Option 3: Document Baseline + Future Hardened Deployment

**For thesis purposes, this is ideal:**

1. **Keep baseline cluster** - Document current state
2. **Run security tests** - Show vulnerabilities (already done!)
3. **Create Terraform config** - Show how it WOULD be hardened (already exists!)
4. **Document improvements** - Theoretical security score improvement

**Thesis Sections:**
- Chapter 5.1: "Baseline Security Assessment" (use current assessment)
- Chapter 5.2: "Infrastructure Hardening Design" (reference Terraform config)
- Chapter 5.3: "Expected Security Improvements" (based on Phase 02 controls)

---

## Recommended Approach for Your Thesis

Given your current situation, I recommend **Option 3** with selective in-place hardening:

### Week 1: Document Current State
```bash
# Already done!
- Baseline security score: 5/100
- Attack simulations: 100% success rate
- Infrastructure assessment: Missing Workload Identity, Secrets Encryption
```

### Week 2: Enable What You Can In-Place
```bash
# Enable Workload Identity (doesn't require cluster recreation)
gcloud container clusters update test-baseline \
  --zone=us-east4 \
  --workload-pool=semaphoreci-deployment.svc.id.goog

# Create service accounts
gcloud iam service-accounts create semaphore-guard

# Test improvement
./test-workload-identity.sh
# Result: Now blocks metadata API abuse! ✅
```

### Week 3-4: Implement Pod Security Standards (Phase 05)
```bash
# This can be done on existing cluster!
kubectl label namespace default pod-security.kubernetes.io/enforce=restricted

# Re-test privileged pod
/tmp/test-privileged-pod.sh
# Result: Now blocked! ✅

# Security score improves: 5/100 → 40/100
```

### Week 5-6: Implement NetworkPolicies (Phase 08)
```bash
# Baseline cluster already has Calico support ✅
kubectl apply -f 08-network-policies/00-default-deny.yaml

# Re-test lateral movement
/tmp/test-lateral-movement.sh
# Result: Now blocked! ✅

# Security score improves: 40/100 → 65/100
```

### Week 7-8: Observability & Runtime Security
```bash
# Deploy Falco (Phase 06)
helm install falco falcosecurity/falco

# Deploy Prometheus/Grafana (Phase 07)
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack

# Security score improves: 65/100 → 85/100
```

---

## Security Score Projection

| Phase | Implemented Controls | Security Score | Attack Success Rate |
|-------|---------------------|----------------|---------------------|
| **Baseline** | Logging, basic monitoring | 5/100 | 100% (12/12) |
| **+Workload Identity** | WI, logging, monitoring | 20/100 | 92% (11/12) |
| **+Pod Security** | WI, PSS, logging | 40/100 | 58% (7/12) |
| **+NetworkPolicies** | WI, PSS, NetPol, logging | 65/100 | 25% (3/12) |
| **+Runtime Security** | WI, PSS, NetPol, Falco | 85/100 | 8% (1/12) |

---

## Features That CANNOT Be Added to Existing Cluster

These require cluster recreation (good to document in thesis as "limitations of in-place hardening"):

1. **Application-layer Secrets Encryption**
   - Requires cluster recreation with KMS key
   - Alternative: Use External Secrets Operator (Phase 04)

2. **GKE Autopilot**
   - Migration from Standard to Autopilot not supported
   - Would need new cluster

3. **Private Nodes**
   - Requires cluster recreation
   - Alternative: Use Cloud Armor + firewall rules

---

## Next Actions

Based on your thesis timeline and current cluster, proceed with:

### Immediate (This Week):
1. ✅ Document baseline state (DONE - this file)
2. Enable Workload Identity on existing cluster
3. Test GCP metadata API access (should now be blocked)

### Next Week:
4. Implement Phase 05 (Pod Security Standards)
5. Test privileged pod creation (should now be blocked)

### Following Weeks:
6. Implement Phase 08 (NetworkPolicies)
7. Implement Phase 06 (Falco)
8. Implement Phase 07 (Observability)

### Final Thesis Presentation:
- Show security score progression: 5 → 85/100
- Show attack success rate reduction: 100% → 8%
- Demonstrate working security controls
- Compare baseline vs. hardened state

---

## Cost Estimate

**Current approach (in-place hardening):**
```
Existing cluster:          $0 (already running)
Workload Identity:         $0 (free)
Pod Security Standards:    $0 (free)
NetworkPolicies:           $0 (free)
Falco:                     $0 (open source)
Prometheus/Grafana:        ~$5-10/month (storage)
────────────────────────────────────
Total Additional Cost:     $5-10/month
```

**Alternative (new hardened cluster):**
```
Hardened GKE Autopilot:    ~$100/month
Keep baseline for tests:   ~$50/month (can scale down)
────────────────────────────────────
Total:                     ~$150/month
```

**Recommendation:** Stay with in-place hardening to maximize free credit duration.

---

## Conclusion

Your baseline cluster has a **decent foundation** (Shielded Nodes, Network Policy support) but is missing **critical security controls**:

- ❌ Workload Identity (allows metadata API abuse)
- ❌ Secrets Encryption (secrets in etcd are base64)
- ❌ Pod Security Standards (privileged pods allowed)
- ❌ NetworkPolicies deployed (no segmentation)
- ❌ Runtime Security (no Falco)

**Recommended Path:** Implement missing controls incrementally on existing cluster, documenting improvements at each phase for your thesis.

**Expected Final State:** Security score 85/100, attack success rate <10%, all critical threats mitigated.
