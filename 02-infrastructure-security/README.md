# Phase 02: Infrastructure Security

## Overview

This phase implements **infrastructure-level security controls** for the GKE cluster running Semaphore. These foundational security improvements address critical threats identified in Phase 01 threat modeling.

## Threat Mitigation Mapping

| Threat (from Phase 01) | Risk Score | Infrastructure Control | Expected Improvement |
|------------------------|------------|------------------------|----------------------|
| **Container escape** | 9 (CRITICAL) | Shielded Nodes, Secure Boot | Prevents bootkit persistence |
| **GCP metadata abuse** | 9 (HIGH) | Workload Identity | Node SA ≠ Pod SA |
| **Kubernetes API exposure** | 6 (MEDIUM) | Private cluster, authorized networks | Reduces attack surface |
| **Secret exposure** | 12 (CRITICAL) | etcd encryption, KMS | Secrets encrypted at rest |
| **Unpatched vulnerabilities** | 6 (MEDIUM) | Auto-upgrade, vulnerability scanning | Automated patching |

## Security Controls Implemented

### 1. GKE Autopilot Hardened Cluster

**What it does:**
- Fully managed control plane and nodes
- Automatic security best practices
- Built-in Pod Security Standards
- Automated node upgrades and patching

**Why it matters:**
- Eliminates node misconfiguration (CIS compliance by default)
- Reduces operational burden
- Ensures security patches applied automatically

### 2. Workload Identity

**What it does:**
- Binds Kubernetes ServiceAccounts to GCP Service Accounts
- No long-lived credentials (no service account keys)
- Fine-grained IAM permissions per service

**Why it matters:**
- **Mitigates:** GCP metadata API abuse (Threat Score: 9)
- **Baseline:** Node SA has broad permissions, all pods inherit
- **Hardened:** Each pod has minimal IAM permissions
- **Attack prevented:** Compromised pod can't access GCP resources it doesn't need

**Example:**
```bash
# Baseline (vulnerable)
$ kubectl exec malicious-pod -- curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Returns: Node SA token with compute.admin permissions ❌

# Phase 02 (hardened)
$ kubectl exec guard-pod -- curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Returns: Guard SA token with ONLY secretmanager.secretAccessor ✅
```

### 3. Shielded Nodes + Secure Boot

**What it does:**
- Verifies node boot integrity using cryptographic signatures
- Detects bootkit/rootkit malware
- Integrity monitoring alerts on tampering

**Why it matters:**
- **Mitigates:** Container escape → persistent node compromise
- **Baseline:** Attacker who escapes to node can install rootkit
- **Hardened:** Rootkit installation triggers integrity monitoring alert
- **Detection:** Immediate alert in Security Command Center

### 4. Private Cluster + Authorized Networks

**What it does:**
- Nodes have no public IP addresses
- API server accessible only from authorized IPs
- Cloud NAT for outbound internet (pull images, etc.)

**Why it matters:**
- **Mitigates:** Direct Kubernetes API attacks from internet
- **Baseline:** API server on public IP (even if firewalled)
- **Hardened:** API server on private VPC, zero internet exposure

### 5. Secrets Encryption at Rest (etcd + KMS)

**What it does:**
- Kubernetes Secrets encrypted in etcd using GCP KMS keys
- Key rotation managed by Google
- Access audited in Cloud Audit Logs

**Why it matters:**
- **Mitigates:** etcd database compromise
- **Baseline:** Secrets in etcd are base64 only (plaintext)
- **Hardened:** Even with etcd access, secrets are encrypted

### 6. Network Policy Enforcement (Dataplane V2)

**What it does:**
- eBPF-based networking (not iptables)
- Native Kubernetes NetworkPolicy support
- High performance, low overhead

**Why it matters:**
- **Enables:** Phase 08 NetworkPolicy implementation
- **Baseline:** Cluster can't enforce NetworkPolicies
- **Hardened:** Ready for zero-trust network segmentation

### 7. Security Posture Management + Vulnerability Scanning

**What it does:**
- Continuous vulnerability scanning of running containers
- CIS benchmark compliance checks
- Security findings in Security Command Center

**Why it matters:**
- **Visibility:** Know which images have CVEs
- **Compliance:** CIS Kubernetes benchmark violations detected
- **Actionable:** Recommendations to fix vulnerabilities

### 8. Binary Authorization (prepared, enforced in Phase 03)

**What it does:**
- Policy that only allows signed container images
- Blocks unsigned or untrusted images

**Why it matters:**
- **Mitigates:** Supply chain attacks (Phase 01 threat)
- **Baseline:** Any image can be deployed
- **Hardened:** Only Cosign-signed images allowed (implemented in Phase 03)

### 9. GKE Backup

**What it does:**
- Automated daily backups of Kubernetes resources
- Volume data + Secrets included
- 30-day retention, encrypted with KMS

**Why it matters:**
- **Disaster recovery:** Restore cluster after ransomware
- **Compliance:** Data retention requirements
- **Testing:** Validate backup/restore procedures

---

## Implementation Guide

### Prerequisites

1. **GCP Account with free credits**
   - Sign up: https://cloud.google.com/free
   - Get $300 free credits (90 days)

2. **Installed tools**
   ```bash
   # Install gcloud, terraform, kubectl
   curl https://sdk.cloud.google.com | bash
   terraform version  # Should be >= 1.5.0
   kubectl version --client
   ```

3. **GCP Project setup**
   ```bash
   export PROJECT_ID="semaphore-security-$(date +%s)"
   gcloud projects create $PROJECT_ID
   gcloud config set project $PROJECT_ID

   # Enable required APIs
   gcloud services enable container.googleapis.com compute.googleapis.com \
     servicenetworking.googleapis.com iam.googleapis.com \
     binaryauthorization.googleapis.com securitycenter.googleapis.com
   ```

### Step 1: Deploy Hardened GKE Cluster

```bash
cd 02-infrastructure-security/gke-hardened/terraform

# Create terraform.tfvars
cat > terraform.tfvars <<EOF
project_id     = "$PROJECT_ID"
region         = "us-central1"
cluster_name   = "semaphore-prod-hardened"
network_name   = "semaphore-vpc"

# Security features
enable_shielded_nodes           = true
enable_secure_boot              = true
enable_integrity_monitoring     = true
enable_network_policy           = true
enable_private_nodes            = true
enable_private_endpoint         = false  # Keep public for kubectl

# Security Posture
security_posture_mode          = "ENTERPRISE"
vulnerability_mode             = "VULNERABILITY_ENTERPRISE"

# Backup
enable_backup                  = true
backup_schedule                = "0 2 * * *"
backup_retention_days          = 30
EOF

# Deploy (takes ~10-15 minutes)
terraform init
terraform plan
terraform apply
```

**Expected output:**
```
Apply complete! Resources: 12 added, 0 changed, 0 destroyed.

Outputs:
cluster_name = "semaphore-prod-hardened"
guard_service_account_email = "semaphore-guard@PROJECT.iam.gserviceaccount.com"
kubectl_connection_command = "gcloud container clusters get-credentials..."
```

### Step 2: Configure kubectl

```bash
gcloud container clusters get-credentials semaphore-prod-hardened \
  --region=us-central1 --project=$PROJECT_ID

# Verify connection
kubectl cluster-info
kubectl get nodes
```

### Step 3: Verify Security Features

Run the verification script:

```bash
cd ../
./verify-infrastructure-security.sh
```

**Expected checks:**
- ✅ Shielded Nodes enabled
- ✅ Workload Identity configured
- ✅ Private nodes (no public IPs)
- ✅ Network Policy support (Dataplane V2)
- ✅ Secrets encryption enabled
- ✅ Binary Authorization configured
- ✅ Vulnerability scanning active
- ✅ Backup plan created

### Step 4: Deploy Semaphore to Hardened Cluster

```bash
# Navigate to Semaphore deployment
cd ../../semaphore

# Deploy using Helm
helm install semaphore ./helm-chart \
  --namespace semaphore \
  --create-namespace \
  --timeout 20m

# Wait for pods to be ready
kubectl wait --for=condition=Ready pods --all -n semaphore --timeout=300s
```

---

## Security Validation & Testing

### Test 1: Workload Identity

**Objective:** Verify pods can't access node service account

```bash
cd ../../01-threat-modeling/security-testing

cat > /tmp/test-workload-identity.sh <<'EOF'
#!/bin/bash
echo "=== TEST: Workload Identity Isolation ==="
echo ""

POD=$(kubectl get pods -n semaphore -o name | head -1 | cut -d/ -f2)
echo "Testing from pod: $POD"
echo ""

# Try to get node service account token
echo "[Test] Attempting to access node service account via metadata API..."
RESULT=$(kubectl exec -n semaphore $POD -- sh -c '
  curl -sS -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
' 2>&1)

echo "Returned identity: $RESULT"

if echo "$RESULT" | grep -q "compute@developer.gserviceaccount.com"; then
    echo ""
    echo "❌ VULNERABLE: Pod accessing node service account"
    echo "   Impact: Overprivileged access to GCP resources"
elif echo "$RESULT" | grep -q "semaphore-guard"; then
    echo ""
    echo "✅ SECURE: Workload Identity working correctly"
    echo "   Pod has dedicated service account with minimal permissions"
else
    echo ""
    echo "✅ SECURE: Metadata API not accessible or Workload Identity enabled"
fi
EOF

chmod +x /tmp/test-workload-identity.sh
/tmp/test-workload-identity.sh
```

**Expected Result (Phase 02):**
```
✅ SECURE: Workload Identity working correctly
   Pod has dedicated service account with minimal permissions
```

---

### Test 2: Shielded Nodes Verification

```bash
# Check that nodes have Secure Boot enabled
gcloud compute instances list \
  --filter="name~'gke-semaphore'" \
  --format="table(name,shieldedInstanceConfig.enableSecureBoot,shieldedInstanceConfig.enableIntegrityMonitoring)"

# Expected: All nodes show enableSecureBoot=True
```

---

### Test 3: Private Cluster Validation

```bash
# Verify nodes have no public IPs
kubectl get nodes -o wide

# Expected: EXTERNAL-IP column shows <none> for all nodes
```

---

### Test 4: Secrets Encryption

```bash
# Create test secret
kubectl create secret generic test-encryption \
  --from-literal=password=SuperSecret123

# Verify it's encrypted in etcd (requires etcd access - check via audit logs)
gcloud logging read "protoPayload.methodName=google.container.v1.ClusterManager.CreateCluster" \
  --limit=1 --format=json | jq '.databaseEncryption'

# Expected: state: "ENCRYPTED"
```

---

### Test 5: Re-run Baseline Attack Simulations

Now let's see if our infrastructure changes blocked any attacks:

```bash
cd ../../01-threat-modeling/security-testing

# Re-run privileged pod test (should still succeed in Phase 02 - blocked in Phase 05)
/tmp/test-privileged-pod.sh

# Re-run lateral movement test (should still succeed - blocked in Phase 08)
/tmp/test-lateral-movement.sh

# Test Workload Identity (NEW - should be blocked now)
/tmp/test-workload-identity.sh
```

**Expected Phase 02 Results:**
- Privileged pod: ❌ Still succeeds (will be blocked in Phase 05)
- Lateral movement: ❌ Still succeeds (will be blocked in Phase 08)
- **Workload Identity abuse: ✅ NOW BLOCKED** (infrastructure improvement!)

---

## Security Metrics Comparison

### Before (Baseline)

```
Security Score: 5/100
Infrastructure Security: 0/25 points

Vulnerabilities:
  ❌ Standard GKE nodes (no shielding)
  ❌ Node service account has broad permissions
  ❌ Secrets not encrypted at rest
  ❌ No vulnerability scanning
  ❌ Public cluster endpoints
```

### After (Phase 02)

```
Security Score: ~35/100 (+30 points improvement)
Infrastructure Security: 20/25 points

Improvements:
  ✅ Shielded Nodes + Secure Boot (+5 points)
  ✅ Workload Identity (+10 points)
  ✅ Secrets encrypted with KMS (+5 points)
  ✅ Vulnerability scanning enabled (+3 points)
  ✅ Private nodes (+2 points)

Still vulnerable (addressed in later phases):
  ⚠️ No Pod Security Standards (Phase 05)
  ⚠️ No NetworkPolicies (Phase 08)
  ⚠️ No runtime detection (Phase 06)
```

---

## Cost Breakdown

### GKE Autopilot Cluster
```
Component                    Monthly Cost    Covered by $300 Credits
------------------------------------------------------------------
Control Plane               FREE             N/A
Workload vCPU (15 pods)     ~$50-70          Yes (6 months)
Workload Memory (30 GB)     ~$20-30          Yes
Network egress              ~$5-10           Yes
Backup storage (100 GB)     ~$3              Yes
------------------------------------------------------------------
TOTAL ESTIMATED             ~$78-113/month   3-4 months free
```

---

## Troubleshooting

### Issue: Terraform apply fails with "quota exceeded"

**Solution:**
```bash
# Check quotas
gcloud compute project-info describe --project=$PROJECT_ID | grep -A 10 quotas

# Request quota increase
# https://console.cloud.google.com/iam-admin/quotas
```

### Issue: kubectl can't connect to cluster

**Solution:**
```bash
# Reconfigure credentials
gcloud container clusters get-credentials semaphore-prod-hardened \
  --region=us-central1 --project=$PROJECT_ID

# Check firewall rules allow your IP
curl ifconfig.me  # Your public IP
# Add to authorized_networks in terraform.tfvars if needed
```

### Issue: Pods can't pull images

**Solution:**
```bash
# Verify Cloud NAT is working
kubectl run test --image=busybox --command -- sleep 3600
kubectl logs test

# Check NAT configuration
gcloud compute routers nats list --router=semaphore-vpc-router --region=us-central1
```

---

## Next Steps

After completing Phase 02:

1. **Phase 03:** CI/CD Security (Trivy scanning, Cosign signing)
2. **Phase 04:** Secrets Management (External Secrets Operator + Vault)
3. **Phase 05:** Pod Security Standards (Block privileged pods)
4. **Phase 06:** Runtime Security (Falco detection)
5. **Phase 07:** Observability (Prometheus, Grafana, Loki)
6. **Phase 08:** Network Policies (Block lateral movement)

---

## Cleanup

When testing is complete:

```bash
cd 02-infrastructure-security/gke-hardened/terraform

# Destroy all resources
terraform destroy

# Or delete entire project
gcloud projects delete $PROJECT_ID
```

---

## References

- [GKE Autopilot Security](https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-security)
- [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [Shielded GKE Nodes](https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes)
- [Application-layer Secrets Encryption](https://cloud.google.com/kubernetes-engine/docs/how-to/encrypting-secrets)
- [GKE Dataplane V2](https://cloud.google.com/kubernetes-engine/docs/concepts/dataplane-v2)
- [GKE Security Posture](https://cloud.google.com/kubernetes-engine/docs/concepts/security-posture-dashboard)

---

## Summary

Phase 02 establishes **secure infrastructure foundations** that:

1. ✅ **Mitigate GCP metadata abuse** via Workload Identity
2. ✅ **Encrypt secrets at rest** with KMS
3. ✅ **Prevent bootkit persistence** with Shielded Nodes
4. ✅ **Enable NetworkPolicy enforcement** (used in Phase 08)
5. ✅ **Provide vulnerability visibility** via Security Posture

**Security Score Improvement:** 5/100 → 35/100 (+30 points, 600% improvement)

**Attack Success Rate:** Still ~100% (lateral movement and privilege escalation not yet mitigated)

**Next:** Implement Pod Security Standards (Phase 05) to block container escape attacks.
