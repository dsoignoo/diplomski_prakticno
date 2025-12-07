# Quick Start - Baseline Deployment

## TL;DR - What You Need to Do

### 1. Enable GCP APIs (5 minutes)
```bash
gcloud auth application-default login
gcloud services enable container.googleapis.com compute.googleapis.com cloudresourcemanager.googleapis.com --project=semaphoreci-deployment
```
Wait 2-3 minutes for APIs to activate.

### 2. Reserve Static IP (1 minute)
```bash
gcloud compute addresses create semaphore-baseline-ip --global --project=semaphoreci-deployment
gcloud compute addresses describe semaphore-baseline-ip --global --format="value(address)"
```
**Note this IP** (e.g., `34.120.45.67`)

### 3. Configure Namecheap DNS (2 minutes)
Go to: https://ap.www.namecheap.com/domains/domaincontrolpanel/hamir.online/advancedns

Add TWO A Records:

| Type | Host | Value | TTL |
|------|------|-------|-----|
| A Record | `@` | `YOUR_STATIC_IP` | 300 |
| A Record | `*` | `YOUR_STATIC_IP` | 300 |

### 4. Run Automated Deployment Script (30-40 minutes)
```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno
bash 00-baseline-deployment-guide.sh
```

The script will:
- Wait for DNS propagation
- Generate Let's Encrypt wildcard certificate (requires TXT record)
- Deploy GKE cluster with Terraform (~10-15 min)
- Deploy Semaphore via Helm (~15-20 min)

### 5. Access Semaphore
```bash
# Get credentials
kubectl get secret semaphore-authentication -o jsonpath='{.data.ROOT_USER_EMAIL}' | base64 -d
kubectl get secret semaphore-authentication -o jsonpath='{.data.ROOT_USER_PASSWORD}' | base64 -d
```

Open: **https://hamir.online**

---

## Alternative: Manual Step-by-Step

If you prefer manual control, follow: `00-BASELINE-SETUP-MANUAL.md`

---

## What Gets Deployed

**GKE Cluster (Baseline - INSECURE):**
- Name: `test-baseline`
- Location: `us-east4`
- Machine: `e2-custom-8-16384` (8 vCPU, 16GB RAM)
- Datapath: **LEGACY** (Calico, not eBPF)
- Master API: **0.0.0.0/0** (accessible from internet) ⚠️
- Network Policy: Enabled but **no policies defined** ⚠️

**Semaphore Platform (15+ microservices):**
- Front (Web UI)
- Guard (Authentication)
- Controller (Job orchestration)
- PostgreSQL (14.15-alpine, 4Gi)
- RabbitMQ (3.13.7, 2Gi)
- Redis (7.2.4, 1Gi)
- MinIO x3 (artifacts, cache, logs, 3Gi each)
- Hubs: Repository, Artifact, Project, Branch

**Domain Configuration:**
- Main: `https://hamir.online`
- Wildcard: `https://*.hamir.online`
- SSL: Let's Encrypt wildcard certificate

**Estimated Costs:**
- GKE cluster: ~$80/month
- Storage: ~$10/month
- Load Balancer: ~$20/month
- **Total: ~$110/month** (covered by $300 GCP free credits)

---

## Known Security Issues (Baseline)

This deployment is **intentionally insecure** for comparison purposes:

- ❌ **Master API exposed to internet** (0.0.0.0/0)
- ❌ **No NetworkPolicies** - all pods can communicate freely
- ❌ **No runtime security** - no Falco detection
- ❌ **No image scanning** - no Trivy
- ❌ **Legacy datapath** - not using eBPF
- ❌ **Secrets in plaintext** - no External Secrets Operator
- ❌ **No security monitoring** - no SIEM
- ❌ **No workload identity** - pods use default SA

**CIS Kubernetes Benchmark: ~55%**

These will be fixed progressively in Phase 1, 2, and 3.

---

## Next Steps

After baseline deployment:

1. **Document current state** - Take screenshots, run penetration tests
2. **Phase 1** - NetworkPolicies + Falco + GKE Hardening
3. **Phase 2** - CI/CD Security + WAF + OPA Gatekeeper
4. **Phase 3** - Observability + SIEM + Cloud Security

**Estimated timeline:** 6-8 weeks total

---

## Troubleshooting

**DNS not resolving?**
```bash
dig hamir.online @8.8.8.8
dig test.hamir.online @8.8.8.8
# Both should return your static IP
# Allow 5-10 minutes for propagation
```

**Terraform errors?**
```bash
# Re-authenticate
gcloud auth application-default login

# Check APIs
gcloud services list --enabled | grep -E "compute|container"
```

**Pods not starting?**
```bash
kubectl get pods --all-namespaces
kubectl describe pod <pod-name>
kubectl logs <pod-name>
```

---

## Cost Management

**To stop spending:**
```bash
# Destroy infrastructure
cd /home/osboxes/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke
terraform destroy -auto-approve

# Release static IP
gcloud compute addresses delete semaphore-baseline-ip --global
```

**To restart:**
```bash
# Just run the deployment script again
bash 00-baseline-deployment-guide.sh
```
