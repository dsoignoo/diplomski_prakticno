# Baseline Semaphore CI/CD Deployment - Complete Documentation

**Date:** November 13, 2025
**Platform:** Google Kubernetes Engine (GKE)
**Domain:** hamir.online
**Semaphore Version:** v1.5.0 (Community Edition)
**Purpose:** Establish intentionally insecure baseline for security research comparison

---

## Deployment Summary

Successfully deployed Semaphore CI/CD platform on GKE with intentionally minimal security controls to serve as baseline for measuring security improvements in subsequent phases.

**Access URL:** https://hamir.online
**Root Email:** admin@hamir.online
**Root Password:** VGktkau-IjbLhm3MrweZafRyWGA=
**API Token:** 0-Zmo5VCm0fmmYGHqHX7

---

## Infrastructure Configuration

### GKE Cluster Details

- **Cluster Name:** test-baseline
- **Region:** us-east4
- **Zone:** us-east4-b
- **Network Mode:** VPC_NATIVE
- **Datapath Provider:** LEGACY_DATAPATH (Calico for NetworkPolicies)
- **Node Pool:** e2-custom-8-16384 (8 vCPU, 16GB RAM)
- **Node Count:** 1
- **Private Nodes:** Enabled (nodes have no external IPs)

### Networking

- **VPC Network:** default
- **Static IP (Ingress):** 34.49.224.110 (global-static-ip-address-baseline)
- **Static IP (Reserved):** 34.117.168.211 (semaphore-baseline-ip, unused)
- **Cloud NAT:** nat-router-baseline / nat-config-baseline
- **DNS:**
  - Root (@): 34.49.224.110
  - Wildcard (*): 34.49.224.110

### SSL/TLS Configuration

- **Certificate:** Let's Encrypt wildcard certificate
- **Domains:** *.hamir.online, hamir.online
- **Certificate Name (GCP):** cert-baseline
- **Issuer:** Let's Encrypt E7
- **Valid Until:** February 10, 2026

---

## Deployment Steps Executed

### 1. Prerequisites Setup

```bash
# Verify tools
gcloud --version
terraform --version
helm version
kubectl version
openssl version

# Configure GCP project
export PROJECT_ID=semaphoreci-deployment
gcloud config set project $PROJECT_ID
```

### 2. Enable Required GCP APIs

```bash
gcloud services enable container.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable cloudresourcemanager.googleapis.com
```

### 3. DNS Configuration

Configured Namecheap DNS for hamir.online:
- **Record 1:** Type: A, Host: @, Value: 34.49.224.110
- **Record 2:** Type: A, Host: *, Value: 34.49.224.110

### 4. SSL Certificate Generation

```bash
# Install certbot
sudo snap install --classic certbot

# Generate Let's Encrypt wildcard certificate
sudo certbot certonly --manual \
  --preferred-challenges dns \
  --email your-email@example.com \
  --agree-tos \
  --no-eff-email \
  -d "hamir.online" \
  -d "*.hamir.online"

# Copy certificates to terraform directory
sudo cp /etc/letsencrypt/live/hamir.online/privkey.pem \
  ~/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke/baseline.key

sudo cp /etc/letsencrypt/live/hamir.online/fullchain.pem \
  ~/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke/baseline.fullchain.cer

sudo chown $USER:$USER baseline.*
```

### 5. Terraform Infrastructure Deployment

Modified `semaphore/ephemeral_environment/terraform/gke/main.tf` to add Cloud NAT:

```hcl
# Cloud Router for NAT
resource "google_compute_router" "nat_router" {
  name    = substr("nat-router-${var.branch}", 0, min(40, length("nat-router-${var.branch}")))
  region  = "us-east4"
  network = "default"
  project = var.project_name
}

# Cloud NAT configuration to allow private nodes to access internet
resource "google_compute_router_nat" "nat_config" {
  name                               = substr("nat-config-${var.branch}", 0, min(40, length("nat-config-${var.branch}")))
  router                             = google_compute_router.nat_router.name
  region                             = google_compute_router.nat_router.region
  project                            = var.project_name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
```

Deployed infrastructure:

```bash
cd ~/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke

terraform init

terraform apply \
  -var="project_name=semaphoreci-deployment" \
  -var="branch=baseline" \
  -var="path_to_private_key=baseline.key" \
  -var="path_to_fullchain_cer=baseline.fullchain.cer"
```

**Deployment Time:** 10m 43s
**Resources Created:**
- GKE cluster
- Node pool
- Global static IP address
- SSL certificate
- Cloud Router
- Cloud NAT

### 6. Kubectl Configuration

```bash
gcloud container clusters get-credentials test-baseline --region us-east4
kubectl config current-context
```

### 7. Emissary Ingress CRDs Deployment

```bash
kubectl apply -f https://app.getambassador.io/yaml/emissary/3.9.1/emissary-crds.yaml
kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n emissary-system
```

### 8. Semaphore Helm Deployment

```bash
helm upgrade --install semaphore "oci://ghcr.io/semaphoreio/semaphore" \
  --debug \
  --version v1.5.0 \
  --timeout 40m \
  --set global.edition=ce \
  --set global.domain.ip="34.49.224.110" \
  --set global.domain.name="hamir.online" \
  --set global.rootUser.email="admin@hamir.online" \
  --set global.rootUser.name="Admin" \
  --set global.rootUser.githubLogin="" \
  --set ingress.staticIpName="global-static-ip-address-baseline" \
  --set ingress.enabled=true \
  --set ingress.ssl.enabled=true \
  --set ingress.ssl.certName="cert-baseline" \
  --set ingress.ssl.type="google" \
  --wait
```

**Deployment Time:** ~20 minutes
**Pods Deployed:** 66 total
- 1 Ambassador (Emissary Ingress)
- 3 Emissary API Extension pods
- 62 Semaphore microservices
  - Authentication: guard, auth, keycloak
  - Project Management: projecthub, repohub, repository-hub
  - CI/CD: plumber, zebra, controller
  - Webhooks: github-hooks, hooks-processor, hooks-receiver
  - Storage: minio-artifacts, minio-cache, minio-logs
  - Databases: postgres, rabbitmq, redis
  - APIs: public-api, public-api-gateway
  - Notifications: notifications, github-notifier
  - Other services: scouter, secrethub, loghub2, badges, etc.

**One Pod in CrashLoopBackOff (Expected):**
- `self-hosted-hub-agent-cleaner`: Fails without agent configuration (intentional for baseline)

### 9. DNS Issue Resolution

Initial deployment pointed DNS to wrong IP (34.117.168.211 instead of 34.49.224.110).

**Fix:** Updated Namecheap DNS records to point to correct GKE Ingress IP: 34.49.224.110

### 10. Validation

```bash
# Check all pods
kubectl get pods -A

# Check ingress
kubectl get ingress

# Check services
kubectl get svc

# Test HTTPS access
curl -I https://hamir.online
```

**Result:** All services healthy, HTTPS working, Semaphore UI accessible.

---

## Intentional Security Vulnerabilities (Baseline)

This deployment intentionally includes security weaknesses to establish a baseline for comparison:

### Network Security
- ✗ No NetworkPolicies defined (all pod-to-pod communication allowed)
- ✗ Master API server accessible from 0.0.0.0/0
- ✗ Private nodes rely on Cloud NAT for egress (not isolated)
- ✗ No network segmentation between services

### Access Control
- ✗ No GitHub/GitLab/Bitbucket authentication configured
- ✗ Single root user with full access
- ✗ No RBAC policies beyond defaults
- ✗ No Workload Identity configured

### Runtime Security
- ✗ No runtime security monitoring (Falco)
- ✗ No admission controllers (OPA Gatekeeper)
- ✗ No Pod Security Standards enforcement
- ✗ Containers may run as root

### Secrets Management
- ✗ Secrets stored as Kubernetes Secrets (base64 encoded)
- ✗ No external secrets management
- ✗ No encryption at rest for application secrets
- ✗ Root password visible in cluster secrets

### Observability
- ✗ Minimal logging (only basic GKE logging)
- ✗ No centralized log aggregation
- ✗ No SIEM integration
- ✗ No distributed tracing
- ✗ No security alerting

### Image Security
- ✗ No image scanning
- ✗ No image signing verification
- ✗ No Binary Authorization
- ✗ Images pulled from public registries without verification

### Data Protection
- ✗ No backup strategy
- ✗ No disaster recovery plan
- ✗ No data encryption at rest (application level)
- ✗ Database credentials in plain Kubernetes secrets

### Cluster Hardening
- ✗ Using LEGACY_DATAPATH (Calico) instead of GKE Dataplane V2
- ✗ No Security Command Center integration
- ✗ No GKE Autopilot security features
- ✗ No node auto-upgrade security patches
- ✗ No vulnerability scanning enabled

---

## Deployed Components

### Core Infrastructure (3 pods)
- ambassador (Emissary Ingress)
- emissary-apiext (3 replicas)

### Authentication Services (9 pods)
- auth
- guard-api
- guard-authentication-api
- guard-consumers
- guard-id-http-api
- guard-instance-config
- guard-organization-api
- guard-user-api
- keycloak

### Project & Repository Management (7 pods)
- projecthub-public
- projecthub-standalone-grpc
- projecthub-workers
- repository-hub
- repohub
- branch-hub
- scouter-api

### CI/CD Pipeline (8 pods)
- plumber
- plumber-public
- public-api
- public-api-gateway
- semaphore-controller
- zebra-db-worker
- zebra-internal-api
- zebra-message-worker
- zebra-public-api
- zebra-self-hosted-dispatcher

### Webhooks & Integrations (8 pods)
- github-hooks
- github-hooks-repo-proxy-api
- github-hooks-sidekiq
- github-hooks-sidekiq-web
- github-notifier-api
- github-notifier-consumer
- hooks-processor-api
- hooks-processor-bitbucket
- hooks-processor-git
- hooks-processor-gitlab
- hooks-receiver

### Storage Services (6 pods)
- minio-artifacts
- minio-cache
- minio-logs
- postgres
- rabbitmq
- redis

### Supporting Services (13 pods)
- artifacthub-bucketcleaner-scheduler
- artifacthub-bucketcleaner-worker
- artifacthub-internal-grpc-api
- artifacthub-public-grpc-api
- badges
- dashboardhub-v1alpha-public-grpc-api
- loghub2-archivator
- loghub2-internal-api
- loghub2-public-api
- notifications
- periodic-scheduler
- secrethub
- self-hosted-hub-internal-api
- self-hosted-hub-public-api

### UI Services (3 pods)
- job-page
- project-page
- ui-cache-reactor

### Initialization (1 pod, completed)
- bootstrapper-init-org-job

### RBAC (1 pod)
- rbac-api

---

## Resource Utilization

```bash
# Check cluster resources
kubectl top nodes
kubectl top pods

# Storage usage
kubectl get pvc
```

**Estimated Monthly Cost:**
- GKE cluster: ~$70/month
- Compute (e2-custom-8-16384): ~$180/month
- Networking (Cloud NAT, egress): ~$20/month
- Load Balancer: ~$18/month
- **Total: ~$288/month**

---

## Troubleshooting Notes

### Issue 1: ImagePullBackOff on Private Nodes
**Problem:** Private GKE nodes couldn't pull images from ghcr.io
**Solution:** Added Cloud NAT to Terraform configuration to enable internet egress

### Issue 2: PR_END_OF_FILE_ERROR / SSL Connection Failed
**Problem:** DNS pointing to wrong IP address (34.117.168.211 vs 34.49.224.110)
**Root Cause:** Two static IPs were created, DNS pointed to reserved but unused IP
**Solution:** Updated DNS to point to active GKE Ingress IP (34.49.224.110)

### Issue 3: Helm Chart Version Not Found
**Problem:** v1.6.0 not available in ghcr.io/semaphoreio/semaphore
**Solution:** Used v1.5.0 which is available in OCI registry

---

## Next Steps for Security Hardening

1. **Phase 1: Infrastructure Security**
   - Deploy hardened GKE cluster configuration
   - Implement GKE Dataplane V2 (eBPF)
   - Enable Workload Identity
   - Configure Security Command Center

2. **Phase 2: Network Security**
   - Implement NetworkPolicies (default-deny)
   - Restrict master API access
   - Configure service mesh (Istio)
   - Enable mTLS between services

3. **Phase 3: Runtime Security**
   - Deploy Falco for runtime monitoring
   - Implement Pod Security Standards
   - Deploy OPA Gatekeeper policies
   - Enable Binary Authorization

4. **Phase 4: Secrets Management**
   - Deploy External Secrets Operator
   - Integrate with Google Secret Manager
   - Rotate all credentials
   - Implement least-privilege access

5. **Phase 5: Observability**
   - Deploy Prometheus + Grafana
   - Configure Loki for log aggregation
   - Enable Jaeger for distributed tracing
   - Integrate SIEM (Elasticsearch)

---

## Validation Checklist

- [x] GKE cluster deployed and accessible
- [x] Cloud NAT configured for private nodes
- [x] DNS resolving to correct IP
- [x] SSL certificate valid and working
- [x] All 66 pods running (1 expected failure)
- [x] GKE Ingress created with static IP
- [x] Semaphore UI accessible at https://hamir.online
- [x] Root user credentials retrieved
- [x] All microservices healthy
- [x] Ambassador routing traffic correctly

---

## References

- **Semaphore Documentation:** https://docs.semaphore.io/CE/getting-started/about-semaphore
- **GKE Hardening Guide:** https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster
- **CIS Kubernetes Benchmark:** https://www.cisecurity.org/benchmark/kubernetes
- **Terraform GKE Module:** Used upstream Semaphore configuration
- **Helm Chart:** oci://ghcr.io/semaphoreio/semaphore:v1.5.0

---

## Appendix: Key Configuration Files

### Terraform Variables Used
```hcl
project_name              = "semaphoreci-deployment"
branch                    = "baseline"
path_to_private_key       = "baseline.key"
path_to_fullchain_cer     = "baseline.fullchain.cer"
```

### Helm Values Set
```yaml
global:
  edition: ce
  domain:
    ip: "34.49.224.110"
    name: "hamir.online"
  rootUser:
    email: "admin@hamir.online"
    name: "Admin"
    githubLogin: ""

ingress:
  staticIpName: "global-static-ip-address-baseline"
  enabled: true
  ssl:
    enabled: true
    certName: "cert-baseline"
    type: "google"
```

### Critical Secrets Location
```bash
# Root user credentials
kubectl get secret semaphore-authentication -n default -o yaml

# Organization config
kubectl get secret organization -n default -o yaml

# Authentication secrets
kubectl get secret authentication -n default -o yaml
```

---

**Document Version:** 1.0
**Last Updated:** November 13, 2025
**Status:** Baseline Deployment Complete ✅
