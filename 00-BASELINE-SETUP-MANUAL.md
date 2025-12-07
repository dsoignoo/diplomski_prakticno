# Baseline Semaphore Deployment - Manual Steps

## Prerequisites
- Domain: `hamir.online` (Namecheap)
- GCP Project: `semaphoreci-deployment`
- Tools installed: gcloud, terraform, helm, kubectl

## Step-by-Step Deployment

### 1. Authenticate with GCP

```bash
# Login for gcloud CLI
gcloud auth login

# Login for Terraform (Application Default Credentials)
gcloud auth application-default login

# Set project
gcloud config set project semaphoreci-deployment
```

### 2. Enable Required APIs

```bash
gcloud services enable \
  container.googleapis.com \
  compute.googleapis.com \
  cloudresourcemanager.googleapis.com \
  certificatemanager.googleapis.com \
  --project=semaphoreci-deployment

# Wait 2-3 minutes for APIs to propagate
```

### 3. Reserve Static IP Address

```bash
# Create global static IP
gcloud compute addresses create semaphore-baseline-ip \
  --global \
  --project=semaphoreci-deployment

# Get the IP address
gcloud compute addresses describe semaphore-baseline-ip \
  --global \
  --project=semaphoreci-deployment \
  --format="value(address)"
```

**Note the IP address** (e.g., `34.120.45.67`)

### 4. Configure Wildcard DNS in Namecheap

1. Go to: https://ap.www.namecheap.com/domains/domaincontrolpanel/hamir.online/advancedns
2. Add **TWO A Records**:

**Record 1 - Root domain:**
   - **Type**: A Record
   - **Host**: `@` (or leave blank)
   - **Value**: `<YOUR_STATIC_IP_FROM_STEP_3>`
   - **TTL**: 300 (5 minutes)

**Record 2 - Wildcard:**
   - **Type**: A Record
   - **Host**: `*`
   - **Value**: `<YOUR_STATIC_IP_FROM_STEP_3>`
   - **TTL**: 300 (5 minutes)

Example:
```
Type: A Record
Host: @
Value: 34.120.45.67
TTL: Automatic

Type: A Record
Host: *
Value: 34.120.45.67
TTL: Automatic
```

This will make Semaphore accessible at:
- `https://hamir.online` (main domain)
- `https://semaphore.hamir.online` (subdomain)
- `https://*.hamir.online` (any subdomain)

### 5. Wait for DNS Propagation (5-10 minutes)

Test DNS resolution:
```bash
# Test main domain
dig +short hamir.online @8.8.8.8

# Test wildcard
dig +short semaphore.hamir.online @8.8.8.8
dig +short test.hamir.online @8.8.8.8

# All should return your static IP
```

Or use online tools:
- https://dnschecker.org/#A/hamir.online
- https://dnschecker.org/#A/semaphore.hamir.online

### 6. Option A: Use Self-Signed Wildcard Certificate (Quick Start)

Navigate to terraform directory:
```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke
```

Generate wildcard certificate:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout baseline.key \
  -out baseline.fullchain.cer \
  -subj "/CN=*.hamir.online/O=Semaphore Baseline/C=BA" \
  -addext "subjectAltName=DNS:*.hamir.online,DNS:hamir.online"
```

This creates a wildcard certificate valid for:
- `*.hamir.online` (all subdomains)
- `hamir.online` (root domain)

### 6. Option B: Use Let's Encrypt Wildcard Certificate (Recommended)

Install certbot:
```bash
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
```

Get wildcard certificate (DNS challenge required for wildcards):
```bash
sudo certbot certonly --manual --preferred-challenges dns \
  -d "*.hamir.online" \
  -d "hamir.online" \
  --agree-tos \
  --email amir.hasanbasic.2305@gmail.com
```

**Important:** Certbot will ask you to add a TXT record in Namecheap DNS:

1. **Record Name**: `_acme-challenge`
2. **Record Type**: TXT
3. **Value**: (provided by certbot)
4. **TTL**: 300

Wait 2-3 minutes after adding the TXT record, then press Enter in certbot.

Copy certificates:
```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke

sudo cp /etc/letsencrypt/live/hamir.online/privkey.pem ./baseline.key
sudo cp /etc/letsencrypt/live/hamir.online/fullchain.pem ./baseline.fullchain.cer
sudo chown $USER:$USER ./baseline.key ./baseline.fullchain.cer
chmod 600 ./baseline.key
chmod 644 ./baseline.fullchain.cer
```

### 7. Deploy GKE Cluster with Terraform

```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke

# Initialize Terraform
terraform init

# Plan (review what will be created)
terraform plan \
  -var="project_name=semaphoreci-deployment" \
  -var="branch=baseline" \
  -var="path_to_private_key=baseline.key" \
  -var="path_to_fullchain_cer=baseline.fullchain.cer"

# Apply (create infrastructure)
terraform apply \
  -var="project_name=semaphoreci-deployment" \
  -var="branch=baseline" \
  -var="path_to_private_key=baseline.key" \
  -var="path_to_fullchain_cer=baseline.fullchain.cer"
```

**This takes 10-15 minutes** to create the GKE cluster.

### 8. Configure kubectl

```bash
gcloud container clusters get-credentials test-baseline \
  --region us-east4 \
  --project semaphoreci-deployment

# Verify access
kubectl get nodes
```

### 9. Deploy Emissary Ingress CRDs

```bash
kubectl apply -f https://app.getambassador.io/yaml/emissary/3.9.1/emissary-crds.yaml

kubectl wait --timeout=90s \
  --for=condition=available deployment emissary-apiext \
  -n emissary-system
```

### 10. Create GitHub App Secret (Optional for Baseline)

```bash
kubectl create secret generic github-app \
  --from-literal=GITHUB_APPLICATION_NAME="semaphore-baseline" \
  --from-literal=GITHUB_APPLICATION_ID="000000" \
  --from-literal=GITHUB_APPLICATION_CLIENT_ID="dummy" \
  --from-literal=GITHUB_APPLICATION_CLIENT_SECRET="dummy" \
  --from-literal=GITHUB_APPLICATION_PRIVATE_KEY="dummy" \
  --namespace=default
```

### 11. Build Helm Chart

```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno/semaphore/helm-chart

# Generate Chart.yaml if needed
make helm.create
```

### 12. Deploy Semaphore via Helm

Get Terraform outputs:
```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke

EXTERNAL_IP=$(terraform output -raw external_ip_address)
EXTERNAL_IP_NAME=$(terraform output -raw external_ip_name)
SSL_CERT_NAME=$(terraform output -raw ssl_cert_name)

echo "External IP: $EXTERNAL_IP"
echo "IP Name: $EXTERNAL_IP_NAME"
echo "Cert Name: $SSL_CERT_NAME"
```

Deploy Semaphore:
```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno/semaphore/helm-chart

helm upgrade --install semaphore . \
  --set global.rootUser.githubLogin=admin \
  --set global.domain.name=hamir.online \
  --set global.domain.ip=$EXTERNAL_IP \
  --set ingress.staticIpName=$EXTERNAL_IP_NAME \
  --set ingress.ssl.certName=$SSL_CERT_NAME \
  --set ingress.ssl.type=google \
  --timeout 20m \
  --wait
```

**This takes 15-20 minutes** to deploy all Semaphore components.

### 13. Validate Deployment

Check all pods are running:
```bash
kubectl get pods --all-namespaces

# Expected pods:
# - front
# - guard
# - controller
# - postgres
# - rabbitmq
# - redis
# - minio (artifacts, cache, logs)
# - repository-hub, artifact-hub, project-hub, branch-hub
```

Get credentials:
```bash
kubectl get secret semaphore-authentication -o jsonpath='{.data.ROOT_USER_EMAIL}' | base64 -d
echo ""
kubectl get secret semaphore-authentication -o jsonpath='{.data.ROOT_USER_PASSWORD}' | base64 -d
echo ""
```

### 14. Access Semaphore

Open in browser: **https://hamir.online**

Login with credentials from step 13.

**Note**: Semaphore uses path-based routing on the main domain:
- Main UI: `https://hamir.online`
- API endpoints: `https://hamir.online/api/*`
- Badges: `https://hamir.online/badges/*`

---

## Troubleshooting

### DNS not resolving
```bash
# Check DNS with different servers
dig semaphore.hamir.online @8.8.8.8
dig semaphore.hamir.online @1.1.1.1

# Check Namecheap DNS settings
# Allow 5-10 minutes for propagation
```

### Terraform errors
```bash
# Re-authenticate
gcloud auth application-default login

# Check APIs are enabled
gcloud services list --enabled --project=semaphoreci-deployment | grep -E "compute|container"
```

### Pods not starting
```bash
# Check pod status
kubectl get pods --all-namespaces

# Check specific pod logs
kubectl logs -f <pod-name>

# Check events
kubectl get events --all-namespaces --sort-by='.lastTimestamp'
```

---

## Baseline Security Posture (for documentation)

Record these vulnerabilities for your thesis comparison:

- ❌ Master API: 0.0.0.0/0 (accessible from internet)
- ❌ No NetworkPolicies (pods can communicate freely)
- ❌ No runtime security (Falco)
- ❌ No image scanning
- ❌ Secrets in plaintext
- ❌ Legacy datapath (not eBPF)
- ❌ No security monitoring
- ❌ No audit logging beyond basic GKE

**CIS Kubernetes Benchmark**: ~55% compliance

---

## Next Steps

After baseline deployment, proceed with:

1. **Phase 1**: NetworkPolicies + Falco + GKE Hardening
2. **Phase 2**: CI/CD Security + WAF + OPA Gatekeeper
3. **Phase 3**: Observability + SIEM + Cloud Security

Estimated timeline: 6-8 weeks total
