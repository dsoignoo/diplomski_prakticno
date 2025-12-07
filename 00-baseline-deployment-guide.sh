#!/bin/bash
# Baseline Semaphore Deployment Script
# This script deploys the INSECURE baseline Semaphore for comparison purposes

set -e

PROJECT_ID="semaphoreci-deployment"
DOMAIN="hamir.online"
REGION="us-east4"
CLUSTER_NAME="test-baseline"

echo "=========================================="
echo "Semaphore Baseline Deployment"
echo "=========================================="
echo "Project: $PROJECT_ID"
echo "Domain: $DOMAIN (with wildcard *.${DOMAIN})"
echo "Region: $REGION"
echo "=========================================="

# Step 1: Authenticate
echo ""
echo "Step 1: Authenticating with GCP..."
gcloud auth application-default login

# Step 2: Set project
echo ""
echo "Step 2: Setting GCP project..."
gcloud config set project $PROJECT_ID

# Step 3: Enable required APIs
echo ""
echo "Step 3: Enabling required GCP APIs (this takes 2-3 minutes)..."
gcloud services enable \
  container.googleapis.com \
  compute.googleapis.com \
  cloudresourcemanager.googleapis.com \
  certificatemanager.googleapis.com \
  --project=$PROJECT_ID

echo "Waiting 60 seconds for APIs to propagate..."
sleep 60

# Step 4: Reserve static IP
echo ""
echo "Step 4: Reserving global static IP address..."
if gcloud compute addresses describe semaphore-baseline-ip --global --project=$PROJECT_ID &>/dev/null; then
  echo "Static IP already exists, retrieving..."
else
  gcloud compute addresses create semaphore-baseline-ip --global --project=$PROJECT_ID
fi

STATIC_IP=$(gcloud compute addresses describe semaphore-baseline-ip --global --project=$PROJECT_ID --format="value(address)")
echo "Static IP: $STATIC_IP"

# Step 5: DNS Configuration Instructions
echo ""
echo "=========================================="
echo "⚠️  ACTION REQUIRED: Configure DNS"
echo "=========================================="
echo ""
echo "Go to Namecheap DNS settings for hamir.online and add TWO A Records:"
echo ""
echo "Record 1 - Root domain:"
echo "  Type: A Record"
echo "  Host: @"
echo "  Value: $STATIC_IP"
echo "  TTL: 300"
echo ""
echo "Record 2 - Wildcard:"
echo "  Type: A Record"
echo "  Host: *"
echo "  Value: $STATIC_IP"
echo "  TTL: 300"
echo ""
echo "This allows access via:"
echo "  - https://hamir.online"
echo "  - https://*.hamir.online"
echo ""
echo "Press ENTER when DNS is configured..."
read -r

# Step 6: Wait for DNS propagation
echo ""
echo "Step 6: Checking DNS propagation..."
echo "Testing DNS resolution for $DOMAIN and wildcard..."

RETRY=0
MAX_RETRIES=30
while [ $RETRY -lt $MAX_RETRIES ]; do
  RESOLVED_IP=$(dig +short $DOMAIN @8.8.8.8 | tail -1)
  RESOLVED_WILDCARD=$(dig +short test.$DOMAIN @8.8.8.8 | tail -1)

  if [ "$RESOLVED_IP" == "$STATIC_IP" ] && [ "$RESOLVED_WILDCARD" == "$STATIC_IP" ]; then
    echo "✅ DNS resolved correctly:"
    echo "   $DOMAIN -> $STATIC_IP"
    echo "   *.$DOMAIN -> $STATIC_IP"
    break
  else
    echo "Waiting for DNS propagation... (attempt $((RETRY+1))/$MAX_RETRIES)"
    echo "  $DOMAIN: $RESOLVED_IP (expected: $STATIC_IP)"
    echo "  *.$DOMAIN: $RESOLVED_WILDCARD (expected: $STATIC_IP)"
    sleep 10
    RETRY=$((RETRY+1))
  fi
done

if [ $RETRY -eq $MAX_RETRIES ]; then
  echo "⚠️  DNS not fully propagated yet, but continuing..."
fi

# Step 7: Generate TLS certificates with Let's Encrypt (using certbot)
echo ""
echo "Step 7: Generating wildcard TLS certificates..."
cd /home/osboxes/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke

if command -v certbot &> /dev/null; then
  echo "Using certbot for Let's Encrypt wildcard certificates..."
  echo "⚠️  You will need to add a TXT record to DNS when prompted"
  sudo certbot certonly --manual --preferred-challenges dns \
    -d "$DOMAIN" \
    -d "*.$DOMAIN" \
    --agree-tos \
    --email amir.hasanbasic.2305@gmail.com \
    --no-eff-email

  # Copy certificates
  sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem ./baseline.key
  sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem ./baseline.fullchain.cer
  sudo chown $USER:$USER ./baseline.key ./baseline.fullchain.cer
  chmod 600 ./baseline.key
  chmod 644 ./baseline.fullchain.cer
else
  echo "Certbot not installed, using self-signed wildcard certificate..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout baseline.key \
    -out baseline.fullchain.cer \
    -subj "/CN=*.$DOMAIN/O=Semaphore Baseline/C=BA" \
    -addext "subjectAltName=DNS:*.$DOMAIN,DNS:$DOMAIN"
fi

# Step 8: Deploy GKE cluster with Terraform
echo ""
echo "Step 8: Deploying GKE cluster with Terraform..."
terraform init

terraform apply \
  -var="project_name=$PROJECT_ID" \
  -var="branch=baseline" \
  -var="path_to_private_key=baseline.key" \
  -var="path_to_fullchain_cer=baseline.fullchain.cer" \
  -auto-approve

# Step 9: Configure kubectl
echo ""
echo "Step 9: Configuring kubectl access..."
gcloud container clusters get-credentials $CLUSTER_NAME --region $REGION --project $PROJECT_ID

# Step 10: Deploy Emissary Ingress CRDs
echo ""
echo "Step 10: Deploying Emissary Ingress CRDs..."
kubectl apply -f https://app.getambassador.io/yaml/emissary/3.9.1/emissary-crds.yaml
kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n emissary-system

# Step 11: Create namespace
echo ""
echo "Step 11: Creating semaphore namespace..."
kubectl create namespace semaphore --dry-run=client -o yaml | kubectl apply -f -

# Step 12: Create GitHub App secret (dummy for baseline)
echo ""
echo "Step 12: Creating GitHub App secret..."
kubectl create secret generic github-app \
  --from-literal=GITHUB_APPLICATION_NAME="semaphore-baseline" \
  --from-literal=GITHUB_APPLICATION_ID="000000" \
  --from-literal=GITHUB_APPLICATION_CLIENT_ID="dummy-client-id" \
  --from-literal=GITHUB_APPLICATION_CLIENT_SECRET="dummy-client-secret" \
  --from-literal=GITHUB_APPLICATION_PRIVATE_KEY="dummy-private-key" \
  --namespace=default \
  --dry-run=client -o yaml | kubectl apply -f -

# Step 13: Get Terraform outputs
echo ""
echo "Step 13: Getting infrastructure details..."
EXTERNAL_IP=$(terraform output -raw external_ip_address)
EXTERNAL_IP_NAME=$(terraform output -raw external_ip_name)
SSL_CERT_NAME=$(terraform output -raw ssl_cert_name)

# Step 14: Deploy Semaphore Helm chart
echo ""
echo "Step 14: Deploying Semaphore via Helm..."
cd ../../../helm-chart

# Build helm chart if needed
if [ ! -f "Chart.yaml" ]; then
  make helm.create
fi

helm upgrade --install semaphore . \
  --set global.rootUser.githubLogin=admin \
  --set global.domain.name=$DOMAIN \
  --set global.domain.ip=$EXTERNAL_IP \
  --set ingress.staticIpName=$EXTERNAL_IP_NAME \
  --set ingress.ssl.certName=$SSL_CERT_NAME \
  --set ingress.ssl.type=google \
  --timeout 20m \
  --wait

# Step 15: Validate deployment
echo ""
echo "Step 15: Validating deployment..."
kubectl get pods --all-namespaces

echo ""
echo "=========================================="
echo "✅ Baseline Deployment Complete!"
echo "=========================================="
echo ""
echo "Access Semaphore at: https://$DOMAIN"
echo ""
echo "Get credentials with:"
echo "  kubectl get secret semaphore-authentication -o jsonpath='{.data.ROOT_USER_EMAIL}' | base64 -d"
echo "  kubectl get secret semaphore-authentication -o jsonpath='{.data.ROOT_USER_PASSWORD}' | base64 -d"
echo ""
echo "⚠️  This is the INSECURE BASELINE deployment"
echo "Known vulnerabilities (to be fixed in Phase 1-3):"
echo "  - Master API accessible from 0.0.0.0/0"
echo "  - No NetworkPolicies (lateral movement possible)"
echo "  - No runtime security (Falco)"
echo "  - Legacy datapath (not eBPF)"
echo "  - Secrets in plaintext"
echo ""
echo "Next: Implement Phase 1 security controls"
echo "=========================================="
