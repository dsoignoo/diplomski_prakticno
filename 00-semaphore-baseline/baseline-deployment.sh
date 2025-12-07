#!/bin/bash
#
# Semaphore CI/CD Baseline Deployment Script
# Date: November 13, 2025
# Purpose: Deploy intentionally insecure baseline Semaphore for security research
#

set -e

# Configuration
PROJECT_ID="semaphoreci-deployment"
REGION="us-east4"
DOMAIN="hamir.online"
BRANCH="baseline"

echo "=========================================="
echo "Semaphore Baseline Deployment"
echo "=========================================="
echo ""

# Step 1: Verify prerequisites
echo "Step 1: Verifying prerequisites..."
command -v gcloud >/dev/null 2>&1 || { echo "gcloud not found. Install Google Cloud SDK."; exit 1; }
command -v terraform >/dev/null 2>&1 || { echo "terraform not found. Install Terraform."; exit 1; }
command -v helm >/dev/null 2>&1 || { echo "helm not found. Install Helm."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found. Install kubectl."; exit 1; }
echo "✓ All prerequisites installed"
echo ""

# Step 2: Configure GCP project
echo "Step 2: Configuring GCP project..."
gcloud config set project $PROJECT_ID
echo "✓ Project configured: $PROJECT_ID"
echo ""

# Step 3: Enable required APIs
echo "Step 3: Enabling required GCP APIs..."
gcloud services enable container.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable cloudresourcemanager.googleapis.com
echo "✓ APIs enabled"
echo ""

# Step 4: DNS Configuration
echo "Step 4: DNS Configuration"
echo "Configure the following DNS records on Namecheap for $DOMAIN:"
echo "  Record 1: Type=A, Host=@, Value=<STATIC_IP>"
echo "  Record 2: Type=A, Host=*, Value=<STATIC_IP>"
echo ""
read -p "Press Enter after configuring DNS..."

# Step 5: SSL Certificate
echo "Step 5: Generating SSL Certificate..."
if [ ! -f "baseline.key" ] || [ ! -f "baseline.fullchain.cer" ]; then
    echo "SSL certificates not found. Please run:"
    echo "  sudo certbot certonly --manual --preferred-challenges dns \\"
    echo "    -d \"$DOMAIN\" -d \"*.$DOMAIN\""
    echo ""
    echo "Then copy:"
    echo "  sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem baseline.key"
    echo "  sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem baseline.fullchain.cer"
    echo "  sudo chown \$USER:\$USER baseline.*"
    exit 1
else
    echo "✓ SSL certificates found"
fi
echo ""

# Step 6: Deploy infrastructure with Terraform
echo "Step 6: Deploying GKE infrastructure with Terraform..."
cd ~/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke

terraform init

terraform apply \
  -var="project_name=$PROJECT_ID" \
  -var="branch=$BRANCH" \
  -var="path_to_private_key=baseline.key" \
  -var="path_to_fullchain_cer=baseline.fullchain.cer" \
  -auto-approve

echo "✓ Infrastructure deployed"
echo ""

# Step 7: Get static IP
STATIC_IP=$(terraform output -raw external_ip_address)
echo "Static IP: $STATIC_IP"
echo ""
echo "UPDATE YOUR DNS NOW to point to $STATIC_IP"
read -p "Press Enter after updating DNS..."

# Step 8: Configure kubectl
echo "Step 8: Configuring kubectl..."
gcloud container clusters get-credentials test-$BRANCH --region $REGION
echo "✓ kubectl configured"
echo ""

# Step 9: Deploy Emissary Ingress CRDs
echo "Step 9: Deploying Emissary Ingress CRDs..."
kubectl apply -f https://app.getambassador.io/yaml/emissary/3.9.1/emissary-crds.yaml
kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n emissary-system
echo "✓ Emissary CRDs deployed"
echo ""

# Step 10: Deploy Semaphore via Helm
echo "Step 10: Deploying Semaphore (this takes ~20 minutes)..."
helm upgrade --install semaphore "oci://ghcr.io/semaphoreio/semaphore" \
  --version v1.5.0 \
  --timeout 40m \
  --set global.edition=ce \
  --set global.domain.ip="$STATIC_IP" \
  --set global.domain.name="$DOMAIN" \
  --set global.rootUser.email="admin@$DOMAIN" \
  --set global.rootUser.name="Admin" \
  --set global.rootUser.githubLogin="" \
  --set ingress.staticIpName="global-static-ip-address-baseline" \
  --set ingress.enabled=true \
  --set ingress.ssl.enabled=true \
  --set ingress.ssl.certName="cert-baseline" \
  --set ingress.ssl.type="google" \
  --wait

echo "✓ Semaphore deployed"
echo ""

# Step 11: Retrieve credentials
echo "Step 11: Retrieving credentials..."
ROOT_EMAIL=$(kubectl get secret semaphore-authentication -n default -o jsonpath='{.data.ROOT_USER_EMAIL}' | base64 -d)
ROOT_PASSWORD=$(kubectl get secret semaphore-authentication -n default -o jsonpath='{.data.ROOT_USER_PASSWORD}' | base64 -d)
API_TOKEN=$(kubectl get secret semaphore-authentication -n default -o jsonpath='{.data.ROOT_USER_TOKEN}' | base64 -d)

echo ""
echo "=========================================="
echo "DEPLOYMENT COMPLETE!"
echo "=========================================="
echo ""
echo "Access URL: https://$DOMAIN"
echo "Email: $ROOT_EMAIL"
echo "Password: $ROOT_PASSWORD"
echo "API Token: $API_TOKEN"
echo ""
echo "Save these credentials securely!"
echo ""

# Step 12: Validation
echo "Validating deployment..."
kubectl get pods -A | grep -v "kube-system\|gke-"
echo ""
kubectl get ingress
echo ""
echo "Testing HTTPS access..."
curl -I https://$DOMAIN
echo ""
echo "✓ Deployment validated"
echo ""
echo "=========================================="
echo "Baseline deployment complete!"
echo "This is an INTENTIONALLY INSECURE baseline"
echo "for security research purposes."
echo "=========================================="
