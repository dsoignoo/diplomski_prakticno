# GKE Autopilot Hardened Cluster za Semaphore

Ovaj direktorij sadrži Terraform konfiguraciju i setup guide za kreiranje production-ready, security-hardened GKE Autopilot klastera za Semaphore CI/CD platformu.

## 🎯 Sigurnosne features

GKE Autopilot cluster uključuje sledeće sigurnosne kontrole:

### ✅ Automatski uključeno (Autopilot defaults):
- **Shielded GKE Nodes** - Secure Boot i Integrity Monitoring
- **Automatic node upgrades** - Patch management
- **Workload Identity** - Cloud IAM integracija bez service account keys
- **VPC-native networking** - IP aliasing za Network Policy
- **Binary Authorization** - Deployment sa potpisanim images
- **Encrypted etcd** - Secrets enkripcija at rest
- **Private nodes** - Nodes bez javnih IP adresa
- **Limited node access** - Automatsko SSH ograničenje

### ✅ Konfigurisano u ovom setup-u:
- **Private GKE cluster** - Private endpoint za API server
- **Network Policy enforcement** - Calico za mrežnu segmentaciju
- **Security Posture Management** - Vulnerability scanning
- **Cloud Armor** - DDoS i WAF zaštita
- **Security Command Center** - Centralni threat detection
- **Audit logging** - Kompletno logovanje API aktivnosti

## 📋 Preduslovi

### 1. Google Cloud Account sa free credits

```bash
# Registracija: https://cloud.google.com/free
# Dobijate $300 free credits na 90 dana
# Nema potrebe za kreditnom karticom za trial account
```

### 2. Instalirani alati

```bash
# Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init

# Terraform
wget https://releases.hashicorp.com/terraform/1.6.4/terraform_1.6.4_linux_amd64.zip
unzip terraform_1.6.4_linux_amd64.zip
sudo mv terraform /usr/local/bin/
terraform --version

# kubectl
gcloud components install kubectl

# Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

### 3. GCP Project setup

```bash
# Kreirati novi project
export PROJECT_ID="semaphore-security-$(date +%s)"
gcloud projects create $PROJECT_ID --name="Semaphore Security Demo"

# Setovati kao default
gcloud config set project $PROJECT_ID

# Enable potrebne API-je
gcloud services enable \
  container.googleapis.com \
  compute.googleapis.com \
  servicenetworking.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com \
  binaryauthorization.googleapis.com \
  securitycenter.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com

# Kreirati Terraform service account
gcloud iam service-accounts create terraform-sa \
  --display-name="Terraform Service Account"

# Dodijeliti permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/container.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/compute.networkAdmin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountAdmin"

# Kreirati key
gcloud iam service-accounts keys create ~/terraform-key.json \
  --iam-account=terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com
```

## 🚀 Deployment koraci

### Korak 1: Konfiguracija Terraform varijabli

```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno/02-infrastructure-security/gke-hardened/terraform

# Kreirati terraform.tfvars
cat > terraform.tfvars <<EOF
project_id     = "$PROJECT_ID"
region         = "us-central1"
cluster_name   = "semaphore-prod"
network_name   = "semaphore-vpc"

# Workload Identity pool
workload_identity_pool = "${PROJECT_ID}.svc.id.goog"

# Binary Authorization
binary_authorization_evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"

# Security features
enable_shielded_nodes           = true
enable_secure_boot              = true
enable_integrity_monitoring     = true
enable_network_policy           = true
enable_private_nodes            = true
enable_private_endpoint         = false  # Keep public for kubectl access
master_ipv4_cidr_block          = "172.16.0.0/28"

# Security posture
security_posture_mode          = "ENTERPRISE"
vulnerability_mode             = "VULNERABILITY_ENTERPRISE"

# Backup
enable_backup                  = true
backup_schedule                = "0 2 * * *"  # Daily at 2 AM
backup_retention_days          = 30

# Monitoring
enable_cloud_logging          = true
enable_cloud_monitoring       = true
EOF
```

### Korak 2: Terraform init i plan

```bash
# Initialize Terraform
export GOOGLE_APPLICATION_CREDENTIALS=~/terraform-key.json
terraform init

# Review plan
terraform plan

# Apply (kreiranje klastera traje ~10-15 minuta)
terraform apply
```

### Korak 3: Konfiguracija kubectl

```bash
# Get credentials
gcloud container clusters get-credentials semaphore-prod \
  --region=us-central1 \
  --project=$PROJECT_ID

# Verify connection
kubectl cluster-info
kubectl get nodes
```

### Korak 4: Setup Workload Identity za Semaphore komponente

```bash
# Skriptu ćemo kreirati u setup-workload-identity.sh
./setup-workload-identity.sh
```

### Korak 5: Setup Binary Authorization policy

```bash
# Kreirati attestor
gcloud beta container binauthz attestors create semaphore-attestor \
  --project=$PROJECT_ID \
  --attestation-authority-note=semaphore-note \
  --attestation-authority-note-project=$PROJECT_ID

# Setup policy
./setup-binary-authorization.sh
```

### Korak 6: Enable Security Command Center

```bash
# Automatic za Enterprise tier (besplatno 30 dana)
gcloud scc sources list --organization=YOUR_ORG_ID

# Container Threat Detection automatski aktivan
# Event Threat Detection automatski aktivan
# Security Health Analytics automatski aktivan
```

## 💰 Cost Estimate

### GKE Autopilot pricing:

```
GKE Autopilot: Pay-per-pod pricing
- Control Plane: BESPLATNO (za Autopilot)
- Podovi: ~$0.04-0.06 po vCPU-sat
- Memory: ~$0.004-0.006 po GB-sat

Za Semaphore (procjena):
- ~15 podova sa 0.5-1 vCPU svaki
- ~30 GB RAM ukupno
- Mjesečno: ~$50-100

SA $300 FREE CREDITS: 3-6 mjeseci BESPLATNO!
```

## 🔐 Sigurnosne validacije

Nakon deployment-a, izvršiti sledeće validacije:

```bash
# 1. Provjera da su nodes shielded
gcloud compute instances list \
  --filter="name~'gke-semaphore'" \
  --format="table(name,shieldedInstanceConfig.enableSecureBoot)"

# 2. Provjera Network Policy support
kubectl get pods -n kube-system | grep calico

# 3. Provjera Workload Identity
kubectl describe sa default -n semaphore | grep "Annotations"

# 4. Provjera Binary Authorization
gcloud container binauthz policy export

# 5. Provjera audit logging
gcloud logging read "resource.type=k8s_cluster" --limit=10
```

## 📊 Sljedeći koraci

Nakon uspješnog deployment-a GKE klastera:

1. **Deploy Semaphore**: Idite na `00-semaphore-baseline/`
2. **NetworkPolicies**: Idite na `08-network-policies/`
3. **Falco**: Idite na `06-runtime-security/`
4. **Backup**: Idite na `11-backup-disaster-recovery/`

## 🧹 Cleanup (kada završite testiranje)

```bash
# Terraform destroy za brisanje svih resursa
cd terraform/
terraform destroy

# Ili manualno kroz gcloud
gcloud container clusters delete semaphore-prod --region=us-central1

# Delete project (briše SVE)
gcloud projects delete $PROJECT_ID
```

## 📚 Reference

- [GKE Autopilot Overview](https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview)
- [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [Binary Authorization](https://cloud.google.com/binary-authorization/docs)
- [Security Command Center](https://cloud.google.com/security-command-center/docs)
