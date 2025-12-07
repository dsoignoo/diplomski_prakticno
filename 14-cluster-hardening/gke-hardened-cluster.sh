#!/bin/bash
# GKE Hardened Cluster Creation Script
# Kreira production-ready GKE cluster sa svim sigurnosnim kontrolama

set -e

# Konfiguracija
PROJECT_ID="${PROJECT_ID:-semaphore-prod}"
CLUSTER_NAME="${CLUSTER_NAME:-semaphore-hardened}"
REGION="${REGION:-europe-west1}"
NETWORK="${NETWORK:-semaphore-vpc}"
SUBNET="${SUBNET:-semaphore-subnet}"

echo "=== Kreiranje GKE Hardened Cluster ==="
echo "Project: $PROJECT_ID"
echo "Cluster: $CLUSTER_NAME"
echo "Region: $REGION"

# Kreiranje KMS ključa za encryption at rest
echo "Kreiranje KMS ključa..."
gcloud kms keyrings create gke-keyring \
    --location=$REGION \
    --project=$PROJECT_ID || true

gcloud kms keys create gke-etcd-key \
    --keyring=gke-keyring \
    --location=$REGION \
    --purpose=encryption \
    --project=$PROJECT_ID || true

KMS_KEY="projects/$PROJECT_ID/locations/$REGION/keyRings/gke-keyring/cryptoKeys/gke-etcd-key"

# Kreiranje hardened GKE klastera
echo "Kreiranje GKE klastera..."
gcloud container clusters create $CLUSTER_NAME \
    --project=$PROJECT_ID \
    --location=$REGION \
    --network=$NETWORK \
    --subnetwork=$SUBNET \
    \
    # Private Cluster
    --enable-private-nodes \
    --enable-private-endpoint \
    --master-ipv4-cidr="172.16.0.0/28" \
    --enable-master-authorized-networks \
    --master-authorized-networks="10.0.0.0/8" \
    \
    # Workload Identity
    --workload-pool="$PROJECT_ID.svc.id.goog" \
    \
    # Shielded Nodes
    --enable-shielded-nodes \
    --shielded-secure-boot \
    --shielded-integrity-monitoring \
    \
    # Binary Authorization
    --enable-binauthz \
    --binauthz-evaluation-mode="PROJECT_SINGLETON_POLICY_ENFORCE" \
    \
    # Network Policy
    --enable-network-policy \
    \
    # Security Posture
    --security-posture=standard \
    --workload-vulnerability-scanning=standard \
    \
    # Encryption at rest
    --database-encryption-key=$KMS_KEY \
    \
    # Release Channel
    --release-channel=regular \
    \
    # Logging and Monitoring
    --enable-stackdriver-kubernetes \
    --logging=SYSTEM,WORKLOAD \
    --monitoring=SYSTEM \
    \
    # Node Configuration
    --num-nodes=3 \
    --machine-type=e2-standard-4 \
    --image-type=COS_CONTAINERD \
    --disk-type=pd-ssd \
    --disk-size=100 \
    --enable-autorepair \
    --enable-autoupgrade \
    --max-surge-upgrade=1 \
    --max-unavailable-upgrade=0 \
    \
    # Metadata concealment
    --metadata=disable-legacy-endpoints=true \
    \
    # Labels
    --labels=environment=production,team=platform

echo "Cluster kreiran uspješno!"

# Konfiguracija Binary Authorization policy
echo "Konfiguriranje Binary Authorization..."
cat > /tmp/binauthz-policy.yaml << 'EOF'
defaultAdmissionRule:
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
  evaluationMode: REQUIRE_ATTESTATION
  requireAttestationsBy:
    - projects/semaphore-prod/attestors/build-attestor
admissionWhitelistPatterns:
  - namePattern: gcr.io/google_containers/*
  - namePattern: k8s.gcr.io/*
  - namePattern: gke.gcr.io/*
EOF

gcloud container binauthz policy import /tmp/binauthz-policy.yaml \
    --project=$PROJECT_ID

# Kreiranje Workload Identity binding za semaphore namespace
echo "Konfiguriranje Workload Identity..."
gcloud iam service-accounts create semaphore-workload \
    --project=$PROJECT_ID \
    --display-name="Semaphore Workload Identity SA" || true

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:semaphore-workload@$PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

gcloud iam service-accounts add-iam-policy-binding \
    semaphore-workload@$PROJECT_ID.iam.gserviceaccount.com \
    --role="roles/iam.workloadIdentityUser" \
    --member="serviceAccount:$PROJECT_ID.svc.id.goog[semaphore/default]" \
    --project=$PROJECT_ID

echo ""
echo "=== GKE Hardened Cluster Setup Complete ==="
echo ""
echo "Sljedeći koraci:"
echo "1. gcloud container clusters get-credentials $CLUSTER_NAME --region $REGION"
echo "2. kubectl create namespace semaphore"
echo "3. kubectl annotate serviceaccount default -n semaphore iam.gke.io/gcp-service-account=semaphore-workload@$PROJECT_ID.iam.gserviceaccount.com"
