#!/bin/bash
# Enable Google Cloud Operations for Semaphore Platform
# This script integrates Falco with Cloud Pub/Sub and demonstrates Cloud Logging/Monitoring access

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_ID=$(gcloud config get-value project)
CLUSTER_NAME="semaphore-hardened"
REGION="us-central1"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Google Cloud Operations Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Project: $PROJECT_ID"
echo "Cluster: $CLUSTER_NAME"
echo "Region: $REGION"
echo ""

# Step 1: Verify Cloud Operations APIs are enabled
echo -e "${GREEN}Step 1: Verifying Cloud Operations APIs...${NC}"
gcloud services enable monitoring.googleapis.com \
  logging.googleapis.com \
  cloudtrace.googleapis.com \
  pubsub.googleapis.com \
  --project=$PROJECT_ID

echo -e "${GREEN}✓ APIs enabled${NC}"
echo ""

# Step 2: Create Pub/Sub topic for Falco alerts
echo -e "${GREEN}Step 2: Creating Pub/Sub topic for Falco alerts...${NC}"

if gcloud pubsub topics describe falco-alerts --project=$PROJECT_ID &>/dev/null; then
  echo -e "${YELLOW}Topic 'falco-alerts' already exists${NC}"
else
  gcloud pubsub topics create falco-alerts --project=$PROJECT_ID
  echo -e "${GREEN}✓ Topic 'falco-alerts' created${NC}"
fi

# Create subscription for testing
if gcloud pubsub subscriptions describe falco-alerts-sub --project=$PROJECT_ID &>/dev/null; then
  echo -e "${YELLOW}Subscription 'falco-alerts-sub' already exists${NC}"
else
  gcloud pubsub subscriptions create falco-alerts-sub \
    --topic=falco-alerts \
    --project=$PROJECT_ID
  echo -e "${GREEN}✓ Subscription 'falco-alerts-sub' created${NC}"
fi
echo ""

# Step 3: Create service account for Falcosidekick
echo -e "${GREEN}Step 3: Setting up IAM for Falcosidekick...${NC}"

SA_NAME="falcosidekick-pubsub"
SA_EMAIL="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

if gcloud iam service-accounts describe $SA_EMAIL --project=$PROJECT_ID &>/dev/null; then
  echo -e "${YELLOW}Service account $SA_EMAIL already exists${NC}"
else
  gcloud iam service-accounts create $SA_NAME \
    --display-name="Falcosidekick Pub/Sub Publisher" \
    --project=$PROJECT_ID
  echo -e "${GREEN}✓ Service account created${NC}"
fi

# Grant Pub/Sub publisher role
gcloud pubsub topics add-iam-policy-binding falco-alerts \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/pubsub.publisher" \
  --project=$PROJECT_ID &>/dev/null

echo -e "${GREEN}✓ IAM roles granted${NC}"
echo ""

# Step 4: Create Workload Identity binding
echo -e "${GREEN}Step 4: Setting up Workload Identity...${NC}"

# Allow Kubernetes service account to impersonate GCP service account
gcloud iam service-accounts add-iam-policy-binding $SA_EMAIL \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:$PROJECT_ID.svc.id.goog[falco/falco-falcosidekick]" \
  --project=$PROJECT_ID

echo -e "${GREEN}✓ Workload Identity configured${NC}"
echo ""

# Step 5: Update Falcosidekick configuration
echo -e "${GREEN}Step 5: Updating Falco deployment...${NC}"

cat > /tmp/falco-cloud-values.yaml <<EOF
# Falco with Cloud Pub/Sub Integration
driver:
  kind: modern_ebpf

tty: true
json_output: true
json_include_output_property: true

falcosidekick:
  enabled: true
  webui:
    enabled: true

  # Add Workload Identity annotation to service account
  serviceAccount:
    annotations:
      iam.gke.io/gcp-service-account: $SA_EMAIL

  config:
    debug: false

    # Send to Loki (existing)
    loki:
      hostport: http://loki-gateway.monitoring.svc.cluster.local
      tenant: falco
      endpoint: /loki/api/v1/push

    # Send to Cloud Pub/Sub (new!)
    gcp:
      pubsub:
        projectid: "$PROJECT_ID"
        topic: "falco-alerts"

# Custom Semaphore rules
customRules:
  semaphore-rules.yaml: |-
    - macro: semaphore_container
      condition: (container.image.repository contains "semaphoreio" or k8s.ns.name = "default")

    - rule: Shell Spawned in Semaphore Container
      desc: Detect shell execution in Semaphore microservices
      condition: >
        spawned_process and container and semaphore_container and
        proc.name in (sh, bash, zsh, dash, ksh)
      output: >
        Shell spawned in Semaphore container
        (user=%user.name container=%container.name image=%container.image.repository
         ns=%k8s.ns.name pod=%k8s.pod.name command=%proc.cmdline)
      priority: WARNING
      tags: [semaphore, shell, runtime, T1059]

    - rule: Semaphore Privilege Escalation Attempt
      desc: Detect privilege escalation in Semaphore containers
      condition: >
        spawned_process and container and semaphore_container and
        proc.name in (sudo, su)
      output: >
        Privilege escalation attempt in Semaphore
        (user=%user.name process=%proc.name container=%container.name
         image=%container.image.repository pod=%k8s.pod.name command=%proc.cmdline)
      priority: CRITICAL
      tags: [semaphore, privilege_escalation, T1068]

    - rule: Unexpected File Write in Semaphore
      desc: Detect suspicious file writes indicating persistence
      condition: >
        open_write and container and semaphore_container and
        (fd.name startswith /etc/ or fd.name startswith /root/.ssh/)
      output: >
        Unexpected file write in Semaphore container
        (user=%user.name file=%fd.name container=%container.name pod=%k8s.pod.name)
      priority: WARNING
      tags: [semaphore, persistence, T1543]
EOF

# Apply the update
export KUBECONFIG=/home/osboxes/.kube/configs/gke-config
helm upgrade falco falcosecurity/falco \
  --namespace falco \
  -f /tmp/falco-cloud-values.yaml \
  --reuse-values

echo -e "${GREEN}✓ Falco updated with Cloud Pub/Sub integration${NC}"
echo ""

# Step 6: Wait for pods to restart
echo -e "${GREEN}Step 6: Waiting for Falcosidekick pods to restart...${NC}"
kubectl rollout status deployment/falco-falcosidekick -n falco --timeout=120s

echo -e "${GREEN}✓ Falcosidekick ready${NC}"
echo ""

# Step 7: Test the integration
echo -e "${GREEN}Step 7: Testing Cloud Pub/Sub integration...${NC}"
echo "Waiting 30 seconds for Falco to generate some alerts..."
sleep 30

# Check if messages are in Pub/Sub
MESSAGE_COUNT=$(gcloud pubsub subscriptions pull falco-alerts-sub \
  --limit=5 \
  --format="value(message.data)" \
  --project=$PROJECT_ID 2>/dev/null | wc -l)

if [ $MESSAGE_COUNT -gt 0 ]; then
  echo -e "${GREEN}✓ Successfully receiving Falco alerts in Pub/Sub!${NC}"
  echo "  Received $MESSAGE_COUNT messages"
else
  echo -e "${YELLOW}⚠ No messages yet (this is normal if no security events occurred)${NC}"
  echo "  You can trigger a test alert by running:"
  echo "  kubectl exec -it deployment/front -n default -- /bin/sh"
fi
echo ""

# Step 8: Show Cloud Console URLs
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Cloud Operations Access${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}Cloud Logging:${NC}"
echo "https://console.cloud.google.com/logs/query;query=resource.type%3D%22k8s_container%22%0Aresource.labels.namespace_name%3D%22default%22;project=$PROJECT_ID"
echo ""
echo -e "${GREEN}Cloud Monitoring:${NC}"
echo "https://console.cloud.google.com/monitoring/dashboards;project=$PROJECT_ID"
echo ""
echo -e "${GREEN}Falco Alerts (Pub/Sub):${NC}"
echo "https://console.cloud.google.com/cloudpubsub/topic/detail/falco-alerts;project=$PROJECT_ID"
echo ""
echo -e "${GREEN}GKE Cluster Metrics:${NC}"
echo "https://console.cloud.google.com/kubernetes/clusters/details/$REGION/$CLUSTER_NAME/observability/metrics;project=$PROJECT_ID"
echo ""

# Step 9: Query examples
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Query Examples${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

echo -e "${GREEN}View Falco alerts in Cloud Logging:${NC}"
echo "gcloud logging read 'resource.type=\"k8s_container\" resource.labels.namespace_name=\"falco\" jsonPayload.rule=~\"Shell Spawned\"' --limit=10 --project=$PROJECT_ID"
echo ""

echo -e "${GREEN}View all Semaphore container logs:${NC}"
echo "gcloud logging read 'resource.type=\"k8s_container\" resource.labels.namespace_name=\"default\"' --limit=10 --project=$PROJECT_ID"
echo ""

echo -e "${GREEN}Pull Falco alerts from Pub/Sub:${NC}"
echo "gcloud pubsub subscriptions pull falco-alerts-sub --auto-ack --limit=10 --project=$PROJECT_ID"
echo ""

echo -e "${GREEN}List metrics for GKE cluster:${NC}"
echo "gcloud monitoring time-series list --filter='resource.type=\"k8s_container\"' --project=$PROJECT_ID"
echo ""

# Cleanup temp file
rm -f /tmp/falco-cloud-values.yaml

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Cloud Operations Setup Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Next steps:"
echo "1. Open Cloud Console to view logs and metrics"
echo "2. Create custom dashboards in Cloud Monitoring"
echo "3. Set up alerting policies for critical metrics"
echo "4. (Optional) Export logs to BigQuery for long-term analysis"
echo ""
