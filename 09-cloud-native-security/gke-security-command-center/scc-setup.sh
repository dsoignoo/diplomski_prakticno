#!/bin/bash
# Setup script za GKE Security Command Center

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_ID=${1:-"YOUR_PROJECT_ID"}
ORG_ID=${2:-"YOUR_ORG_ID"}
CLUSTER_NAME="semaphore-autopilot"
CLUSTER_REGION="us-central1"

echo -e "${GREEN}=== GKE Security Command Center Setup ===${NC}"
echo "Project ID: $PROJECT_ID"
echo "Organization ID: $ORG_ID"
echo "Cluster: $CLUSTER_NAME"
echo ""

# 1. Enable APIs
echo -e "${YELLOW}Step 1: Enabling required APIs...${NC}"
gcloud services enable securitycenter.googleapis.com \
  --project=$PROJECT_ID

gcloud services enable containerscanning.googleapis.com \
  --project=$PROJECT_ID

gcloud services enable containeranalysis.googleapis.com \
  --project=$PROJECT_ID

gcloud services enable binaryauthorization.googleapis.com \
  --project=$PROJECT_ID

echo -e "${GREEN}✓ APIs enabled${NC}"
echo ""

# 2. Enable Security Posture Management
echo -e "${YELLOW}Step 2: Enabling GKE Security Posture...${NC}"
gcloud container clusters update $CLUSTER_NAME \
  --region=$CLUSTER_REGION \
  --enable-security-posture \
  --enable-workload-vulnerability-scanning \
  --workload-vulnerability-scanning=enterprise \
  --project=$PROJECT_ID

echo -e "${GREEN}✓ Security Posture enabled${NC}"
echo ""

# 3. Enable Security Health Analytics
echo -e "${YELLOW}Step 3: Enabling Security Health Analytics...${NC}"
gcloud scc settings services modules enable \
  --project=$PROJECT_ID \
  --service=security-health-analytics \
  --module=CONTAINER_SCANNING

gcloud scc settings services modules enable \
  --project=$PROJECT_ID \
  --service=security-health-analytics \
  --module=WEB_SECURITY_SCANNER

echo -e "${GREEN}✓ Security Health Analytics enabled${NC}"
echo ""

# 4. Setup notification channels za Security Command Center
echo -e "${YELLOW}Step 4: Creating notification channels...${NC}"

# Pub/Sub topic za findings
gcloud pubsub topics create scc-findings \
  --project=$PROJECT_ID 2>/dev/null || echo "Topic already exists"

gcloud pubsub subscriptions create scc-findings-sub \
  --topic=scc-findings \
  --project=$PROJECT_ID 2>/dev/null || echo "Subscription already exists"

# Create notification config
gcloud scc notifications create scc-pubsub-notification \
  --organization=$ORG_ID \
  --description="Security Command Center findings to Pub/Sub" \
  --pubsub-topic=projects/$PROJECT_ID/topics/scc-findings \
  --filter="severity=\"CRITICAL\" OR severity=\"HIGH\""

echo -e "${GREEN}✓ Notification channels created${NC}"
echo ""

# 5. Export findings to Cloud Logging (za shipping u Elasticsearch)
echo -e "${YELLOW}Step 5: Setting up log exports...${NC}"

# Log sink za SCC findings
gcloud logging sinks create scc-findings-sink \
  pubsub.googleapis.com/projects/$PROJECT_ID/topics/scc-findings \
  --log-filter='resource.type="cloud_security_command_center_finding"' \
  --project=$PROJECT_ID 2>/dev/null || echo "Sink already exists"

echo -e "${GREEN}✓ Log exports configured${NC}"
echo ""

# 6. Setup IAM permissions za Security Command Center
echo -e "${YELLOW}Step 6: Configuring IAM permissions...${NC}"

# Service account za SCC findings processor
gcloud iam service-accounts create scc-processor \
  --display-name="Security Command Center Findings Processor" \
  --project=$PROJECT_ID 2>/dev/null || echo "SA already exists"

# Grant permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:scc-processor@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/securitycenter.findingsViewer"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:scc-processor@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/pubsub.subscriber"

echo -e "${GREEN}✓ IAM permissions configured${NC}"
echo ""

# 7. Create sample queries
echo -e "${YELLOW}Step 7: Creating sample SCC queries...${NC}"

cat > /tmp/scc-queries.txt <<EOF
# Sample Security Command Center Queries

# 1. List all CRITICAL findings
gcloud scc findings list \\
  --organization=$ORG_ID \\
  --filter="severity=\"CRITICAL\"" \\
  --format=json

# 2. Container vulnerabilities
gcloud scc findings list \\
  --organization=$ORG_ID \\
  --filter="category=\"CONTAINER_VULNERABILITY\" AND severity=\"HIGH\"" \\
  --format=json

# 3. GKE misconfigurations
gcloud scc findings list \\
  --organization=$ORG_ID \\
  --filter="category=\"GKE_MISCONFIGURATION\"" \\
  --format=json

# 4. Public IPs
gcloud scc findings list \\
  --organization=$ORG_ID \\
  --filter="category=\"PUBLIC_IP_ADDRESS\"" \\
  --format=json

# 5. Open firewall rules
gcloud scc findings list \\
  --organization=$ORG_ID \\
  --filter="category=\"OPEN_FIREWALL\"" \\
  --format=json

# 6. Export to JSON
gcloud scc findings list \\
  --organization=$ORG_ID \\
  --format=json > scc-findings-\$(date +%Y%m%d).json
EOF

echo -e "${GREEN}✓ Sample queries saved to /tmp/scc-queries.txt${NC}"
echo ""

# 8. Verify setup
echo -e "${YELLOW}Step 8: Verifying setup...${NC}"

echo "Checking cluster security posture..."
gcloud container clusters describe $CLUSTER_NAME \
  --region=$CLUSTER_REGION \
  --format="value(securityPostureConfig)" \
  --project=$PROJECT_ID

echo ""
echo "Checking for existing findings..."
FINDINGS_COUNT=$(gcloud scc findings list \
  --organization=$ORG_ID \
  --format="value(name)" 2>/dev/null | wc -l)

echo "Found $FINDINGS_COUNT security findings"

echo ""
echo -e "${GREEN}=== Setup Complete ===${NC}"
echo ""
echo "Next steps:"
echo "1. Wait 10-15 minutes for initial scan to complete"
echo "2. View findings: https://console.cloud.google.com/security/command-center"
echo "3. Check compliance: Security Command Center → Compliance"
echo "4. Review queries in /tmp/scc-queries.txt"
echo ""
echo "To view findings now:"
echo "  gcloud scc findings list --organization=$ORG_ID --limit=10"
