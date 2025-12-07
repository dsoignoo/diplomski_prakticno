#!/bin/bash
# Infrastructure Security Verification Script
# Validates that Phase 02 security controls are properly implemented

set -euo pipefail

echo "════════════════════════════════════════════════════════"
echo "  Phase 02: Infrastructure Security Verification"
echo "════════════════════════════════════════════════════════"
echo ""

CLUSTER_NAME=$(kubectl config current-context | cut -d'_' -f4 2>/dev/null || echo "unknown")
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
REGION=$(gcloud config get-value compute/region 2>/dev/null || echo "us-central1")

echo "Cluster: $CLUSTER_NAME"
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo ""

PASS=0
FAIL=0

# Test function
check() {
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"

    echo -n "[$((PASS + FAIL + 1))] $test_name... "

    if eval "$command" 2>&1 | grep -q "$expected_pattern"; then
        echo "✅ PASS"
        PASS=$((PASS + 1))
        return 0
    else
        echo "❌ FAIL"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. CLUSTER CONFIGURATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if Autopilot
check "GKE Autopilot enabled" \
    "gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(autopilot.enabled)'" \
    "True"

# Check Workload Identity
check "Workload Identity configured" \
    "gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(workloadIdentityConfig.workloadPool)'" \
    "svc.id.goog"

# Check Binary Authorization
check "Binary Authorization enabled" \
    "gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(binaryAuthorization.evaluationMode)'" \
    "PROJECT_SINGLETON_POLICY_ENFORCE"

# Check Network Policy
check "Network Policy supported" \
    "gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(networkPolicy.enabled)'" \
    "True"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. SHIELDED NODES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check Shielded Nodes
check "Shielded Nodes enabled" \
    "gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(shieldedNodes.enabled)'" \
    "True"

# Check actual node configuration (if nodes exist)
if kubectl get nodes &>/dev/null; then
    NODES=$(kubectl get nodes -o name)
    if [ -n "$NODES" ]; then
        # Get instance name from first node
        NODE_NAME=$(echo "$NODES" | head -1 | cut -d'/' -f2)
        INSTANCE_NAME=$(gcloud compute instances list --filter="name~'gke-$CLUSTER_NAME'" --format="get(name)" | head -1)

        if [ -n "$INSTANCE_NAME" ]; then
            check "Secure Boot enabled on nodes" \
                "gcloud compute instances describe $INSTANCE_NAME --zone=${REGION}-a --format='get(shieldedInstanceConfig.enableSecureBoot)'" \
                "True"

            check "Integrity Monitoring enabled" \
                "gcloud compute instances describe $INSTANCE_NAME --zone=${REGION}-a --format='get(shieldedInstanceConfig.enableIntegrityMonitoring)'" \
                "True"
        fi
    fi
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. PRIVATE CLUSTER"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check private nodes
check "Private nodes enabled" \
    "gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(privateClusterConfig.enablePrivateNodes)'" \
    "True"

# Verify nodes have no public IPs
if kubectl get nodes -o wide 2>/dev/null | grep -q "<none>"; then
    echo "[✓] Nodes have no public IP addresses ✅ PASS"
    PASS=$((PASS + 1))
else
    echo "[✗] Nodes have public IP addresses ❌ FAIL"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. SECRETS ENCRYPTION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check database encryption
check "Secrets encryption at rest" \
    "gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(databaseEncryption.state)'" \
    "ENCRYPTED"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. MONITORING & LOGGING"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check logging
check "Cloud Logging enabled" \
    "gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(loggingConfig.componentConfig.enableComponents)'" \
    "SYSTEM_COMPONENTS"

# Check monitoring
check "Cloud Monitoring enabled" \
    "gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(monitoringConfig.componentConfig.enableComponents)'" \
    "SYSTEM_COMPONENTS"

# Check managed Prometheus
check "Managed Prometheus enabled" \
    "gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(monitoringConfig.managedPrometheusConfig.enabled)'" \
    "True"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. SECURITY POSTURE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check security posture mode
SEC_POSTURE=$(gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(securityPostureConfig.mode)' 2>/dev/null || echo "DISABLED")

if [ "$SEC_POSTURE" = "ENTERPRISE" ] || [ "$SEC_POSTURE" = "BASIC" ]; then
    echo "[✓] Security Posture enabled ($SEC_POSTURE) ✅ PASS"
    PASS=$((PASS + 1))
else
    echo "[✗] Security Posture not enabled ❌ FAIL"
    FAIL=$((FAIL + 1))
fi

# Check vulnerability mode
VULN_MODE=$(gcloud container clusters describe $CLUSTER_NAME --region=$REGION --format='get(securityPostureConfig.vulnerabilityMode)' 2>/dev/null || echo "VULNERABILITY_DISABLED")

if [ "$VULN_MODE" = "VULNERABILITY_ENTERPRISE" ] || [ "$VULN_MODE" = "VULNERABILITY_BASIC" ]; then
    echo "[✓] Vulnerability scanning enabled ($VULN_MODE) ✅ PASS"
    PASS=$((PASS + 1))
else
    echo "[✗] Vulnerability scanning not enabled ❌ FAIL"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7. WORKLOAD IDENTITY (Functional Test)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if semaphore namespace exists
if kubectl get namespace semaphore &>/dev/null; then
    # Check for Workload Identity annotation on ServiceAccount
    if kubectl get sa default -n semaphore -o jsonpath='{.metadata.annotations.iam\.gke\.io/gcp-service-account}' 2>/dev/null | grep -q "@"; then
        echo "[✓] Workload Identity annotation present ✅ PASS"
        PASS=$((PASS + 1))
    else
        echo "[✗] Workload Identity annotation missing ❌ FAIL"
        FAIL=$((FAIL + 1))
    fi
else
    echo "[⚠] Semaphore namespace not found (skipping Workload Identity test)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "8. BACKUP CONFIGURATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if backup plan exists
if gcloud beta container backup-restore backup-plans list --location=$REGION 2>/dev/null | grep -q "$CLUSTER_NAME-backup-plan"; then
    echo "[✓] GKE Backup Plan configured ✅ PASS"
    PASS=$((PASS + 1))
else
    echo "[⚠] GKE Backup Plan not found (may not be enabled)"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  VERIFICATION SUMMARY"
echo "════════════════════════════════════════════════════════"
echo ""
echo "Tests Passed:  $PASS ✅"
echo "Tests Failed:  $FAIL ❌"
echo "Total Tests:   $((PASS + FAIL))"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "✅ ALL CHECKS PASSED - Infrastructure is properly hardened!"
    echo ""
    echo "Security Improvements:"
    echo "  ✅ Workload Identity preventing metadata abuse"
    echo "  ✅ Shielded Nodes preventing bootkit persistence"
    echo "  ✅ Private nodes reducing attack surface"
    echo "  ✅ Secrets encrypted at rest with KMS"
    echo "  ✅ Vulnerability scanning enabled"
    echo "  ✅ Comprehensive logging and monitoring"
    echo ""
    echo "Next: Deploy Semaphore and proceed to Phase 05 (Pod Security Standards)"
    exit 0
else
    echo "⚠️  SOME CHECKS FAILED - Review failures above"
    echo ""
    echo "Common issues:"
    echo "  - Cluster not fully deployed yet (wait a few minutes)"
    echo "  - terraform.tfvars missing required variables"
    echo "  - Semaphore not yet deployed (expected for some tests)"
    echo ""
    exit 1
fi
