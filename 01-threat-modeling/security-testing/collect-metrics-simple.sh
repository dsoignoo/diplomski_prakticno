#!/bin/bash
# Simplified Security Metrics Collection Script
# Handles edge cases better for baseline assessment

set -euo pipefail

PHASE="${1:-baseline}"
OUTPUT_FILE="metrics/${PHASE}-$(date +%Y%m%d-%H%M%S).json"

mkdir -p metrics

echo "Collecting security metrics for phase: ${PHASE}"
echo ""

# Get cluster info
CLUSTER_NAME=$(kubectl config current-context)
K8S_VERSION=$(kubectl version --short 2>/dev/null | grep Server | awk '{print $3}' || echo "unknown")

echo "  Cluster: ${CLUSTER_NAME}"
echo "  Kubernetes Version: ${K8S_VERSION}"
echo ""

# ==========================================
# 1. POD SECURITY
# ==========================================
echo "  [1/6] Checking Pod Security Standards..."

TOTAL_PODS=$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | wc -l || echo 0)
PRIVILEGED_PODS=0
HOST_NETWORK_PODS=0
ROOT_USER_PODS=0

# Sample pods to avoid timeout (check first 20)
SAMPLE_PODS=$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | head -20)

while IFS= read -r line; do
    [ -z "$line" ] && continue
    NAMESPACE=$(echo "$line" | awk '{print $1}')
    POD=$(echo "$line" | awk '{print $2}')
    STATUS=$(echo "$line" | awk '{print $4}')

    # Only check running pods
    [ "$STATUS" != "Running" ] && continue

    # Check privileged
    PRIV=$(kubectl get pod "$POD" -n "$NAMESPACE" -o jsonpath='{.spec.containers[*].securityContext.privileged}' 2>/dev/null || echo "false")
    [[ "$PRIV" =~ "true" ]] && PRIVILEGED_PODS=$((PRIVILEGED_PODS + 1))

    # Check host network
    HOST_NET=$(kubectl get pod "$POD" -n "$NAMESPACE" -o jsonpath='{.spec.hostNetwork}' 2>/dev/null || echo "false")
    [[ "$HOST_NET" == "true" ]] && HOST_NETWORK_PODS=$((HOST_NETWORK_PODS + 1))

done <<< "$SAMPLE_PODS"

PSS_COMPLIANT=$((TOTAL_PODS - PRIVILEGED_PODS - HOST_NETWORK_PODS))
[ $PSS_COMPLIANT -lt 0 ] && PSS_COMPLIANT=0

echo "    Total pods: ${TOTAL_PODS}"
echo "    Privileged pods: ${PRIVILEGED_PODS}"
echo "    Host network pods: ${HOST_NETWORK_PODS}"

# ==========================================
# 2. NETWORK POLICIES
# ==========================================
echo "  [2/6] Checking NetworkPolicies..."

TOTAL_NETPOL=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l || echo 0)
TOTAL_NAMESPACES=$(kubectl get namespaces --no-headers 2>/dev/null | grep -v "kube-" | wc -l || echo 1)
NAMESPACES_WITH_NETPOL=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | awk '{print $1}' | sort -u | wc -l || echo 0)

echo "    Total NetworkPolicies: ${TOTAL_NETPOL}"
echo "    Namespaces with policies: ${NAMESPACES_WITH_NETPOL}/${TOTAL_NAMESPACES}"

# ==========================================
# 3. RBAC
# ==========================================
echo "  [3/6] Checking RBAC configuration..."

TOTAL_SA=$(kubectl get serviceaccounts --all-namespaces --no-headers 2>/dev/null | wc -l || echo 0)
TOTAL_ROLES=$(kubectl get roles --all-namespaces --no-headers 2>/dev/null | wc -l || echo 0)
CLUSTER_ADMIN_BINDINGS=$(kubectl get clusterrolebindings -o json 2>/dev/null | jq '[.items[] | select(.roleRef.name == "cluster-admin")] | length' || echo 0)

echo "    Service accounts: ${TOTAL_SA}"
echo "    Roles: ${TOTAL_ROLES}"
echo "    Cluster-admin bindings: ${CLUSTER_ADMIN_BINDINGS}"

# ==========================================
# 4. SECRETS
# ==========================================
echo "  [4/6] Checking secrets management..."

TOTAL_SECRETS=$(kubectl get secrets --all-namespaces --no-headers 2>/dev/null | wc -l || echo 0)
EXTERNAL_SECRETS=$(kubectl get externalsecrets --all-namespaces --no-headers 2>/dev/null | wc -l || echo 0)

echo "    Total secrets: ${TOTAL_SECRETS}"
echo "    External secrets: ${EXTERNAL_SECRETS}"

# ==========================================
# 5. RUNTIME SECURITY
# ==========================================
echo "  [5/6] Checking runtime security..."

FALCO_DEPLOYED="false"
if kubectl get deployment -n falco falco &>/dev/null || kubectl get daemonset -n falco falco &>/dev/null; then
    FALCO_DEPLOYED="true"
fi

echo "    Falco deployed: ${FALCO_DEPLOYED}"

# ==========================================
# 6. OBSERVABILITY
# ==========================================
echo "  [6/6] Checking observability stack..."

PROMETHEUS_DEPLOYED="false"
GRAFANA_DEPLOYED="false"

if kubectl get deployment -n monitoring prometheus-server &>/dev/null || \
   kubectl get statefulset -n monitoring prometheus-kube-prometheus-prometheus &>/dev/null; then
    PROMETHEUS_DEPLOYED="true"
fi

if kubectl get deployment -n monitoring grafana &>/dev/null; then
    GRAFANA_DEPLOYED="true"
fi

echo "    Prometheus: ${PROMETHEUS_DEPLOYED}"
echo "    Grafana: ${GRAFANA_DEPLOYED}"

# ==========================================
# CALCULATE SECURITY SCORE
# ==========================================
echo ""
echo "  Calculating security score..."

# PSS Score (20 points)
if [ $TOTAL_PODS -gt 0 ]; then
    PSS_SCORE=$(awk "BEGIN {printf \"%.0f\", (${PSS_COMPLIANT}/${TOTAL_PODS}) * 20}")
else
    PSS_SCORE=0
fi

# Network Policy Score (20 points)
if [ $TOTAL_NAMESPACES -gt 0 ]; then
    NETPOL_SCORE=$(awk "BEGIN {printf \"%.0f\", (${NAMESPACES_WITH_NETPOL}/${TOTAL_NAMESPACES}) * 20}")
else
    NETPOL_SCORE=0
fi

# RBAC Score (15 points) - penalize cluster-admin bindings
if [ $CLUSTER_ADMIN_BINDINGS -gt 5 ]; then
    RBAC_SCORE=5
elif [ $CLUSTER_ADMIN_BINDINGS -gt 2 ]; then
    RBAC_SCORE=10
else
    RBAC_SCORE=15
fi

# Secrets Score (15 points)
if [ $EXTERNAL_SECRETS -gt 0 ]; then
    SECRETS_SCORE=15
else
    SECRETS_SCORE=5
fi

# Vulnerability Score (20 points) - assume poor without Trivy
VULN_SCORE=5

# Runtime Security Score (10 points)
if [ "$FALCO_DEPLOYED" = "true" ]; then
    RUNTIME_SCORE=10
else
    RUNTIME_SCORE=0
fi

TOTAL_SCORE=$((PSS_SCORE + NETPOL_SCORE + RBAC_SCORE + SECRETS_SCORE + VULN_SCORE + RUNTIME_SCORE))

# ==========================================
# GENERATE JSON REPORT
# ==========================================

cat > "${OUTPUT_FILE}" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "phase": "${PHASE}",
  "cluster_name": "${CLUSTER_NAME}",
  "kubernetes_version": "${K8S_VERSION}",

  "pod_security_standards": {
    "total_pods": ${TOTAL_PODS},
    "pss_compliant_pods": ${PSS_COMPLIANT},
    "privileged_pods": ${PRIVILEGED_PODS},
    "host_network_pods": ${HOST_NETWORK_PODS},
    "compliance_rate": $([ $TOTAL_PODS -gt 0 ] && awk "BEGIN {printf \"%.1f\", (${PSS_COMPLIANT}/${TOTAL_PODS})*100}" || echo "0")
  },

  "network_policies": {
    "total_policies": ${TOTAL_NETPOL},
    "total_namespaces": ${TOTAL_NAMESPACES},
    "namespaces_with_policies": ${NAMESPACES_WITH_NETPOL},
    "coverage_rate": $([ $TOTAL_NAMESPACES -gt 0 ] && awk "BEGIN {printf \"%.1f\", (${NAMESPACES_WITH_NETPOL}/${TOTAL_NAMESPACES})*100}" || echo "0")
  },

  "rbac_configuration": {
    "total_service_accounts": ${TOTAL_SA},
    "total_roles": ${TOTAL_ROLES},
    "cluster_admin_bindings": ${CLUSTER_ADMIN_BINDINGS}
  },

  "secrets_management": {
    "total_secrets": ${TOTAL_SECRETS},
    "external_secrets_count": ${EXTERNAL_SECRETS},
    "external_secrets_operator": $([ ${EXTERNAL_SECRETS} -gt 0 ] && echo "true" || echo "false")
  },

  "runtime_security": {
    "falco_deployed": ${FALCO_DEPLOYED}
  },

  "observability": {
    "prometheus": ${PROMETHEUS_DEPLOYED},
    "grafana": ${GRAFANA_DEPLOYED}
  },

  "security_score": ${TOTAL_SCORE},
  "score_breakdown": {
    "pod_security": ${PSS_SCORE},
    "network_segmentation": ${NETPOL_SCORE},
    "rbac": ${RBAC_SCORE},
    "secrets_management": ${SECRETS_SCORE},
    "vulnerability_management": ${VULN_SCORE},
    "runtime_security": ${RUNTIME_SCORE}
  }
}
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Metrics collected successfully"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Output: ${OUTPUT_FILE}"
echo ""
echo "Security Score: ${TOTAL_SCORE}/100"
echo "  - Pod Security:            ${PSS_SCORE}/20"
echo "  - Network Segmentation:    ${NETPOL_SCORE}/20"
echo "  - RBAC Configuration:      ${RBAC_SCORE}/15"
echo "  - Secrets Management:      ${SECRETS_SCORE}/15"
echo "  - Vulnerability Mgmt:      ${VULN_SCORE}/20"
echo "  - Runtime Security:        ${RUNTIME_SCORE}/10"
echo ""

# Assessment
if [ $TOTAL_SCORE -lt 30 ]; then
    echo "⚠️  CRITICAL: Security score is very low (${TOTAL_SCORE}/100)"
    echo "    Immediate action required to implement security controls"
elif [ $TOTAL_SCORE -lt 50 ]; then
    echo "⚠️  WARNING: Security score is low (${TOTAL_SCORE}/100)"
    echo "    Significant security gaps exist"
elif [ $TOTAL_SCORE -lt 70 ]; then
    echo "✓ FAIR: Security score is moderate (${TOTAL_SCORE}/100)"
    echo "    Continue implementing security controls"
elif [ $TOTAL_SCORE -lt 85 ]; then
    echo "✓ GOOD: Security score is acceptable (${TOTAL_SCORE}/100)"
    echo "    Minor improvements recommended"
else
    echo "✓ EXCELLENT: Security score is strong (${TOTAL_SCORE}/100)"
    echo "    Maintain current security posture"
fi

echo ""
