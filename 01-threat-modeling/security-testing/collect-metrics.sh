#!/bin/bash
# Security Metrics Collection Script
# Collects comprehensive security metrics for comparison across phases

set -euo pipefail

PHASE="${1:-baseline}"
OUTPUT_FILE="${2:-metrics/${PHASE}-$(date +%Y%m%d-%H%M%S).json}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$(dirname "$OUTPUT_FILE")"

echo "Collecting security metrics for phase: ${PHASE}"

# Initialize metrics object
cat > "${OUTPUT_FILE}" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "phase": "${PHASE}",
  "kubernetes_version": "$(kubectl version --short 2>/dev/null | grep Server | awk '{print $3}')",
  "cluster_name": "$(kubectl config current-context)",
EOF

# ==========================================
# 1. VULNERABILITY SCANNING
# ==========================================
echo "  [1/8] Scanning container images for vulnerabilities..."

TOTAL_IMAGES=0
VULNERABLE_IMAGES=0
CRITICAL_CVES=0
HIGH_CVES=0
MEDIUM_CVES=0

# Get all images in use
IMAGES=$(kubectl get pods --all-namespaces -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u)

for IMAGE in $IMAGES; do
    TOTAL_IMAGES=$((TOTAL_IMAGES + 1))

    # Scan with Trivy (if available)
    if command -v trivy &> /dev/null; then
        SCAN_RESULT=$(trivy image --severity CRITICAL,HIGH,MEDIUM --format json "$IMAGE" 2>/dev/null || echo '{"Results":[]}')

        CRITICAL=$(echo "$SCAN_RESULT" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length')
        HIGH=$(echo "$SCAN_RESULT" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length')
        MEDIUM=$(echo "$SCAN_RESULT" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length')

        CRITICAL_CVES=$((CRITICAL_CVES + CRITICAL))
        HIGH_CVES=$((HIGH_CVES + HIGH))
        MEDIUM_CVES=$((MEDIUM_CVES + MEDIUM))

        if [ $CRITICAL -gt 0 ] || [ $HIGH -gt 0 ]; then
            VULNERABLE_IMAGES=$((VULNERABLE_IMAGES + 1))
        fi
    fi
done

cat >> "${OUTPUT_FILE}" <<EOF
  "vulnerability_scanning": {
    "total_images": ${TOTAL_IMAGES},
    "vulnerable_images": ${VULNERABLE_IMAGES},
    "vulnerability_rate": $(awk "BEGIN {printf \"%.2f\", ${VULNERABLE_IMAGES}/${TOTAL_IMAGES}*100}"),
    "critical_cves": ${CRITICAL_CVES},
    "high_cves": ${HIGH_CVES},
    "medium_cves": ${MEDIUM_CVES}
  },
EOF

# ==========================================
# 2. POD SECURITY STANDARDS
# ==========================================
echo "  [2/8] Checking Pod Security Standards compliance..."

TOTAL_PODS=$(kubectl get pods --all-namespaces --no-headers | wc -l)
PSS_COMPLIANT=0
PRIVILEGED_PODS=0
HOST_NETWORK_PODS=0
ROOT_USER_PODS=0

# Check each pod's security context
while IFS= read -r line; do
    NAMESPACE=$(echo "$line" | awk '{print $1}')
    POD=$(echo "$line" | awk '{print $2}')

    # Check if privileged
    PRIVILEGED=$(kubectl get pod "$POD" -n "$NAMESPACE" -o json | jq '.spec.containers[].securityContext.privileged // false' | grep -c "true" || echo 0)
    PRIVILEGED_PODS=$((PRIVILEGED_PODS + PRIVILEGED))

    # Check if uses host network
    HOST_NETWORK=$(kubectl get pod "$POD" -n "$NAMESPACE" -o json | jq '.spec.hostNetwork // false' | grep -c "true" || echo 0)
    HOST_NETWORK_PODS=$((HOST_NETWORK_PODS + HOST_NETWORK))

    # Check if runs as root
    RUN_AS_USER=$(kubectl get pod "$POD" -n "$NAMESPACE" -o json | jq '.spec.containers[].securityContext.runAsUser // 0' | grep -c "^0$" || echo 0)
    if [ "$RUN_AS_USER" -gt 0 ]; then
        ROOT_USER_PODS=$((ROOT_USER_PODS + 1))
    fi

    # If none of the above, consider PSS compliant
    if [ "$PRIVILEGED" -eq 0 ] && [ "$HOST_NETWORK" -eq 0 ] && [ "$RUN_AS_USER" -eq 0 ]; then
        PSS_COMPLIANT=$((PSS_COMPLIANT + 1))
    fi
done < <(kubectl get pods --all-namespaces --no-headers | grep -v "kube-system")

cat >> "${OUTPUT_FILE}" <<EOF
  "pod_security_standards": {
    "total_pods": ${TOTAL_PODS},
    "pss_compliant_pods": ${PSS_COMPLIANT},
    "compliance_rate": $(awk "BEGIN {printf \"%.2f\", ${PSS_COMPLIANT}/${TOTAL_PODS}*100}"),
    "privileged_pods": ${PRIVILEGED_PODS},
    "host_network_pods": ${HOST_NETWORK_PODS},
    "root_user_pods": ${ROOT_USER_PODS}
  },
EOF

# ==========================================
# 3. NETWORK POLICIES
# ==========================================
echo "  [3/8] Checking NetworkPolicy coverage..."

TOTAL_NAMESPACES=$(kubectl get namespaces --no-headers | grep -v "kube-" | wc -l)
NAMESPACES_WITH_NETPOL=$(kubectl get networkpolicies --all-namespaces --no-headers | awk '{print $1}' | sort -u | wc -l)
TOTAL_NETPOL=$(kubectl get networkpolicies --all-namespaces --no-headers | wc -l)

# Check for default deny policy
DEFAULT_DENY=$(kubectl get networkpolicies --all-namespaces -o json | jq '[.items[] | select(.spec.policyTypes[] == "Ingress" or .spec.policyTypes[] == "Egress") | select(.spec.ingress == null or .spec.egress == null)] | length')

cat >> "${OUTPUT_FILE}" <<EOF
  "network_policies": {
    "total_policies": ${TOTAL_NETPOL},
    "namespaces_with_policies": ${NAMESPACES_WITH_NETPOL},
    "coverage_rate": $(awk "BEGIN {printf \"%.2f\", ${NAMESPACES_WITH_NETPOL}/${TOTAL_NAMESPACES}*100}"),
    "default_deny_policies": ${DEFAULT_DENY}
  },
EOF

# ==========================================
# 4. RBAC CONFIGURATION
# ==========================================
echo "  [4/8] Auditing RBAC configuration..."

TOTAL_SERVICE_ACCOUNTS=$(kubectl get serviceaccounts --all-namespaces --no-headers | wc -l)
TOTAL_ROLES=$(kubectl get roles --all-namespaces --no-headers | wc -l)
TOTAL_CLUSTER_ROLES=$(kubectl get clusterroles --no-headers | wc -l)

# Check for overly permissive roles
WILDCARD_ROLES=$(kubectl get roles,clusterroles --all-namespaces -o json | jq '[.items[] | select(.rules[]?.verbs[]? == "*" or .rules[]?.resources[]? == "*")] | length')

# Check for use of cluster-admin
CLUSTER_ADMIN_BINDINGS=$(kubectl get clusterrolebindings -o json | jq '[.items[] | select(.roleRef.name == "cluster-admin")] | length')

cat >> "${OUTPUT_FILE}" <<EOF
  "rbac_configuration": {
    "total_service_accounts": ${TOTAL_SERVICE_ACCOUNTS},
    "total_roles": ${TOTAL_ROLES},
    "total_cluster_roles": ${TOTAL_CLUSTER_ROLES},
    "wildcard_permissions": ${WILDCARD_ROLES},
    "cluster_admin_bindings": ${CLUSTER_ADMIN_BINDINGS}
  },
EOF

# ==========================================
# 5. SECRETS MANAGEMENT
# ==========================================
echo "  [5/8] Checking secrets management..."

TOTAL_SECRETS=$(kubectl get secrets --all-namespaces --no-headers | wc -l)

# Check for External Secrets Operator
EXTERNAL_SECRETS=$(kubectl get externalsecrets --all-namespaces --no-headers 2>/dev/null | wc -l || echo 0)

# Check for encryption at rest (GKE specific)
ENCRYPTION_ENABLED="false"
if kubectl get nodes -o json | jq -e '.items[0].metadata.labels["cloud.google.com/gke-encryption"]' &>/dev/null; then
    ENCRYPTION_ENABLED="true"
fi

cat >> "${OUTPUT_FILE}" <<EOF
  "secrets_management": {
    "total_secrets": ${TOTAL_SECRETS},
    "external_secrets_count": ${EXTERNAL_SECRETS},
    "external_secrets_operator": $([ ${EXTERNAL_SECRETS} -gt 0 ] && echo "true" || echo "false"),
    "encryption_at_rest": ${ENCRYPTION_ENABLED}
  },
EOF

# ==========================================
# 6. RUNTIME SECURITY (Falco)
# ==========================================
echo "  [6/8] Checking runtime security (Falco)..."

FALCO_DEPLOYED="false"
FALCO_RULES=0
FALCO_ALERTS_24H=0

if kubectl get deployment -n falco falco &>/dev/null; then
    FALCO_DEPLOYED="true"
    FALCO_RULES=$(kubectl get configmap -n falco falco-rules -o json 2>/dev/null | jq '.data | length' || echo 0)

    # Count Falco alerts in last 24 hours (if Falco Sidekick deployed with logging)
    FALCO_ALERTS_24H=$(kubectl logs -n falco -l app=falco --since=24h 2>/dev/null | grep -c "Priority:" || echo 0)
fi

cat >> "${OUTPUT_FILE}" <<EOF
  "runtime_security": {
    "falco_deployed": ${FALCO_DEPLOYED},
    "falco_rules_count": ${FALCO_RULES},
    "falco_alerts_24h": ${FALCO_ALERTS_24H}
  },
EOF

# ==========================================
# 7. OBSERVABILITY
# ==========================================
echo "  [7/8] Checking observability stack..."

PROMETHEUS_DEPLOYED="false"
GRAFANA_DEPLOYED="false"
LOKI_DEPLOYED="false"
JAEGER_DEPLOYED="false"

if kubectl get deployment -n monitoring prometheus-server &>/dev/null || \
   kubectl get statefulset -n monitoring prometheus-kube-prometheus-prometheus &>/dev/null; then
    PROMETHEUS_DEPLOYED="true"
fi

if kubectl get deployment -n monitoring grafana &>/dev/null; then
    GRAFANA_DEPLOYED="true"
fi

if kubectl get statefulset -n monitoring loki &>/dev/null; then
    LOKI_DEPLOYED="true"
fi

if kubectl get deployment -n monitoring jaeger &>/dev/null; then
    JAEGER_DEPLOYED="true"
fi

cat >> "${OUTPUT_FILE}" <<EOF
  "observability": {
    "prometheus": ${PROMETHEUS_DEPLOYED},
    "grafana": ${GRAFANA_DEPLOYED},
    "loki": ${LOKI_DEPLOYED},
    "jaeger": ${JAEGER_DEPLOYED}
  },
EOF

# ==========================================
# 8. ATTACK SIMULATION RESULTS
# ==========================================
echo "  [8/8] Running attack simulations..."

# Run attack simulations if requested
if [ "${RUN_SIMULATIONS:-false}" = "true" ]; then
    "${SCRIPT_DIR}/run-all-simulations.sh" "${PHASE}" >/dev/null 2>&1 || true

    # Find latest simulation results
    LATEST_RESULTS=$(ls -t "${SCRIPT_DIR}/results/*/summary.json" 2>/dev/null | head -1)

    if [ -f "$LATEST_RESULTS" ]; then
        SIMULATION_DATA=$(cat "$LATEST_RESULTS")
        cat >> "${OUTPUT_FILE}" <<EOF
  "attack_simulations": ${SIMULATION_DATA}
}
EOF
    else
        cat >> "${OUTPUT_FILE}" <<EOF
  "attack_simulations": null
}
EOF
    fi
else
    cat >> "${OUTPUT_FILE}" <<EOF
  "attack_simulations": null
}
EOF
fi

echo ""
echo "✓ Metrics collected successfully"
echo "  Output: ${OUTPUT_FILE}"

# Calculate security score (0-100)
VULN_SCORE=$(awk "BEGIN {printf \"%.0f\", (1 - ${VULNERABLE_IMAGES}/${TOTAL_IMAGES}) * 20}")
PSS_SCORE=$(awk "BEGIN {printf \"%.0f\", ${PSS_COMPLIANT}/${TOTAL_PODS} * 20}")
NETPOL_SCORE=$(awk "BEGIN {printf \"%.0f\", ${NAMESPACES_WITH_NETPOL}/${TOTAL_NAMESPACES} * 20}")
RBAC_SCORE=$(awk "BEGIN {printf \"%.0f\", (1 - ${WILDCARD_ROLES}/${TOTAL_ROLES}) * 15}")
SECRETS_SCORE=$([ "$ENCRYPTION_ENABLED" = "true" ] && echo 15 || echo 5)
RUNTIME_SCORE=$([ "$FALCO_DEPLOYED" = "true" ] && echo 10 || echo 0)

TOTAL_SCORE=$((VULN_SCORE + PSS_SCORE + NETPOL_SCORE + RBAC_SCORE + SECRETS_SCORE + RUNTIME_SCORE))

echo ""
echo "Security Score: ${TOTAL_SCORE}/100"
echo "  - Vulnerability Management: ${VULN_SCORE}/20"
echo "  - Pod Security:            ${PSS_SCORE}/20"
echo "  - Network Segmentation:    ${NETPOL_SCORE}/20"
echo "  - RBAC Configuration:      ${RBAC_SCORE}/15"
echo "  - Secrets Management:      ${SECRETS_SCORE}/15"
echo "  - Runtime Security:        ${RUNTIME_SCORE}/10"

# Update JSON with score
jq --arg score "$TOTAL_SCORE" '. + {security_score: ($score | tonumber)}' "${OUTPUT_FILE}" > "${OUTPUT_FILE}.tmp"
mv "${OUTPUT_FILE}.tmp" "${OUTPUT_FILE}"
