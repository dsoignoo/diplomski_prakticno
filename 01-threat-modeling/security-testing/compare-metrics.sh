#!/bin/bash
# Metrics Comparison Script
# Compares security metrics between two phases to demonstrate improvements

set -euo pipefail

BASELINE_FILE="$1"
CURRENT_FILE="$2"

if [ ! -f "$BASELINE_FILE" ] || [ ! -f "$CURRENT_FILE" ]; then
    echo "Usage: $0 <baseline-metrics.json> <current-metrics.json>"
    exit 1
fi

echo "========================================"
echo "Security Metrics Comparison"
echo "========================================"
echo ""
echo "Baseline: $(jq -r '.phase' "$BASELINE_FILE") ($(jq -r '.timestamp' "$BASELINE_FILE"))"
echo "Current:  $(jq -r '.phase' "$CURRENT_FILE") ($(jq -r '.timestamp' "$CURRENT_FILE"))"
echo ""

# Function to calculate percentage change
calc_change() {
    local baseline=$1
    local current=$2
    local reverse=${3:-false}  # For metrics where lower is better

    if [ "$baseline" -eq 0 ]; then
        echo "N/A"
        return
    fi

    local change=$(awk "BEGIN {printf \"%.1f\", (($current - $baseline) / $baseline) * 100}")

    if [ "$reverse" = "true" ]; then
        # Reverse sign (for metrics where lower is better)
        change=$(awk "BEGIN {printf \"%.1f\", -1 * $change}")
    fi

    if (( $(echo "$change > 0" | bc -l) )); then
        echo "+${change}%"
    else
        echo "${change}%"
    fi
}

# Function to print metric comparison
print_metric() {
    local label="$1"
    local baseline=$2
    local current=$3
    local reverse=${4:-false}
    local unit=${5:-""}

    local change=$(calc_change "$baseline" "$current" "$reverse")

    printf "%-40s %10s → %-10s (%s)\n" "$label" "${baseline}${unit}" "${current}${unit}" "$change"
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "VULNERABILITY MANAGEMENT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BASELINE_VULN_IMAGES=$(jq '.vulnerability_scanning.vulnerable_images' "$BASELINE_FILE")
CURRENT_VULN_IMAGES=$(jq '.vulnerability_scanning.vulnerable_images' "$CURRENT_FILE")
print_metric "Vulnerable Images" "$BASELINE_VULN_IMAGES" "$CURRENT_VULN_IMAGES" "true"

BASELINE_CRITICAL=$(jq '.vulnerability_scanning.critical_cves' "$BASELINE_FILE")
CURRENT_CRITICAL=$(jq '.vulnerability_scanning.critical_cves' "$CURRENT_FILE")
print_metric "Critical CVEs" "$BASELINE_CRITICAL" "$CURRENT_CRITICAL" "true"

BASELINE_HIGH=$(jq '.vulnerability_scanning.high_cves' "$BASELINE_FILE")
CURRENT_HIGH=$(jq '.vulnerability_scanning.high_cves' "$CURRENT_FILE")
print_metric "High CVEs" "$BASELINE_HIGH" "$CURRENT_HIGH" "true"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "POD SECURITY STANDARDS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BASELINE_PSS=$(jq '.pod_security_standards.pss_compliant_pods' "$BASELINE_FILE")
CURRENT_PSS=$(jq '.pod_security_standards.pss_compliant_pods' "$CURRENT_FILE")
print_metric "PSS Compliant Pods" "$BASELINE_PSS" "$CURRENT_PSS"

BASELINE_PRIV=$(jq '.pod_security_standards.privileged_pods' "$BASELINE_FILE")
CURRENT_PRIV=$(jq '.pod_security_standards.privileged_pods' "$CURRENT_FILE")
print_metric "Privileged Pods" "$BASELINE_PRIV" "$CURRENT_PRIV" "true"

BASELINE_ROOT=$(jq '.pod_security_standards.root_user_pods' "$BASELINE_FILE")
CURRENT_ROOT=$(jq '.pod_security_standards.root_user_pods' "$CURRENT_FILE")
print_metric "Root User Pods" "$BASELINE_ROOT" "$CURRENT_ROOT" "true"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "NETWORK SECURITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BASELINE_NETPOL=$(jq '.network_policies.total_policies' "$BASELINE_FILE")
CURRENT_NETPOL=$(jq '.network_policies.total_policies' "$CURRENT_FILE")
print_metric "Network Policies" "$BASELINE_NETPOL" "$CURRENT_NETPOL"

BASELINE_COVERAGE=$(jq '.network_policies.namespaces_with_policies' "$BASELINE_FILE")
CURRENT_COVERAGE=$(jq '.network_policies.namespaces_with_policies' "$CURRENT_FILE")
print_metric "Namespaces with Policies" "$BASELINE_COVERAGE" "$CURRENT_COVERAGE"

BASELINE_DEFAULT_DENY=$(jq '.network_policies.default_deny_policies' "$BASELINE_FILE")
CURRENT_DEFAULT_DENY=$(jq '.network_policies.default_deny_policies' "$CURRENT_FILE")
print_metric "Default Deny Policies" "$BASELINE_DEFAULT_DENY" "$CURRENT_DEFAULT_DENY"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ACCESS CONTROL (RBAC)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BASELINE_WILDCARD=$(jq '.rbac_configuration.wildcard_permissions' "$BASELINE_FILE")
CURRENT_WILDCARD=$(jq '.rbac_configuration.wildcard_permissions' "$CURRENT_FILE")
print_metric "Wildcard Permissions" "$BASELINE_WILDCARD" "$CURRENT_WILDCARD" "true"

BASELINE_ADMIN=$(jq '.rbac_configuration.cluster_admin_bindings' "$BASELINE_FILE")
CURRENT_ADMIN=$(jq '.rbac_configuration.cluster_admin_bindings' "$CURRENT_FILE")
print_metric "Cluster Admin Bindings" "$BASELINE_ADMIN" "$CURRENT_ADMIN" "true"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECRETS MANAGEMENT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BASELINE_EXT_SECRETS=$(jq '.secrets_management.external_secrets_count' "$BASELINE_FILE")
CURRENT_EXT_SECRETS=$(jq '.secrets_management.external_secrets_count' "$CURRENT_FILE")
print_metric "External Secrets" "$BASELINE_EXT_SECRETS" "$CURRENT_EXT_SECRETS"

BASELINE_ENCRYPTION=$(jq -r '.secrets_management.encryption_at_rest' "$BASELINE_FILE")
CURRENT_ENCRYPTION=$(jq -r '.secrets_management.encryption_at_rest' "$CURRENT_FILE")
echo "Encryption at Rest: $BASELINE_ENCRYPTION → $CURRENT_ENCRYPTION"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "RUNTIME SECURITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BASELINE_FALCO=$(jq -r '.runtime_security.falco_deployed' "$BASELINE_FILE")
CURRENT_FALCO=$(jq -r '.runtime_security.falco_deployed' "$CURRENT_FILE")
echo "Falco Deployed: $BASELINE_FALCO → $CURRENT_FALCO"

if [ "$CURRENT_FALCO" = "true" ]; then
    BASELINE_ALERTS=$(jq '.runtime_security.falco_alerts_24h' "$BASELINE_FILE")
    CURRENT_ALERTS=$(jq '.runtime_security.falco_alerts_24h' "$CURRENT_FILE")
    echo "Falco Alerts (24h): $BASELINE_ALERTS → $CURRENT_ALERTS"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ATTACK SIMULATION RESULTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BASELINE_ATTACKS=$(jq '.attack_simulations.attacks_succeeded // 0' "$BASELINE_FILE")
CURRENT_ATTACKS=$(jq '.attack_simulations.attacks_succeeded // 0' "$CURRENT_FILE")
print_metric "Successful Attacks" "$BASELINE_ATTACKS" "$CURRENT_ATTACKS" "true"

BASELINE_BLOCKED=$(jq '.attack_simulations.attacks_blocked // 0' "$BASELINE_FILE")
CURRENT_BLOCKED=$(jq '.attack_simulations.attacks_blocked // 0' "$CURRENT_FILE")
print_metric "Attacks Blocked" "$BASELINE_BLOCKED" "$CURRENT_BLOCKED"

BASELINE_DETECTED=$(jq '.attack_simulations.attacks_detected // 0' "$BASELINE_FILE")
CURRENT_DETECTED=$(jq '.attack_simulations.attacks_detected // 0' "$CURRENT_FILE")
print_metric "Attacks Detected" "$BASELINE_DETECTED" "$CURRENT_DETECTED"

BASELINE_MTTD=$(jq '.attack_simulations.avg_mttd_seconds // 0' "$BASELINE_FILE")
CURRENT_MTTD=$(jq '.attack_simulations.avg_mttd_seconds // 0' "$CURRENT_FILE")
if [ "$BASELINE_MTTD" != "null" ] && [ "$CURRENT_MTTD" != "null" ]; then
    print_metric "Mean Time to Detect (MTTD)" "$BASELINE_MTTD" "$CURRENT_MTTD" "true" "s"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "OVERALL SECURITY SCORE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BASELINE_SCORE=$(jq '.security_score // 0' "$BASELINE_FILE")
CURRENT_SCORE=$(jq '.security_score // 0' "$CURRENT_FILE")

printf "\nSecurity Score: %d/100 → %d/100 " "$BASELINE_SCORE" "$CURRENT_SCORE"

SCORE_DIFF=$((CURRENT_SCORE - BASELINE_SCORE))
if [ $SCORE_DIFF -gt 0 ]; then
    echo -e "\033[0;32m(+${SCORE_DIFF} points improvement)\033[0m"
elif [ $SCORE_DIFF -lt 0 ]; then
    echo -e "\033[0;31m(${SCORE_DIFF} points regression)\033[0m"
else
    echo "(no change)"
fi

echo ""

# Generate visual progress bar
print_progress_bar() {
    local score=$1
    local bar_length=50
    local filled=$((score * bar_length / 100))
    local empty=$((bar_length - filled))

    printf "["
    for ((i=0; i<filled; i++)); do printf "▰"; done
    for ((i=0; i<empty; i++)); do printf "▱"; done
    printf "]"
}

echo "Baseline: $(print_progress_bar "$BASELINE_SCORE") ${BASELINE_SCORE}%"
echo "Current:  $(print_progress_bar "$CURRENT_SCORE") ${CURRENT_SCORE}%"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
