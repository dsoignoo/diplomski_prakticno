#!/bin/bash
# Security Testing Suite - Master Test Runner
# Executes all attack simulations and validates security controls

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results/$(date +%Y%m%d-%H%M%S)"
PHASE="${1:-baseline}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_TESTS=0
ATTACKS_SUCCEEDED=0
ATTACKS_BLOCKED=0
ATTACKS_DETECTED=0
TOTAL_MTTD=0

# Create results directory
mkdir -p "${RESULTS_DIR}"

echo "========================================"
echo "Security Testing Suite - Execution Report"
echo "========================================"
echo ""
echo "Phase: ${PHASE}"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Results Directory: ${RESULTS_DIR}"
echo ""

# Function to run a test and capture results
run_test() {
    local test_name="$1"
    local test_script="$2"
    local category="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    echo -n "  Test ${TOTAL_TESTS}: ${test_name}... "

    # Run test and capture output
    local start_time=$(date +%s)
    local result_file="${RESULTS_DIR}/test-${TOTAL_TESTS}-$(echo ${test_name} | tr ' ' '-').json"

    if bash "${test_script}" > "${result_file}" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        # Check if attack succeeded
        if grep -q "ATTACK_SUCCESS=true" "${result_file}"; then
            echo -e "${RED}SUCCESS${NC} (${duration}s)"
            ATTACKS_SUCCEEDED=$((ATTACKS_SUCCEEDED + 1))

            # Check if detected
            if grep -q "DETECTED=true" "${result_file}"; then
                local mttd=$(grep "MTTD=" "${result_file}" | cut -d'=' -f2)
                echo -e "    ${GREEN}✓ DETECTED${NC} (MTTD: ${mttd}s)"
                ATTACKS_DETECTED=$((ATTACKS_DETECTED + 1))
                TOTAL_MTTD=$((TOTAL_MTTD + mttd))
            else
                echo -e "    ${RED}✗ NOT DETECTED${NC}"
            fi
        else
            echo -e "${GREEN}BLOCKED${NC}"
            ATTACKS_BLOCKED=$((ATTACKS_BLOCKED + 1))

            # Extract blocking mechanism
            local blocked_by=$(grep "BLOCKED_BY=" "${result_file}" | cut -d'=' -f2 || echo "Unknown")
            echo -e "    ${GREEN}✓${NC} Blocked by: ${blocked_by}"
        fi
    else
        echo -e "${YELLOW}ERROR${NC} (test script failed)"
        echo "    See: ${result_file}"
    fi
}

echo "[CONTAINER ESCAPE TESTS]"
run_test "Privileged container escape" \
    "${SCRIPT_DIR}/simulations/container-escape/privileged-escape.sh" \
    "container-escape"

run_test "CAP_SYS_ADMIN abuse" \
    "${SCRIPT_DIR}/simulations/container-escape/cap-sys-admin.sh" \
    "container-escape"

run_test "Hostpath escape" \
    "${SCRIPT_DIR}/simulations/container-escape/hostpath-escape.sh" \
    "container-escape"

echo ""
echo "[SECRET EXFILTRATION TESTS]"
run_test "K8s secret enumeration" \
    "${SCRIPT_DIR}/simulations/secret-exfiltration/k8s-secrets.sh" \
    "secret-exfiltration"

run_test "PostgreSQL direct access" \
    "${SCRIPT_DIR}/simulations/secret-exfiltration/postgres-access.sh" \
    "secret-exfiltration"

run_test "GCP metadata API access" \
    "${SCRIPT_DIR}/simulations/secret-exfiltration/gcp-metadata.sh" \
    "secret-exfiltration"

run_test "Redis cache access" \
    "${SCRIPT_DIR}/simulations/secret-exfiltration/redis-access.sh" \
    "secret-exfiltration"

echo ""
echo "[LATERAL MOVEMENT TESTS]"
run_test "Frontend → Database connection" \
    "${SCRIPT_DIR}/simulations/lateral-movement/frontend-to-database.sh" \
    "lateral-movement"

run_test "ServiceAccount token theft" \
    "${SCRIPT_DIR}/simulations/lateral-movement/token-theft.sh" \
    "lateral-movement"

run_test "DNS tunneling exfiltration" \
    "${SCRIPT_DIR}/simulations/lateral-movement/dns-exfil.sh" \
    "lateral-movement"

echo ""
echo "[SUPPLY CHAIN TESTS]"
run_test "Unsigned image deployment" \
    "${SCRIPT_DIR}/simulations/supply-chain/unsigned-image.sh" \
    "supply-chain"

run_test "Malicious artifact upload" \
    "${SCRIPT_DIR}/simulations/supply-chain/artifact-tamper.sh" \
    "supply-chain"

run_test "Vulnerable dependency" \
    "${SCRIPT_DIR}/simulations/supply-chain/vulnerable-dep.sh" \
    "supply-chain"

echo ""
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "Total Tests:        ${TOTAL_TESTS}"
echo -e "Attacks Succeeded:  ${RED}${ATTACKS_SUCCEEDED}${NC} ($(( ATTACKS_SUCCEEDED * 100 / TOTAL_TESTS ))%)"
echo -e "Attacks Blocked:    ${GREEN}${ATTACKS_BLOCKED}${NC} ($(( ATTACKS_BLOCKED * 100 / TOTAL_TESTS ))%)"
echo -e "Attacks Detected:   ${YELLOW}${ATTACKS_DETECTED}${NC} ($(( ATTACKS_DETECTED * 100 / TOTAL_TESTS ))%)"

if [ ${ATTACKS_DETECTED} -gt 0 ]; then
    AVG_MTTD=$((TOTAL_MTTD / ATTACKS_DETECTED))
    echo "Mean Time to Detect: ${AVG_MTTD}s"
else
    echo "Mean Time to Detect: N/A"
fi

echo ""

# Generate JSON report
cat > "${RESULTS_DIR}/summary.json" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "phase": "${PHASE}",
  "total_tests": ${TOTAL_TESTS},
  "attacks_succeeded": ${ATTACKS_SUCCEEDED},
  "attacks_blocked": ${ATTACKS_BLOCKED},
  "attacks_detected": ${ATTACKS_DETECTED},
  "attack_success_rate": $(( ATTACKS_SUCCEEDED * 100 / TOTAL_TESTS )),
  "detection_rate": $(( ATTACKS_DETECTED * 100 / TOTAL_TESTS )),
  "avg_mttd_seconds": $([ ${ATTACKS_DETECTED} -gt 0 ] && echo $((TOTAL_MTTD / ATTACKS_DETECTED)) || echo "null")
}
EOF

# Security assessment
if [ ${ATTACKS_SUCCEEDED} -eq ${TOTAL_TESTS} ]; then
    echo -e "${RED}⚠️  CRITICAL: All attacks succeeded without detection!${NC}"
    echo "Recommendation: Implement security controls (Phase 02-13)"
    exit 1
elif [ ${ATTACKS_SUCCEEDED} -gt $((TOTAL_TESTS / 2)) ]; then
    echo -e "${YELLOW}⚠️  WARNING: More than 50% of attacks succeeded${NC}"
    echo "Recommendation: Continue implementing security controls"
    exit 1
elif [ ${ATTACKS_SUCCEEDED} -gt $((TOTAL_TESTS / 10)) ]; then
    echo -e "${YELLOW}✓ MODERATE: Attack success rate <50%${NC}"
    echo "Recommendation: Focus on detection improvements"
    exit 0
else
    echo -e "${GREEN}✓ EXCELLENT: Attack success rate <10%${NC}"
    echo "Security posture is strong. Continue monitoring."
    exit 0
fi
