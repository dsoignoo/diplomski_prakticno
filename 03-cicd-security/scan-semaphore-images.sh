#!/bin/bash
# Scan all Semaphore v1.5.0 images for vulnerabilities using Trivy

set -e

REGISTRY="ghcr.io/semaphoreio"
OUTPUT_DIR="./scan-results-$(date +%Y%m%d-%H%M%S)"
TRIVY_BIN="./trivy/trivy"

# Ensure Trivy is installed
if [ ! -f "$TRIVY_BIN" ]; then
  echo "Trivy not found at $TRIVY_BIN. Please run install-trivy.sh first."
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "Scanning Semaphore v1.5.0 container images..."
echo "Output directory: $OUTPUT_DIR"

# Define image list with service name and tag from published helm chart
declare -A IMAGES=(
  ["plumber-public"]="fc0ba626a18ff304660395e1657bb6fb69fbcd96"
  ["public-api"]="9480e60fb47ca8d7caf3cfd7ddcdaa0f5ffd2ced"
  ["artifacthub"]="529ed00cf85b6c99fda207cbbcd774f00592fcca"
  ["audit"]="bd10abf1870c8247bb7b12e922aa865863255066"
  ["auth"]="570873cccc0c443e433697a0efb7a3f33d6f3ecd"
  ["badges"]="ca99da955f57364a0742800c4be606f7273dd5b0"
  ["bootstrapper"]="3dc98d61830f896779dcbc8ac351937a767246a9"
  ["branch_hub"]="f91642321656d85f76624f30dc65df04748d9a8a"
  ["dashboardhub"]="bd10abf1870c8247bb7b12e922aa865863255066"
  ["front"]="c4bdd9c00662df0ccc0f0a5731d81e39b96ea844"
  ["github-notifier"]="ca99da955f57364a0742800c4be606f7273dd5b0"
  ["gofer"]="ca99da955f57364a0742800c4be606f7273dd5b0"
  ["guard"]="71d97737dcd4c147dd48d8971b14a2e0f4b92710"
  ["hooks-processor"]="f3a59a99f766e3424e2ace4af72a51ac0b7d4a0e"
  ["hooks-receiver"]="ca99da955f57364a0742800c4be606f7273dd5b0"
  ["keycloak"]="9d8d8a9fa94b10aa6aae92ce37dfb8b84b2806aa"
  ["keycloak-setup"]="09c3479c1ed0268e616eb1f6efc5560a46901f8c"
  ["periodic-scheduler"]="9480e60fb47ca8d7caf3cfd7ddcdaa0f5ffd2ced"
  ["loghub2"]="f6988855dea477d94a6ab3d00f93e710c54625b2"
  ["github_hooks"]="d54f88485a8ee0b078e70bd39d2ce6b43eeb5c0c"
  ["notifications"]="af028026dce8936799662ef3f99458df5fd6c49b"
  ["plumber"]="e702c50ca730258eca7980f9879f3e1b2c558957"
  ["projecthub"]="9480e60fb47ca8d7caf3cfd7ddcdaa0f5ffd2ced"
  ["projecthub-public"]="9480e60fb47ca8d7caf3cfd7ddcdaa0f5ffd2ced"
  ["pre-flight-checks-hub"]="3facc2c7dd33174f5e50010d3d34820c5bb354b8"
  ["rbac"]="e805920f02975cccc27aca9b7e74a4df0f23b685"
  ["rbac_ee"]="65fe8a59cfdae6e775ba503f298c3a9379a1e976"
  ["public-api-gateway"]="b56bb174d0122b324472379efaf297b69880778a"
  ["repohub"]="7cb53760f53f6b93ce3a5c86ac418edbccb83e84"
  ["repository_hub"]="7e108a16c449af177c925b1c8fab9581f8b5315c"
  ["scouter"]="3facc2c7dd33174f5e50010d3d34820c5bb354b8"
  ["secrethub"]="ca99da955f57364a0742800c4be606f7273dd5b0"
  ["self-hosted-hub"]="377ba70acb65ef3f62559fe828482adcc60a4b3d"
  ["velocity-hub"]="ca99da955f57364a0742800c4be606f7273dd5b0"
  ["zebra"]="f4f1d3a7d3567b091deaf0137eb4dd8e365646dc"
  ["statsd"]="3facc2c7dd33174f5e50010d3d34820c5bb354b8"
  ["encryptor"]="7cb53760f53f6b93ce3a5c86ac418edbccb83e84"
)

TOTAL=${#IMAGES[@]}
COUNT=0
FAILED=0
CRITICAL_CVE_COUNT=0
HIGH_CVE_COUNT=0
MEDIUM_CVE_COUNT=0

# Summary file
SUMMARY_FILE="$OUTPUT_DIR/00-SUMMARY.md"
cat > "$SUMMARY_FILE" << 'EOF'
# Semaphore v1.5.0 Vulnerability Scan Results

## Scan Metadata
- **Scan Date**: $(date +"%Y-%m-%d %H:%M:%S %Z")
- **Scanner**: Trivy
- **Images Scanned**: ${TOTAL}
- **Helm Chart Version**: v1.5.0

## Severity Breakdown

| Severity | Count |
|----------|-------|
EOF

# Scan each image
for SERVICE in "${!IMAGES[@]}"; do
  COUNT=$((COUNT + 1))
  TAG="${IMAGES[$SERVICE]}"
  IMAGE="$REGISTRY/$SERVICE:$TAG"

  echo "[$COUNT/$TOTAL] Scanning $SERVICE ($IMAGE)..."

  # Scan and save results in multiple formats
  if $TRIVY_BIN image \
    --severity HIGH,CRITICAL \
    --format json \
    --output "$OUTPUT_DIR/${SERVICE}.json" \
    "$IMAGE" 2>&1 | tee "$OUTPUT_DIR/${SERVICE}.scan.log"; then

    # Generate human-readable report
    $TRIVY_BIN image \
      --severity HIGH,CRITICAL \
      --format table \
      "$IMAGE" > "$OUTPUT_DIR/${SERVICE}.txt" 2>&1 || true

    echo "✅ Scan completed: $SERVICE"
  else
    echo "❌ Scan failed: $SERVICE"
    FAILED=$((FAILED + 1))
  fi

  echo ""
done

echo "================================"
echo "Scan Summary"
echo "================================"
echo "Total images: $TOTAL"
echo "Successful scans: $((TOTAL - FAILED))"
echo "Failed scans: $FAILED"
echo ""
echo "Detailed results saved to: $OUTPUT_DIR"
echo ""

# Generate aggregate statistics
echo "Analyzing vulnerability counts..."

for SERVICE in "${!IMAGES[@]}"; do
  JSON_FILE="$OUTPUT_DIR/${SERVICE}.json"
  if [ -f "$JSON_FILE" ]; then
    CRITICAL=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$JSON_FILE" 2>/dev/null || echo 0)
    HIGH=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$JSON_FILE" 2>/dev/null || echo 0)
    MEDIUM=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "$JSON_FILE" 2>/dev/null || echo 0)

    CRITICAL_CVE_COUNT=$((CRITICAL_CVE_COUNT + CRITICAL))
    HIGH_CVE_COUNT=$((HIGH_CVE_COUNT + HIGH))
    MEDIUM_CVE_COUNT=$((MEDIUM_CVE_COUNT + MEDIUM))
  fi
done

# Update summary file
cat >> "$SUMMARY_FILE" << EOF
| CRITICAL | $CRITICAL_CVE_COUNT |
| HIGH | $HIGH_CVE_COUNT |
| MEDIUM | $MEDIUM_CVE_COUNT |
| **TOTAL** | **$((CRITICAL_CVE_COUNT + HIGH_CVE_COUNT + MEDIUM_CVE_COUNT))** |

## Next Steps

1. **Review CRITICAL vulnerabilities** - Must be fixed before deployment
2. **Assess HIGH vulnerabilities** - Should be addressed in next sprint
3. **Plan MEDIUM remediation** - Include in backlog

## Security Posture

**Verdict**: ${CRITICAL_CVE_COUNT} CRITICAL vulnerabilities found
- ❌ **BLOCK DEPLOYMENT** if CRITICAL_CVE_COUNT > 0
- ✅ **ALLOW DEPLOYMENT** if CRITICAL_CVE_COUNT == 0

## Detailed Reports

Individual scan results are available in this directory:
- \`*.json\` - Machine-readable JSON format
- \`*.txt\` - Human-readable table format
- \`*.scan.log\` - Full scan logs

## Threat Model Mapping (MITRE ATT&CK)

This scan addresses the following tactics:
- **T1525** (Implant Internal Image) - Prevents malicious images with known CVEs
- **T1195.002** (Compromise Software Supply Chain) - Detects vulnerable dependencies
EOF

echo "✅ Summary report: $SUMMARY_FILE"
echo ""

if [ $CRITICAL_CVE_COUNT -gt 0 ]; then
  echo "❌ CRITICAL: Found $CRITICAL_CVE_COUNT CRITICAL vulnerabilities - DEPLOYMENT BLOCKED"
  exit 1
else
  echo "✅ PASS: No CRITICAL vulnerabilities detected - deployment allowed"
  exit 0
fi
