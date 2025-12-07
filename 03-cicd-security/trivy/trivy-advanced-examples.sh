#!/bin/bash
# Trivy napredne opcije skeniranja
# Primjeri naprednog korištenja Trivy vulnerability scannera

set -e

# Varijable
IMAGE="${IMAGE:-nginx:latest}"
OUTPUT_DIR="${OUTPUT_DIR:-./scan-results}"

mkdir -p "$OUTPUT_DIR"

echo "=== Trivy Napredne Opcije Skeniranja ==="
echo "Target: $IMAGE"
echo ""

# 1. Skeniranje sa ignorisanjem nerješenih ranjivosti
echo "--- Skeniranje bez unfixed ranjivosti ---"
trivy image --ignore-unfixed "$IMAGE"

# 2. Skeniranje s fokusom samo na kritične i visoke ranjivosti
echo ""
echo "--- Samo HIGH i CRITICAL ranjivosti ---"
trivy image --severity CRITICAL,HIGH "$IMAGE"

# 3. Generisanje izvještaja u JSON formatu
echo ""
echo "--- Generisanje JSON izvještaja ---"
trivy image -f json -o "$OUTPUT_DIR/results.json" "$IMAGE"
echo "JSON izvještaj sačuvan u: $OUTPUT_DIR/results.json"

# 4. Skeniranje s provjerom licence
echo ""
echo "--- Skeniranje ranjivosti i licenci ---"
trivy image --scanners vuln,license "$IMAGE"

# 5. Skeniranje konfiguracija (IaC)
echo ""
echo "--- Skeniranje konfiguracija (ako je primjenjivo) ---"
if [ -d "./kubernetes" ]; then
    trivy config --severity CRITICAL,HIGH ./kubernetes
else
    echo "Nema kubernetes/ direktorija za skeniranje konfiguracija"
fi

# 6. Table format sa detaljima
echo ""
echo "--- Detaljni tabelarni prikaz ---"
trivy image --format table --severity HIGH,CRITICAL "$IMAGE"

# 7. SARIF format za integraciju sa IDE/GitHub
echo ""
echo "--- SARIF format za GitHub Security ---"
trivy image -f sarif -o "$OUTPUT_DIR/results.sarif" "$IMAGE"
echo "SARIF izvještaj sačuvan u: $OUTPUT_DIR/results.sarif"

# 8. HTML izvještaj
echo ""
echo "--- HTML izvještaj ---"
trivy image -f template --template "@contrib/html.tpl" -o "$OUTPUT_DIR/results.html" "$IMAGE" 2>/dev/null || \
    echo "HTML template nije dostupan, preskačem..."

# 9. Exit code za CI/CD - kritične ranjivosti blokiraju build
echo ""
echo "--- CI/CD Check - Exit code 1 ako ima CRITICAL ---"
trivy image --exit-code 1 --severity CRITICAL "$IMAGE" && \
    echo "PASS: Nema kritičnih ranjivosti" || \
    echo "FAIL: Pronađene kritične ranjivosti"

echo ""
echo "=== Skeniranje završeno ==="
echo "Rezultati su sačuvani u: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
