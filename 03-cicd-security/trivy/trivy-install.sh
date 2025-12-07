#!/bin/bash
# Trivy instalacija na Ubuntu/Debian sistemima
# Ovaj script instalira Trivy vulnerability scanner

set -e

echo "=== Instalacija Trivy Vulnerability Scanner ==="

# Instalacija potrebnih paketa
sudo apt-get update
sudo apt-get install -y wget apt-transport-https gnupg lsb-release

# Dodavanje Trivy repozitorija
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | \
  sudo tee -a /etc/apt/sources.list.d/trivy.list

# Instalacija Trivy
sudo apt-get update
sudo apt-get install -y trivy

# Verifikacija instalacije
echo ""
echo "=== Trivy instaliran uspješno ==="
trivy --version

echo ""
echo "=== Primjeri korištenja ==="
echo ""
echo "# Skeniranje javne slike"
echo "trivy image nginx:latest"
echo ""
echo "# Skeniranje lokalne slike"
echo "trivy image moja-aplikacija:1.0.0"
echo ""
echo "# Skeniranje sa JSON izlazom"
echo "trivy image -f json -o results.json nginx:latest"
