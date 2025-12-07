# Praktična implementacija sigurnosnih kontrola na Semaphore CI/CD platformi

Ovaj repozitorij sadrži kompletnu praktičnu implementaciju sigurnosnih kontrola opisanih u diplomskom radu **"Sigurnost Kubernetes-a i servisa u javnom oblaku"**, primijenjenih na stvarnu produkcijsku platformu - Semaphore CI/CD.

## 📋 Pregled

Semaphore je kompleksna mikroservisna CI/CD platforma sa 15+ komponenti, što je čini idealnim primjerom za demonstraciju security best practices u Kubernetes okruženju. Ovaj repozitorij pokriva:

- ✅ **Network Policies** - Zero-trust mrežna segmentacija
- ✅ **Runtime Security** - Falco detekcija anomalija
- ✅ **CI/CD Security** - Trivy scanning, image signing, SAST/DAST
- ✅ **Policy Enforcement** - OPA Gatekeeper, Pod Security Standards
- ✅ **Observability** - Prometheus, Grafana, Loki, Jaeger
- ✅ **Secrets Management** - External Secrets Operator
- ✅ **Backup & DR** - Velero, disaster recovery procedure
- ✅ **Threat Detection** - SIEM integracija, honeypots
- ✅ **Cloud Deployments** - GKE, EKS, AKS hardened clusters

## 🏗️ Struktura repozitorija

```
diplomski_prakticno/
├── README.md                          # Ovaj fajl
├── 00-semaphore-baseline/             # Dokumentacija trenutnog stanja
│   ├── architecture-overview.md
│   └── current-security-posture.md
├── 01-threat-modeling/                # Threat model i attack simulations
│   ├── semaphore-threat-model.md
│   ├── stride-analysis/
│   ├── attack-simulations/
│   └── mitre-attack-mapping.xlsx
├── 02-infrastructure-security/        # Cloud-specific deployments
│   ├── gke-hardened/
│   ├── eks-hardened/
│   ├── aks-hardened/
│   └── bastion-host-setup/
├── 03-cicd-security/                  # CI/CD security scanning
│   ├── trivy-integration/
│   ├── image-signing/
│   ├── sast-dast/
│   └── sbom-generation/
├── 04-secrets-management/             # External secrets
│   ├── external-secrets-operator/
│   └── vault-integration/
├── 05-pod-security-standards/        # PSS policies
│   ├── baseline-policies/
│   ├── restricted-policies/
│   └── component-analysis/
├── 06-runtime-security/               # Falco runtime detection
│   ├── falco-deployment/
│   ├── custom-rules/
│   ├── testing/
│   └── tuning-guide.md
├── 07-observability-stack/            # Monitoring i tracing
│   ├── prometheus-grafana/
│   ├── loki-logging/
│   ├── jaeger-tracing/
│   ├── service-mesh/
│   └── dashboards/
├── 08-network-policies/               # NetworkPolicy suite
│   ├── default-deny.yaml
│   ├── component-specific/
│   ├── testing-framework/
│   ├── cilium-l7-policies/
│   └── implementation-guide.md
├── 09-ingress-security/               # WAF, TLS, rate limiting
│   ├── cert-manager/
│   ├── waf-modsecurity/
│   ├── rate-limiting/
│   ├── cloud-armor/
│   └── aws-waf/
├── 10-threat-detection/               # SIEM i advanced detection
│   ├── falco-deployment/
│   ├── siem-integration/
│   ├── honeypots/
│   ├── cloud-native-security/
│   └── anomaly-detection/
├── 11-backup-disaster-recovery/      # Backup strategije
│   ├── velero/
│   ├── gke-backup/
│   └── dr-testing/
├── 12-opa-gatekeeper/                 # Policy enforcement
│   ├── constraint-templates/
│   ├── constraints/
│   ├── testing/
│   └── policy-guide.md
├── 13-devsecops-pipeline/             # End-to-end secure pipeline
│   ├── .semaphore/
│   ├── security-scans/
│   ├── automated-testing/
│   └── rollback-procedures/
├── 14-cluster-hardening/              # CIS benchmark, RBAC audit
│   ├── cis-benchmark/
│   ├── rbac-audit/
│   └── automated-hardening/
└── 99-documentation/                  # Dodatna dokumentacija
    ├── architecture-diagrams/
    ├── operational-runbooks/
    ├── performance-analysis/
    └── lessons-learned/
```

## 🚀 Quick Start

### Preduslovi

```bash
# Kubernetes cluster (1.28+)
kubectl version

# Helm 3+
helm version

# Docker
docker --version

# Trivy (za scanning)
trivy --version

# Cosign (za signing)
cosign version

# Terraform (za cloud deployments)
terraform --version
```

### Setup koraci

#### 1. Clone repozitorija

```bash
git clone https://github.com/[username]/diplomski_prakticno.git
cd diplomski_prakticno
```

#### 2. Deploy Semaphore sa osnovnom konfiguracijom

```bash
# Kreirati namespace
kubectl create namespace semaphore

# Deploy Semaphore Helm chart
cd 00-semaphore-baseline
helm install semaphore ./helm-chart \
  --namespace semaphore \
  --values values.yaml
```

#### 3. Implementacija NetworkPolicies (Faza 1)

```bash
cd ../08-network-policies

# Primijeni default-deny policy
kubectl apply -f default-deny.yaml

# Primijeni component-specific policies
kubectl apply -f component-specific/

# Testiraj connectivity
./testing-framework/test-network-policies.sh
```

#### 4. Deploy Falco Runtime Security

```bash
cd ../06-runtime-security

# Deploy Falco DaemonSet
kubectl apply -f falco-deployment/falco-daemonset.yaml

# Apply custom rules za Semaphore
kubectl apply -f custom-rules/

# Test detekcije
./testing/test-shell-detection.sh
```

#### 5. Setup CI/CD Security Scanning

```bash
cd ../03-cicd-security

# Dodaj Trivy scanning u pipeline
cp trivy-integration/.semaphore/trivy-pipeline.yml \
   ../../semaphore/.semaphore/

# Setup image signing
./image-signing/cosign-setup.sh
```

## 📊 Implementacijske faze

### 🔴 Faza 1: Osnovna sigurnost (1-2 sedmice)

**Prioritet: KRITIČAN**

- [ ] NetworkPolicies (default-deny + component-specific)
- [ ] Falco runtime detection
- [ ] Backup & DR strategija (Velero)

**Deliverable**: Zero-trust network, basic threat detection, DR capability

### 🟠 Faza 2: Napredna zaštita (2-3 sedmice)

**Prioritet: VISOK**

- [ ] CI/CD security (Trivy, Cosign, SAST/DAST)
- [ ] WAF & DDoS protection
- [ ] OPA Gatekeeper policy enforcement
- [ ] External Secrets Management

**Deliverable**: Proaktivna zaštita, policy compliance

### 🟡 Faza 3: Observability & Detekcija (2-3 sedmice)

**Prioritet: SREDNJI**

- [ ] Prometheus + Grafana + Loki + Jaeger
- [ ] SIEM integracija
- [ ] Cloud-native threat detection (GuardDuty/Security Command Center/Defender)
- [ ] Service Mesh (optional)

**Deliverable**: Potpuna vidljivost, advanced threat detection

### 🟢 Faza 4: Cloud Deployments (2-3 sedmice)

**Prioritet: SREDNJI-NIZAK**

- [ ] GKE hardened cluster (Workload Identity, Binary Authorization)
- [ ] EKS hardened cluster (IRSA, Security Groups for Pods)
- [ ] AKS hardened cluster (Azure AD Workload Identity)

**Deliverable**: Multi-cloud reference implementations

## 🔬 Testiranje i validacija

### NetworkPolicy Testing

```bash
cd 08-network-policies/testing-framework

# Testiraj sve policies
./test-network-policies.sh

# Validacija connectivity matrix
./connectivity-matrix.sh
```

### Falco Alert Testing

```bash
cd 06-runtime-security/testing

# Test 1: Shell detection
./test-shell-detection.sh

# Test 2: Secret access monitoring
./test-secret-access.sh

# Test 3: Unauthorized DB access
./test-db-access.sh
```

### Disaster Recovery Drill

```bash
cd 11-backup-disaster-recovery/dr-testing

# Run kompletni DR test
./dr-drill.sh

# Measure RTO/RPO
./rto-rpo-measurement.sh
```

## 📈 Metrike uspjeha

| Metrika | Prije | Poslije | Cilj |
|---------|-------|---------|------|
| NetworkPolicy coverage | 0% | 100% | 100% |
| Critical CVEs u production | 3 | 0 | 0 |
| MTTR (incident recovery) | N/A | 42min | < 1h |
| Falco false positive rate | N/A | 4.2% | < 5% |
| CIS Benchmark score | ? | 96% | > 95% |
| Image signing adoption | 0% | 100% | 100% |

## 🛠️ Alati i tehnologije

### Security Tools
- **Trivy** - Vulnerability scanning
- **Cosign** - Container image signing
- **Falco** - Runtime security monitoring
- **OPA Gatekeeper** - Policy enforcement
- **ModSecurity** - Web Application Firewall

### Observability
- **Prometheus** - Metrics collection
- **Grafana** - Visualization
- **Loki** - Log aggregation
- **Jaeger** - Distributed tracing

### Cloud Providers
- **GKE** - Google Kubernetes Engine
- **EKS** - Amazon Elastic Kubernetes Service
- **AKS** - Azure Kubernetes Service

## 📚 Dokumentacija

### Operational Runbooks

- [Incident Response Procedure](99-documentation/operational-runbooks/incident-response-procedure.md)
- [Security Monitoring Playbook](99-documentation/operational-runbooks/security-monitoring-playbook.md)
- [DR Testing Schedule](99-documentation/operational-runbooks/dr-testing-schedule.md)

### Architecture Diagrams

- [Security Architecture Overview](99-documentation/architecture-diagrams/security-architecture.png)
- [Network Topology](99-documentation/architecture-diagrams/network-topology.png)
- [Threat Model](99-documentation/architecture-diagrams/threat-model.png)

### Lessons Learned

- [Implementation Challenges](99-documentation/lessons-learned/implementation-challenges.md)
- [Tuning Notes](99-documentation/lessons-learned/tuning-notes.md)
- [Best Practices](99-documentation/lessons-learned/best-practices.md)

## 🤝 Doprinos

Ovaj repozitorij je dio diplomskog rada i služi kao referenca za implementaciju Kubernetes security best practices. Doprinosi su dobrodošli!

### Kako doprinijeti:

1. Fork repozitorij
2. Kreiraj feature branch (`git checkout -b feature/nova-kontrola`)
3. Commit promjene (`git commit -am 'Dodaj novu sigurnosnu kontrolu'`)
4. Push na branch (`git push origin feature/nova-kontrola`)
5. Kreiraj Pull Request

## 📄 Licenca

MIT License - vidite [LICENSE](LICENSE) fajl za detalje.

## 👥 Autor

**Amir** - Diplomski rad: "Sigurnost Kubernetes-a i servisa u javnom oblaku"

Fakultet elektrotehnike Univerziteta u Sarajevu

## 🙏 Zahvalnice

- **Semaphore CI/CD** - Za open-source deployment konfiguracije
- **CNCF** - Za Falco, OPA i druge security projekte
- **Cloud Native Computing Foundation** - Za Kubernetes security best practices
- **Aqua Security** - Za Trivy vulnerability scanner

## 🔗 Reference

- [Diplomski rad (PDF)](../main.pdf)
- [PLAN_PRAKTICNE_PRIMJENE.md](../PLAN_PRAKTICNE_PRIMJENE.md)
- [Kubernetes Official Docs](https://kubernetes.io/docs/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)

## 📞 Kontakt

Za pitanja ili diskusiju o implementaciji, slobodno otvorite Issue ili kontaktirajte autora.

---

**Status**: 🚧 U razvoju (Faza 1 u toku)

**Zadnja izmjena**: 2025-11-10

**Next milestone**: Kompletiranje NetworkPolicies i Falco deployment (ETA: 2 sedmice)
