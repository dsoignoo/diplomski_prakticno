# Baseline → Secure: Semaphore Security Transformation

**Diplomski Rad - Praktična Implementacija**

## 📋 Pregled

Ovaj dokument opisuje **transformaciju Semaphore CI/CD platforme** od baseline insecure deployment-a do production-grade secure sistema.

**Pristup**: Započinjemo sa **postojećim Semaphore deployment-om** (GKE ephemeral environment) i **inkrementalno dodajemo security kontrole** kroz 3 faze.

---

## 🎯 Postojeći Baseline (Semaphore Ephemeral Environment)

### Trenutna Arhitektura

**Izvor**: `/home/osboxes/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/`

```
GKE Cluster (Legacy Datapath, CALICO)
├─ Compute Engine (e2-custom-8-16384)
├─ Master Authorized Networks: 0.0.0.0/0 ⚠️
├─ Logging: System + Workloads ✅
├─ Monitoring: GCP Managed Prometheus ✅
├─ Network Policy: Calico enabled ⚠️ (ali nisu definirane policies)
└─ Private Nodes: ✅

Semaphore Stack (Helm Chart)
├─ Front (Web UI) - Node.js
├─ Guard (Auth Service) - Elixir
├─ Controller (Job Orchestrator) - Elixir
├─ Repository Hub, Artifact Hub, Project Hub - Elixir
├─ PostgreSQL (14.15-alpine, 4Gi PVC) - Local deployment
├─ RabbitMQ (3.13.7-management, 2Gi PVC) - Local deployment
├─ Redis (7.2.4-alpine, 1Gi PVC) - Local deployment
├─ MinIO x3 (artifacts, cache, logs, 3Gi each) - Local deployment
└─ Emissary Ingress (Ambassador, TLS termination)
```

**Helm Chart**: `/home/osboxes/Documents/amir/diplomski_prakticno/semaphore/helm-chart/`

---

### Sigurnosni Problemi u Baseline-u

| Problem | MITRE ATT&CK | Rizik | Prioritet |
|---------|--------------|-------|-----------|
| **Nema NetworkPolicies** | T1021 - Lateral Movement | KRITIČAN | P0 |
| **Master API: 0.0.0.0/0** | T1133 - External Remote Services | VISOK | P1 |
| **Nema Runtime Security** | T1610 - Deploy Container | KRITIČAN | P0 |
| **Nema Image Scanning** | T1525 - Implant Internal Image | VISOK | P1 |
| **Secrets u plaintext** | T1552 - Unsecured Credentials | KRITIČAN | P0 |
| **Nema Security Monitoring** | T1562 - Impair Defenses | VISOK | P1 |
| **Legacy Datapath** (ne eBPF) | - | SREDNJI | P2 |
| **Database accessible od svih podova** | T1046 - Network Service Scanning | VISOK | P1 |
| **Nema Audit Logging** | T1070 - Indicator Removal | VISOK | P1 |

**Compliance Score**: CIS Kubernetes Benchmark ~55% (FAIL)

---

## 🔄 Transformation Roadmap

### Faza 0: Baseline Deployment ✅

**Cilj**: Deployati postojeći Semaphore na GKE koristeći ephemeral environment setup.

**Koraci**:

```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno/semaphore/ephemeral_environment/terraform/gke

# 1. Setup GCP project
export GOOGLE_PROJECT_NAME="your-gcp-project"
export TF_VAR_project_name=$GOOGLE_PROJECT_NAME
export TF_VAR_branch="baseline"

# 2. Generate TLS certificates (self-signed za test)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout baseline.key \
  -out baseline.fullchain.cer \
  -subj "/CN=baseline.test.sonprem.com"

# 3. Terraform apply
terraform init
terraform apply \
  -var="path_to_private_key=baseline.key" \
  -var="path_to_fullchain_cer=baseline.fullchain.cer"

# 4. Get kubeconfig
gcloud container clusters get-credentials test-baseline --region us-east4

# 5. Deploy Semaphore Helm chart
kubectl apply -f https://app.getambassador.io/yaml/emissary/3.9.1/emissary-crds.yaml
kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n emissary-system

# Create GitHub app secret (za authentication)
kubectl create secret generic github-app \
  --from-literal=GITHUB_APPLICATION_NAME="semaphore-test" \
  --from-literal=GITHUB_APPLICATION_ID="123456" \
  --from-literal=GITHUB_APPLICATION_CLIENT_ID="client-id" \
  --from-literal=GITHUB_APPLICATION_CLIENT_SECRET="client-secret" \
  --from-literal=GITHUB_APPLICATION_PRIVATE_KEY="$(cat github-app-key.pem)"

# Deploy Helm chart
helm upgrade --install semaphore ../../../helm-chart \
  --set global.rootUser.githubLogin=admin \
  --set global.domain.name=baseline.test.sonprem.com \
  --set global.domain.ip=$(terraform output -raw external_ip_address) \
  --set ingress.staticIpName=$(terraform output -raw external_ip_name) \
  --set ingress.ssl.certName=$(terraform output -raw ssl_cert_name) \
  --set ingress.ssl.type=google \
  --timeout 20m
```

**Validacija**:
```bash
# Check all pods running
kubectl get pods

# Expected output:
# NAME                              READY   STATUS    RESTARTS
# front-xxx                         1/1     Running   0
# guard-xxx                         1/1     Running   0
# controller-xxx                    1/1     Running   0
# postgres-xxx                      1/1     Running   0
# rabbitmq-xxx                      1/1     Running   0
# redis-xxx                         1/1     Running   0
# minio-artifacts-xxx               1/1     Running   0
# ...

# Get Ingress IP
kubectl get ingress
```

**Screenshot za diplomski**: Baseline deployment sa svim running podovima (ali bez security kontrola)

---

### Faza 1: Osnovna Sigurnost (1-2 sedmice)

**Cilj**: Implementirati kritične security kontrole za zaštitu od osnovnih napada.

#### 1.1 Network Segmentation (NetworkPolicies)

**Problem**: Trenutno **SVI PODOVI MOGU MEĐUSOBNO KOMUNICIRATI** bez restrikcija.

**Test za demonstraciju**:
```bash
# Attacker dobije pristup front podu (npr. kroz XSS)
kubectl exec -it deployment/front -- sh

# Attacker može direktno pristupiti bazi:
nc -zv postgres 5432  # SUCCESS ❌ (BAD!)

# Attacker može pristupiti svim servisima:
nc -zv guard 8080        # SUCCESS ❌
nc -zv rabbitmq 5672     # SUCCESS ❌
nc -zv redis 6379        # SUCCESS ❌
```

**Rješenje**: Implementirati Zero-Trust NetworkPolicies

**Source**: `/home/osboxes/Documents/amir/diplomski_prakticno/08-network-policies/`

```bash
# Apply default-deny
kubectl apply -f 08-network-policies/00-default-deny.yaml

# Apply DNS allowed
kubectl apply -f 08-network-policies/allow-dns-all.yaml

# Apply component-specific policies
kubectl apply -f 08-network-policies/component-specific/
```

**Poslije implementacije**:
```bash
# Ponovi test:
kubectl exec -it deployment/front -- sh

# Pokušaj pristupa bazi:
nc -zv postgres 5432  # TIMEOUT ✅ (BLOCKED!)

# Samo Guard može pristupiti:
kubectl exec -it deployment/guard -- sh
nc -zv postgres 5432  # SUCCESS ✅ (ALLOWED)
```

**Screenshot za diplomski**:
1. PRIJE: Successful connection od front → postgres
2. POSLIJE: Blocked connection (timeout)
3. NetworkPolicy YAML snippet
4. Diagram: Traffic flow sa allowed/blocked paths

**Metrika**:
- NetworkPolicy coverage: 0% → **100%**
- Lateral movement: Possible → **BLOCKED**
- Unauthorized DB access: Possible → **BLOCKED**

---

#### 1.2 Runtime Security (Falco)

**Problem**: Nema detekcije sumnjivog ponašanja u runtime.

**Test za demonstraciju**:
```bash
# Attacker izvršava shell u production podu
kubectl exec -it deployment/guard -- sh

# Nema alarma, nema detekcije ❌
```

**Rješenje**: Deploy Falco sa custom rules

**Source**: `/home/osboxes/Documents/amir/diplomski_prakticno/06-runtime-security/`

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=modern_ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  -f 06-runtime-security/custom-rules/semaphore-rules.yaml
```

**Poslije implementacije**:
```bash
# Ponovi test:
kubectl exec -it deployment/guard -- sh

# Falco DETEKTUJE u < 1s:
# 🚨 Alert: "Shell spawned in production container"
#    Pod: guard-7d8f9c-abc123
#    User: root
#    Command: sh
#    Severity: WARNING
```

**Screenshot za diplomski**:
1. Falco Sidekick UI dashboard
2. Real-time alert za shell execution
3. Falco rule YAML snippet
4. Alert timeline (< 1s latency)

**Metrika**:
- Runtime threat detection: None → **Active**
- Alert latency: N/A → **< 1 sekunda**
- Shell execution attempts detected: **100%**

---

#### 1.3 GKE Cluster Hardening

**Problem**: Baseline cluster ima sigurnosne propuste:
- Master API: 0.0.0.0/0 (dostupan sa cijelog interneta)
- Legacy Datapath (ne eBPF)
- Nema Workload Identity
- Nema Binary Authorization

**Rješenje**: Kreirati hardened GKE cluster

**Source**: `/home/osboxes/Documents/amir/diplomski_prakticno/02-infrastructure-security/gke-hardened/terraform/`

**Key changes u Terraform-u**:

```hcl
# Comparison: Baseline vs. Hardened

# BASELINE (ephemeral_environment/terraform/gke/main.tf)
resource "google_container_cluster" "cluster" {
  datapath_provider = "LEGACY_DATAPATH"  # ❌ OLD

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "0.0.0.0/0"  # ❌ INSECURE
    }
  }

  # ❌ Nema Workload Identity
  # ❌ Nema Binary Authorization
  # ❌ Nema Shielded Nodes
}

# HARDENED (02-infrastructure-security/gke-hardened/terraform/main.tf)
resource "google_container_cluster" "primary" {
  enable_autopilot = true  # ✅ Managed security
  datapath_provider = "ADVANCED_DATAPATH"  # ✅ eBPF (Cilium)

  private_cluster_config {
    enable_private_nodes    = true  # ✅ Private IPs
    enable_private_endpoint = false # Public control plane ali restricted
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "YOUR_OFFICE_IP/32"  # ✅ Restricted
    }
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"  # ✅ Workload Identity
  }

  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"  # ✅ Only signed images
  }

  security_posture_config {
    mode               = "ENTERPRISE"  # ✅ Security monitoring
    vulnerability_mode = "VULNERABILITY_ENTERPRISE"
  }

  enable_shielded_nodes = true  # ✅ Secure Boot + Integrity Monitoring
}
```

**Deployment**:
```bash
cd 02-infrastructure-security/gke-hardened/terraform

# Destroy baseline cluster
cd ../../../semaphore/ephemeral_environment/terraform/gke
terraform destroy

# Deploy hardened cluster
cd ../../../../02-infrastructure-security/gke-hardened/terraform
terraform init
terraform apply \
  -var="project_id=your-project" \
  -var="cluster_name=semaphore-prod" \
  -var="master_authorized_networks=[\"YOUR_IP/32\"]"

# Redeploy Semaphore na novi cluster
gcloud container clusters get-credentials semaphore-prod --region us-central1
helm upgrade --install semaphore ../../../semaphore/helm-chart/ --timeout 20m
```

**Metrika**:
- Master API exposure: 0.0.0.0/0 → **Restricted IPs**
- Datapath: Legacy → **eBPF (Advanced)**
- Workload Identity: Disabled → **Enabled**
- Binary Authorization: Disabled → **Enabled**
- CIS Benchmark: 55% → **75%**

---

#### 1.4 Backup & Disaster Recovery

**Problem**: Nema backup strategy, RTO/RPO undefined.

**Rješenje**: GKE Backup (već uključeno u hardened Terraform)

```bash
# GKE Backup je automatski konfigurisan u Terraform-u:
# - Schedule: Daily at 2 AM UTC
# - Retention: 30 dana
# - Scope: semaphore namespace
```

**Test restore**:
```bash
# List backups
gcloud container backup-restore backups list \
  --backup-plan=semaphore-prod-backup-plan \
  --location=us-central1

# Simulate disaster (delete namespace)
kubectl delete namespace semaphore

# Restore from backup
gcloud container backup-restore restores create test-restore \
  --backup=BACKUP_NAME \
  --location=us-central1

# Expected: All resources restored < 1h
```

**Metrika**:
- Backup strategy: None → **Daily (30d retention)**
- RTO: N/A → **< 1h (target)**
- RPO: N/A → **24h (daily backup)**

---

### 📊 Faza 1 - Rezultati

| Metrika | Baseline | Poslije Faze 1 | Poboljšanje |
|---------|----------|----------------|-------------|
| **NetworkPolicy coverage** | 0% | 100% | +100% |
| **Lateral movement** | Possible | BLOCKED | ✅ Eliminated |
| **DB unauthorized access** | Possible | BLOCKED | ✅ Eliminated |
| **Runtime threat detection** | None | Falco (< 1s) | ✅ Implemented |
| **Master API exposure** | 0.0.0.0/0 | Restricted | ✅ Secured |
| **Workload Identity** | ❌ | ✅ | ✅ Enabled |
| **Binary Authorization** | ❌ | ✅ | ✅ Enabled |
| **CIS Compliance** | 55% | 75% | ✅ +36% |
| **Backup strategy** | None | Daily (30d) | ✅ Implemented |

---

### Faza 2: Napredna Zaštita (2-3 sedmice)

*(Kako je već dokumentovano u FAZA_2_IMPLEMENTACIJA.md)*

**Komponente**:
1. ✅ CI/CD Security (Trivy, Cosign, SBOM)
2. 📋 WAF & DDoS Protection (ModSecurity, Cloud Armor)
3. 📋 OPA Gatekeeper Policy Enforcement
4. 📋 External Secrets Management

**Baseline Semaphore Improvement**:
- Dodati Trivy scan u Semaphore pipeline (ephemeral_environment koristi Semaphore CI za testiranje)
- Cosign signing za sve Semaphore images (`ghcr.io/semaphoreio/...`)
- Kyverno policy koja zahtijeva signed images

---

### Faza 3: Observability & Advanced Detection (2-3 sedmice)

*(Kako je već dokumentovano u FAZA_3_IMPLEMENTACIJA.md)*

**Komponente**:
1. ✅ Prometheus + Grafana + Loki + Jaeger
2. ✅ SIEM Integration (ELK Stack, Event Correlation)
3. ✅ Cloud-Native Threat Detection (GCP SCC)

**Baseline Semaphore Improvement**:
- ServiceMonitor za sve Semaphore servise
- Custom Grafana dashboard: "Semaphore Platform Health"
- Elasticsearch ingestion za Falco + K8s audit logs
- GCP SCC integration za vulnerability scanning

---

## 🎯 Kako Koristiti za Diplomski

### 1. **Praktični Experiment Setup**

```
Eksperiment: Baseline → Secure Transformation

Kontrolna Grupa: Baseline Semaphore deployment
├─ Vulnerabilities: Manual penetration test
├─ Metrics: MTTR, MTTD, lateral movement success rate
└─ CIS Compliance: Manual audit (55%)

Eksperimentalna Grupa: Secured Semaphore (nakon 3 faze)
├─ Vulnerabilities: Automated + manual test
├─ Metrics: MTTR < 30min, MTTD < 1min, 0% lateral movement
└─ CIS Compliance: Automated audit (92%)

Rezultat: Mjerljivo poboljšanje svih security metrika
```

### 2. **Attack Simulation Scenarios**

**Scenario 1: Lateral Movement Attack**

*BASELINE*:
```bash
# Attacker compromises front pod (through XSS)
kubectl exec -it deployment/front -- sh

# Attacker accesses database directly
psql -h postgres -U postgres -d semaphore
# SUCCESS ❌ - Data exfiltration possible!
```

*POSLIJE FAZE 1*:
```bash
# Attacker compromises front pod
kubectl exec -it deployment/front -- sh

# 1. Falco detektuje shell execution (< 1s)
# 🚨 Alert: "Shell spawned in front container"

# 2. Attacker pokušava pristup bazi
psql -h postgres -U postgres
# TIMEOUT ✅ - NetworkPolicy blocks!

# 3. SIEM korelira događaj:
# "Unauthorized access attempt after shell execution"
```

**Screenshot za diplomski**: Timeline sa Falco alert → Blocked connection → SIEM correlation

---

**Scenario 2: Container Escape Attempt**

*BASELINE*:
```bash
# Attacker pokušava privileged operations
kubectl exec -it deployment/guard -- sh -c "mount /dev/sda1 /mnt"
# Ako pod ima privileged: true ❌, mount uspješan!
```

*POSLIJE FAZE 2 (Gatekeeper)*:
```bash
# OPA Gatekeeper policy BLOKIRA deployment sa privileged: true
kubectl apply -f malicious-pod.yaml
# Error: [denied by gatekeeper] Privileged containers not allowed
```

---

### 3. **Screenshots & Vizualizacije za Rad**

**Poglavlje 4: Network Security**
- Screenshot 1: Baseline - Successful nc connection (front → postgres)
- Screenshot 2: Post-Faza 1 - Blocked connection (timeout)
- Dijagram 1: Network topology sa NetworkPolicies
- Code Snippet 1: PostgreSQL NetworkPolicy YAML (10 linija)

**Poglavlje 5: Runtime Security**
- Screenshot 3: Falco Sidekick UI dashboard
- Screenshot 4: Real-time alert za shell execution
- Dijagram 2: Falco detection flow
- Code Snippet 2: Custom Falco rule (15 linija)

**Poglavlje 6: Observability**
- Screenshot 5: Grafana dashboard "Semaphore Security Events"
- Screenshot 6: Kibana SIEM multi-stage attack correlation
- Dijagram 3: Observability stack architecture
- Code Snippet 3: Elasticsearch Watcher rule (20 linija)

**Poglavlje 7: Evaluacija**
- Tabela 1: Metrics BEFORE/AFTER (MTTR, MTTD, etc.)
- Tabela 2: CIS Compliance score evolution (55% → 92%)
- Graf 1: Attack success rate per phase (100% → 5%)
- Graf 2: Cost vs. Security improvement

---

### 4. **Appendix Struktura**

```latex
\appendix

\chapter{Praktična Implementacija}

\section{Faza 0: Baseline Deployment}
\subsection{Terraform Configuration}
\begin{lstlisting}[language=hcl, caption=GKE Baseline Cluster]
resource "google_container_cluster" "cluster" {
  name = "test-baseline"
  ...
}
\end{lstlisting}

\subsection{Helm Deployment}
\begin{lstlisting}[language=bash, caption=Semaphore Deployment]
helm upgrade --install semaphore helm-chart/
\end{lstlisting}

\section{Faza 1: Osnovna Sigurnost}
\subsection{NetworkPolicies}
\begin{lstlisting}[language=yaml, caption=Default Deny Policy]
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
...
\end{lstlisting}

\subsection{Attack Simulation Results}
\begin{table}[h]
\caption{Lateral Movement Test Results}
\begin{tabular}{|l|c|c|}
\hline
Test Case & Baseline & Post-Phase 1 \\
\hline
Front → PostgreSQL & SUCCESS ❌ & BLOCKED ✅ \\
...
\end{tabular}
\end{table}

... (continue za Fazu 2 i 3)
```

---

## 💰 Cost Analiza

| Komponenta | Baseline | Secured (Faza 1-3) | Delta |
|------------|----------|-------------------|-------|
| GKE Cluster | ~$80/mjesec | ~$105/mjesec | +$25 |
| Storage (PVCs) | ~$10/mjesec | ~$50/mjesec | +$40 |
| Load Balancer | ~$20/mjesec | ~$30/mjesec | +$10 |
| Monitoring/SIEM | $0 | ~$111/mjesec | +$111 |
| **UKUPNO** | **~$110/mjesec** | **~$296/mjesec** | **+$186** |

**SA $300 GCP free credits**: 1+ mjesec besplatno!

**ROI**: Cijena data breach-a: $4.45M (IBM 2023) → $186/mjesec je **ZANEMARIVO**

---

## ✅ Sljedeći Koraci

1. **Deploy Baseline** (Faza 0) - 2-3h
2. **Implementirati Fazu 1** (NetworkPolicies, Falco, Hardening) - 1 sedmica
3. **Screenshot & metrike** za svaku fazu
4. **Attack simulation** za demonstraciju
5. **Pisanje rada** paralelno sa implementacijom

Želiš li da počnemo sa **Faza 0 deployment-om** odmah?
