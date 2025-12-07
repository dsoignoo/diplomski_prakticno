# Baseline Semaphore Deployment

Ovaj direktorij sadrži dokumentaciju i konfiguraciju za **baseline** (osnovni, nezaštićeni) Semaphore deployment na GKE Autopilot cluster.

**VAŽNO**: Ovo je **početno stanje** - deployment bez naprednih sigurnosnih kontrola. Tokom Faza 1-4 ćemo postepeno dodavati sigurnosne layer-e.

## 📊 Trenutno stanje sigurnosti

### ✅ Što već imamo (GKE Autopilot defaults):
- Shielded Nodes (Secure Boot, Integrity Monitoring)
- Encrypted etcd (secrets at rest)
- Private nodes (bez public IP-a)
- Workload Identity (umjesto service account keys)

### ⚠️ Što nam nedostaje (implementiraćemo):
- ❌ **Network Policies** - lateral movement NIJE blokiran
- ❌ **Runtime Security (Falco)** - nema detekcije sumnjivog ponašanja
- ❌ **Image Scanning** - nije blokirano deployment sa CVE
- ❌ **Image Signing** - nije verified integritet images
- ❌ **OPA Gatekeeper** - nema policy enforcement
- ❌ **Pod Security Standards** - privileged podovi dozvoljeni
- ❌ **WAF/Rate Limiting** - nema L7 zaštite
- ❌ **SIEM Integration** - logovi nisu centralizirani

## 🚀 Deployment Semaphore-a

### Preduslovi

1. **GKE Autopilot cluster kreiran** (vidi `02-infrastructure-security/gke-hardened/`)
2. **kubectl konfigurisan**:
   ```bash
   gcloud container clusters get-credentials semaphore-prod \
     --region=us-central1 \
     --project=$PROJECT_ID
   ```
3. **Helm 3+ instaliran**

### Korak 1: Kreiranje namespace-a

```bash
# Kreirati semaphore namespace
kubectl create namespace semaphore

# Label za monitoring
kubectl label namespace semaphore \
  monitoring=enabled \
  security=baseline
```

### Korak 2: Priprema Helm values

Semaphore Helm chart se nalazi u `semaphore/helm-chart/`. Potrebno je kreirati custom values file:

```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno/semaphore/helm-chart

# Kopirati template values
cp values.yaml.in values.yaml

# Generisati Chart.yaml iz template-a
export VERSION="v2.5.0"  # ili najnovija verzija
envsubst < Chart.yaml.in > Chart.yaml
```

**Sadržaj custom-values.yaml** (kreirati u `00-semaphore-baseline/`):

```yaml
# custom-values.yaml - Baseline Semaphore deployment

global:
  ## Semaphore domain
  host: "semaphore.example.com"  # PROMIJENITI na vaš domen

  ## Database konfiguracija
  postgresql:
    enabled: true
    host: "postgresql"
    port: 5432
    database: "semaphore"
    username: "semaphore"
    # Password će biti u Secret-u (zasad plain-text, kasnije External Secrets)
    password: "CHANGE_ME_STRONG_PASSWORD"

  ## Redis konfiguracija
  redis:
    enabled: true
    host: "redis-master"
    port: 6379

  ## RabbitMQ konfiguracija
  rabbitmq:
    enabled: true
    host: "rabbitmq"
    port: 5672
    username: "semaphore"
    password: "CHANGE_ME_STRONG_PASSWORD"

  ## MinIO (S3-compatible storage)
  minio:
    enabled: true
    endpoint: "minio:9000"
    accessKey: "CHANGE_ME"
    secretKey: "CHANGE_ME_STRONG_SECRET"
    bucket: "semaphore-artifacts"

  ## GitHub integration (za CI/CD)
  github:
    enabled: true
    # GitHub App credentials će biti dodani kasnije

## PostgreSQL subchart
postgresql:
  enabled: true
  auth:
    username: semaphore
    password: "CHANGE_ME_STRONG_PASSWORD"
    database: semaphore
  primary:
    persistence:
      enabled: true
      size: 20Gi
    resources:
      requests:
        memory: "256Mi"
        cpu: "250m"
      limits:
        memory: "1Gi"
        cpu: "1000m"

## Redis subchart
redis:
  enabled: true
  auth:
    enabled: false  # Za baseline, kasnije ćemo enable
  master:
    persistence:
      enabled: true
      size: 8Gi
    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "512Mi"
        cpu: "500m"

## RabbitMQ subchart
rabbitmq:
  enabled: true
  auth:
    username: semaphore
    password: "CHANGE_ME_STRONG_PASSWORD"
  persistence:
    enabled: true
    size: 8Gi
  resources:
    requests:
      memory: "256Mi"
      cpu: "250m"
    limits:
      memory: "1Gi"
      cpu: "1000m"

## MinIO subchart
minio:
  enabled: true
  mode: standalone
  rootUser: semaphore
  rootPassword: "CHANGE_ME_STRONG_SECRET"
  persistence:
    enabled: true
    size: 50Gi
  resources:
    requests:
      memory: "256Mi"
      cpu: "250m"
    limits:
      memory: "1Gi"
      cpu: "1000m"

## Semaphore komponente

# Front (Web UI)
front:
  enabled: true
  replicaCount: 2
  image:
    repository: semaphoreui/front
    tag: "v2.5.0"
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "512Mi"
      cpu: "500m"

# Guard (Auth service)
guard:
  enabled: true
  replicaCount: 2
  image:
    repository: semaphoreui/guard
    tag: "v2.5.0"
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "512Mi"
      cpu: "500m"

# Hooks Processor (GitHub webhooks)
hooksProcessor:
  enabled: true
  replicaCount: 2
  image:
    repository: semaphoreui/hooks-processor
    tag: "v2.5.0"
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "512Mi"
      cpu: "500m"

# RBAC Service
rbac:
  enabled: true
  replicaCount: 1
  image:
    repository: semaphoreui/rbac
    tag: "v2.5.0"
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "256Mi"
      cpu: "250m"

## Ingress konfiguracija
ingress:
  enabled: true
  className: "gce"  # GKE Ingress controller
  annotations:
    # Cloud Armor će biti dodato kasnije
    # cert-manager će biti dodato kasnije
  hosts:
    - host: semaphore.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: semaphore-tls
      hosts:
        - semaphore.example.com

## Service Account
serviceAccount:
  create: true
  annotations:
    # Workload Identity annotation će biti dodato kasnije
    # iam.gke.io/gcp-service-account: semaphore-guard@PROJECT_ID.iam.gserviceaccount.com
  name: "semaphore"

## Security Context (baseline - minimalni)
securityContext:
  runAsNonRoot: false  # Neki servisi zahtijevaju root (zasad)
  runAsUser: 1000
  fsGroup: 1000
```

### Korak 3: Deploy Semaphore sa Helm-om

```bash
# Pregled chart-a
helm template semaphore ../semaphore/helm-chart \
  --namespace semaphore \
  --values custom-values.yaml

# Dry-run test
helm install semaphore ../semaphore/helm-chart \
  --namespace semaphore \
  --values custom-values.yaml \
  --dry-run --debug

# Stvarni deployment
helm install semaphore ../semaphore/helm-chart \
  --namespace semaphore \
  --values custom-values.yaml \
  --create-namespace

# Provjera statusa
helm status semaphore -n semaphore
```

### Korak 4: Validacija deployment-a

```bash
# Provjera podova
kubectl get pods -n semaphore

# Expected output (može trajati 2-5 min dok se sve pokrene):
# NAME                                READY   STATUS    RESTARTS
# front-xxxxxxxxx-xxxxx               1/1     Running   0
# guard-xxxxxxxxx-xxxxx               1/1     Running   0
# hooks-processor-xxxxxxxxx-xxxxx     1/1     Running   0
# rbac-xxxxxxxxx-xxxxx                1/1     Running   0
# postgresql-0                        1/1     Running   0
# redis-master-0                      1/1     Running   0
# rabbitmq-0                          1/1     Running   0
# minio-xxxxxxxxx-xxxxx               1/1     Running   0

# Provjera servisa
kubectl get svc -n semaphore

# Provjera Ingress-a
kubectl get ingress -n semaphore

# Provjera logova (primjer za front)
kubectl logs -n semaphore deployment/front --tail=50

# Port-forward za testiranje (dok ne konfigurisemo Ingress sa pravim domenom)
kubectl port-forward -n semaphore svc/front 8080:80

# Pristupiti: http://localhost:8080
```

### Korak 5: Inicijalani setup Semaphore-a

1. Otvoriti http://localhost:8080 (ili konfigurisani domen)
2. Kreirati admin account
3. Konfigurisati GitHub App integration (optional)
4. Kreirati test project

## 📊 Baseline arhitektura

```
┌─────────────────────────────────────────────────────────────┐
│                      INTERNET                                │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│              GKE Ingress Controller (L7)                     │
│               (Cloud Load Balancer)                          │
└────────────────────┬────────────────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          │                     │
┌─────────▼────────┐   ┌────────▼────────┐
│  Front Service   │   │  Guard Service  │
│   (Web UI)       │   │  (Auth)         │
│  2 replicas      │   │  2 replicas     │
└─────────┬────────┘   └────────┬────────┘
          │                     │
          └──────────┬──────────┘
                     │
      ┌──────────────┼──────────────┐
      │              │              │
┌─────▼───────┐ ┌───▼────────┐ ┌──▼──────────┐
│ PostgreSQL  │ │   Redis    │ │  RabbitMQ   │
│ (Primary)   │ │  (Master)  │ │  (Queue)    │
│ PVC: 20Gi   │ │ PVC: 8Gi   │ │ PVC: 8Gi    │
└─────────────┘ └────────────┘ └─────────────┘
```

⚠️ **Sigurnosni problemi u baseline deployment-u:**
1. Nema NetworkPolicy - svi podovi mogu komunicirati međusobno
2. Nema runtime monitoring - ne detektujemo sumnjivo ponašanje
3. Passwords u plain-text u values.yaml
4. Nema image scanning - mogu biti CVE u images
5. Nema WAF - direktan pristup aplikaciji
6. Nema rate limiting - podložan DDoS-u

## 🎯 Sljedeći koraci: Faza 1 implementacija

Nakon uspješnog baseline deployment-a, prelazimo na **Fazu 1: Osnovna sigurnost**:

1. **NetworkPolicies** → `08-network-policies/`
   - Default-deny za semaphore namespace
   - Component-specific policies
   - Testiranje connectivity

2. **Falco Runtime Security** → `06-runtime-security/`
   - Falco DaemonSet deployment
   - Custom rules za Semaphore
   - Alert integration

3. **GKE Backup** → `11-backup-disaster-recovery/`
   - Backup plan konfiguracija
   - Restore testiranje
   - DR runbook

## 📚 Reference

- [Semaphore Docs](https://docs.semaphore.io/)
- [Semaphore GitHub](https://github.com/semaphoreci/semaphore)
- [Helm Chart Documentation](../semaphore/helm-chart/README.md)
