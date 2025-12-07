# Phase 07: Observability Stack - Implementation Guide

## Overview

This phase implements a comprehensive observability stack for the Semaphore platform deployed on the hardened GKE cluster. The stack includes metrics collection (Prometheus), visualization (Grafana), and log aggregation (Loki + Promtail).

## Components Deployed

### 1. Prometheus & Grafana (kube-prometheus-stack)

**Deployment:**
```bash
export KUBECONFIG=/home/osboxes/.kube/configs/gke-config

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.retention=7d \
  --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=10Gi \
  --set grafana.adminPassword=admin \
  --set grafana.persistence.enabled=true \
  --set grafana.persistence.size=5Gi
```

**Configuration:**
- **Prometheus retention**: 7 days
- **Prometheus storage**: 10Gi persistent volume
- **Grafana persistence**: 5Gi persistent volume
- **Grafana admin password**: `admin` (change in production)
- **Namespace**: `monitoring`

**Access Grafana:**
```bash
# Port-forward to access Grafana UI
kubectl port-forward -n monitoring svc/kube-prometheus-stack-grafana 3000:80

# Open browser to http://localhost:3000
# Username: admin
# Password: admin
```

### 2. Loki (Log Aggregation)

**Configuration File:** `loki-values.yaml`

**Deployment:**
```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

helm install loki grafana/loki \
  --namespace monitoring \
  -f 07-observability-stack/loki/loki-values.yaml
```

**Key Configuration:**
- **Deployment mode**: SingleBinary (simplified for testing)
- **Storage**: Filesystem with 10Gi persistent volume
- **Replication factor**: 1
- **Gateway**: Enabled for unified query interface
- **ServiceMonitor**: Enabled for Prometheus integration

**Loki Components:**
- `loki-0`: Main Loki server (StatefulSet)
- `loki-gateway`: Nginx gateway for reads/writes
- `loki-chunks-cache`: Chunk caching
- `loki-results-cache`: Query results caching
- `loki-canary`: Health check canaries on each node

**Log Ingestion URL:**
```
http://loki-gateway.monitoring.svc.cluster.local/loki/api/v1/push
```

**Query URL (for Grafana):**
```
http://loki-gateway.monitoring.svc.cluster.local
```

### 3. Promtail (Log Collection Agent)

**Configuration File:** `promtail-values.yaml`

**Deployment:**
```bash
helm install promtail grafana/promtail \
  --namespace monitoring \
  -f 07-observability-stack/loki/promtail-values.yaml
```

**Key Configuration:**
- **Deployment**: DaemonSet (runs on every node)
- **Target**: Sends logs to `loki-gateway`
- **Log Sources**: All Kubernetes pods via `/var/log/pods`
- **Labels Added**:
  - `namespace`: Kubernetes namespace
  - `pod`: Pod name
  - `container`: Container name
  - `app`: App label (if exists)
  - `service`: Service label (if exists)

**Pipeline:**
1. Scrapes logs from all pods using Kubernetes service discovery
2. Parses container runtime (CRI) format
3. Extracts labels for filtering
4. Sends to Loki via HTTP

## Grafana Datasource Configuration

### Adding Loki to Grafana

A ConfigMap has been created to provision Loki as a datasource:

```bash
kubectl apply -f 07-observability-stack/grafana/loki-datasource.yaml
```

**Manual Configuration** (if needed):
1. Log into Grafana (http://localhost:3000, admin/admin)
2. Go to Configuration → Data Sources
3. Click "Add data source"
4. Select "Loki"
5. Set URL: `http://loki-gateway.monitoring.svc.cluster.local`
6. Click "Save & Test"

## Verification

### Check Pod Status

```bash
export KUBECONFIG=/home/osboxes/.kube/configs/gke-config

# Check all monitoring pods
kubectl get pods -n monitoring

# Check Loki and Promtail specifically
kubectl get pods -n monitoring | grep -E "(loki|promtail)"
```

**Expected Output:**
```
loki-0                          2/2     Running   0          5m
loki-gateway-xxx                1/1     Running   0          5m
loki-chunks-cache-0             2/2     Running   0          5m
loki-results-cache-0            2/2     Running   0          5m
loki-canary-xxx                 1/1     Running   0          5m
promtail-xxx                    1/1     Running   0          5m
```

### Test Log Ingestion

```bash
# Port-forward Loki gateway
kubectl port-forward -n monitoring svc/loki-gateway 3100:80 &

# Send a test log
curl -H "Content-Type: application/json" -XPOST -s "http://127.0.0.1:3100/loki/api/v1/push" \
  --data-raw "{\"streams\": [{\"stream\": {\"job\": \"test\"}, \"values\": [[\"$(date +%s)000000000\", \"test log message\"]]}]}"

# Query logs
curl "http://127.0.0.1:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="test"}' | jq .data.result
```

### Query Semaphore Logs in Grafana

1. Open Grafana → Explore
2. Select "Loki" datasource
3. Example queries:
```logql
# All logs from default namespace
{namespace="default"}

# Logs from specific Semaphore service
{namespace="default", app="guard"}

# Logs containing errors
{namespace="default"} |= "error"

# Logs from all Semaphore services
{namespace="default", app=~"guard|front|controller|.*hub"}
```

## Resource Consumption

### Storage

- **Prometheus**: 10Gi PVC (7 day retention)
- **Grafana**: 5Gi PVC (dashboards, settings)
- **Loki**: 10Gi PVC (log storage)

**Total Storage**: ~25Gi

### CPU & Memory

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|-------------|-----------|----------------|--------------|
| Prometheus | (varies) | (varies) | (varies) | (varies) |
| Grafana | (varies) | (varies) | (varies) | (varies) |
| Loki | 500m | 1000m | 1Gi | 2Gi |
| Promtail (per node) | 100m | 200m | 128Mi | 256Mi |

## Integration with Phase 06 (Falco Runtime Security)

The next step is to integrate Falco alerts into this observability stack for unified security event visualization.

### Falco Integration (Next Task)

Falco can send alerts to multiple backends:
- **Grafana Loki**: Via Falcosidekick
- **Prometheus**: Via Falcosidekick metrics exporter
- **Alertmanager**: For alert routing and notifications

## MITRE ATT&CK Coverage

This observability stack enhances detection capabilities for:

| Technique | Description | Detection Method |
|-----------|-------------|------------------|
| **T1078** | Valid Accounts | Log analysis of authentication attempts |
| **T1136** | Create Account | Audit logs showing account creation |
| **T1070** | Indicator Removal | Detect log deletion or tampering |
| **T1485** | Data Destruction | Detect abnormal delete operations |
| **T1496** | Resource Hijacking | CPU/memory spikes from cryptomining |
| **T1190** | Exploit Public-Facing Application | Error logs showing exploit attempts |

## Troubleshooting

### SSH Tunnel Issues

If kubectl commands time out with `dial tcp 172.16.0.2:443: i/o timeout`:

```bash
# Kill existing tunnel
pkill -f "8443:172.16.0.2:443"

# Restart tunnel
gcloud compute ssh semaphore-hardened-bastion --zone=us-central1-a \
  --tunnel-through-iap -- -L 8443:172.16.0.2:443 -N &

# Update kubeconfig to use tunnel
export KUBECONFIG=/home/osboxes/.kube/configs/gke-config
kubectl config set-cluster $(kubectl config current-context) --server=https://127.0.0.1:8443
kubectl config set-cluster $(kubectl config current-context) --insecure-skip-tls-verify=true

# Test connectivity
kubectl get nodes
```

### Loki Not Receiving Logs

```bash
# Check Promtail is running on all nodes
kubectl get pods -n monitoring -l app.kubernetes.io/name=promtail -o wide

# Check Promtail logs for errors
kubectl logs -n monitoring -l app.kubernetes.io/name=promtail --tail=100

# Check Loki logs
kubectl logs -n monitoring loki-0 -c loki

# Verify network connectivity
kubectl exec -n monitoring -it loki-0 -c loki -- wget -O- http://loki-gateway/ready
```

### Grafana Datasource Not Working

```bash
# Check if ConfigMap was created
kubectl get configmap -n monitoring grafana-loki-datasource

# Restart Grafana to pick up changes
kubectl rollout restart deployment/kube-prometheus-stack-grafana -n monitoring

# Check Grafana logs
kubectl logs -n monitoring -l app.kubernetes.io/name=grafana
```

## Next Steps

1. **Integrate Falco with Loki**: Configure Falcosidekick to send security alerts to Loki
2. **Create Dashboards**: Build Grafana dashboards for Semaphore services
3. **Set up Alerting**: Configure Prometheus alerting rules for critical conditions
4. **Add Jaeger**: Deploy distributed tracing for request flow analysis
5. **SIEM Integration**: Forward logs to external SIEM for advanced threat detection

## Files Created

```
07-observability-stack/
├── prometheus-grafana/
│   └── (deployed via Helm)
├── loki/
│   ├── loki-values.yaml           # Loki configuration
│   └── promtail-values.yaml       # Promtail configuration
├── grafana/
│   └── loki-datasource.yaml       # Loki datasource for Grafana
└── IMPLEMENTATION.md              # This file
```

## Status

- [x] Prometheus deployed with 7d retention, 10Gi storage
- [x] Grafana deployed with persistence, 5Gi storage
- [x] Loki deployed in SingleBinary mode with 10Gi storage
- [x] Promtail deployed as DaemonSet on all nodes
- [x] Loki datasource ConfigMap created
- [ ] Falco integration with observability stack
- [ ] Custom Grafana dashboards for Semaphore
- [ ] Alerting rules configuration

---

**Deployment Date**: 2025-11-14
**Cluster**: `semaphore-hardened` (GKE us-central1)
**Namespace**: `monitoring`
**Stack Version**: kube-prometheus-stack (latest), Loki 3.5.7, Promtail 3.5.1
