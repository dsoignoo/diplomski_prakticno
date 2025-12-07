# SIEM Integration - Elasticsearch, Kibana, Filebeat

## Pregled

SIEM (Security Information and Event Management) integracija omogućava centralizovano prikupljanje, analizu i korelaciju sigurnosnih događaja iz svih izvora:

- **Falco runtime security events**
- **Kubernetes audit logs**
- **Application logs** (iz Loki)
- **Network policy violations**
- **Authentication/authorization events**

## Arhitektura

```
┌─────────────────────────────────────────────────────────────┐
│                         Data Sources                         │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│ Falco       │ K8s Audit   │ App Logs    │ Network Events   │
│ (Webhook)   │ (API Server)│ (Filebeat)  │ (Cilium Hubble)  │
└──────┬──────┴──────┬──────┴──────┬──────┴────────┬─────────┘
       │             │             │               │
       │             └─────────────┴───────────────┘
       │                           │
       v                           v
┌──────────────┐           ┌──────────────┐
│ Logstash     │           │ Filebeat     │
│ (Parsing)    │           │ (Shipper)    │
└──────┬───────┘           └──────┬───────┘
       │                           │
       └───────────────┬───────────┘
                       v
              ┌─────────────────┐
              │ Elasticsearch   │
              │ (SIEM Backend)  │
              └────────┬────────┘
                       │
              ┌────────┴────────┐
              │     Kibana      │
              │ (SIEM Frontend) │
              └─────────────────┘
```

## Komponente

### 1. Elasticsearch

- **Uloga**: Storage i indexing za sve log/event podatke
- **Konfiguracija**: 3-node cluster za HA
- **Retention**: 30 dana
- **Index patterns**: `falco-*`, `k8s-audit-*`, `filebeat-*`

### 2. Kibana

- **Uloga**: Vizualizacija i SIEM dashboards
- **Features**:
  - Security dashboards
  - Threat hunting
  - Alert investigation
  - Incident response workflows

### 3. Filebeat

- **Uloga**: Log shipping iz Kubernetes
- **Modules**:
  - Kubernetes module (audit logs)
  - System module (node logs)
  - Custom module (application logs)

### 4. Logstash (opciono)

- **Uloga**: Log parsing i enrichment
- **Pipelines**:
  - Falco event parsing
  - GeoIP enrichment
  - Threat intelligence lookup

## Instalacija

### Preduvjeti

```bash
# Dodaj Elastic Helm repo
helm repo add elastic https://helm.elastic.co
helm repo update

# Kreiraj namespace
kubectl create namespace elk
```

### 1. Instalacija Elasticsearch

```bash
# Apply ECK operator (Elastic Cloud on Kubernetes)
kubectl create -f https://download.elastic.co/downloads/eck/2.10.0/crds.yaml
kubectl apply -f https://download.elastic.co/downloads/eck/2.10.0/operator.yaml

# Instaliraj Elasticsearch cluster
kubectl apply -f elasticsearch/elasticsearch-cluster.yaml

# Čekaj da bude ready
kubectl wait --for=condition=Ready elasticsearch/semaphore-es -n elk --timeout=600s

# Uzmi password za elastic user
kubectl get secret semaphore-es-elastic-user -n elk -o=jsonpath='{.data.elastic}' | base64 --decode
```

### 2. Instalacija Kibana

```bash
# Instaliraj Kibana
kubectl apply -f kibana/kibana-instance.yaml

# Čekaj da bude ready
kubectl wait --for=condition=Ready kibana/semaphore-kibana -n elk --timeout=300s

# Port forward za pristup
kubectl port-forward service/semaphore-kibana-kb-http 5601 -n elk

# Otvori browser: https://localhost:5601
# Username: elastic
# Password: (iz prethodnog koraka)
```

### 3. Instalacija Filebeat

```bash
# Instaliraj Filebeat DaemonSet
kubectl apply -f filebeat/filebeat-daemonset.yaml

# Verifikuj da su svi podovi running
kubectl get pods -n elk -l app=filebeat
```

### 4. Falco → Elasticsearch Integration

```bash
# Konfigurišemo Falco da šalje evente u Elasticsearch
kubectl apply -f falco-integration/falco-elasticsearch-output.yaml

# Restart Falco podova
kubectl rollout restart daemonset/falco -n falco
```

### 5. Import Kibana Dashboards

```bash
# Import pre-konfigurisanih dashboards
kubectl apply -f kibana/dashboards/security-overview-dashboard.ndjson

# Ili kroz Kibana UI:
# Stack Management → Saved Objects → Import
```

## Sigurnosni Use Case-evi

### 1. Runtime Threat Detection

**Query u Kibana:**
```
event.dataset: "falco" AND priority: "Critical"
```

**Alerte:**
- Shell execution u production containeru
- Privileged container spawn
- Sensitive file access (/etc/shadow, /etc/passwd)

### 2. Kubernetes Audit Analysis

**Query:**
```
kubernetes.audit.verb: "delete" AND kubernetes.audit.objectRef.resource: "secrets"
```

**Alerte:**
- Unauthorized secret access
- Role/RoleBinding modification
- Service account token creation

### 3. Application Security Events

**Query:**
```
http.response.status_code: [401 TO 403] AND source.ip: *
```

**Alerte:**
- Brute force attacks (multiple 401s)
- Unauthorized access attempts (403s)
- Suspicious user agents

### 4. Network Policy Violations

**Query:**
```
event.dataset: "falco" AND falco.rule: "*network*"
```

**Alerte:**
- Outbound connection attempts
- Connection to suspicious IPs
- Port scanning activity

## SIEM Dashboards

### 1. Security Overview Dashboard

- **Total security events** (last 24h)
- **Critical alerts** timeline
- **Top attacked services**
- **Geographic attack map** (GeoIP)
- **MITRE ATT&CK techniques** detected

### 2. Falco Events Dashboard

- **Events by priority** (Critical, Warning, Info)
- **Top triggered rules**
- **Events by container/pod**
- **Shell executions** timeline
- **File access patterns**

### 3. Kubernetes Audit Dashboard

- **API operations** timeline
- **Failed authentication** attempts
- **RBAC changes**
- **Secret access** logs
- **Namespace operations**

### 4. Incident Response Dashboard

- **Active incidents**
- **Investigation timeline**
- **Related events** correlation
- **Remediation actions**
- **Incident status** tracking

## Alert Rules

Konfiguracija u `alerts/` direktoriju:

### Critical Alerts

1. **Shell in Production Container**
   - Trigger: Falco shell detection event
   - Severity: Critical
   - Action: Auto-create incident, notify SOC

2. **Unauthorized Secret Access**
   - Trigger: K8s audit + RBAC violation
   - Severity: Critical
   - Action: Lock account, notify admin

3. **Privilege Escalation Attempt**
   - Trigger: Falco privilege escalation rule
   - Severity: Critical
   - Action: Kill pod, create incident

### Warning Alerts

1. **High Authentication Failures**
   - Trigger: >10 401s in 5 minutes
   - Severity: Warning
   - Action: Rate limit IP

2. **Suspicious Network Activity**
   - Trigger: Outbound connection to non-whitelisted IP
   - Severity: Warning
   - Action: Log and review

## Threat Intelligence Integration

### 1. IP Reputation

```yaml
# Logstash pipeline sa threat intel lookup
- name: threat-intel-lookup
  processors:
    - geoip:
        field: source.ip
    - threat_intel:
        field: source.ip
        target_field: threat
        ignore_missing: true
```

### 2. MITRE ATT&CK Mapping

Falco pravila su mapirana na MITRE ATT&CK tehnike:

- **T1059** - Command and Scripting Interpreter
- **T1078** - Valid Accounts
- **T1136** - Create Account
- **T1543** - Create or Modify System Process

## Performance Tuning

### Elasticsearch Index Lifecycle

```yaml
# ILM policy za automatsko brisanje starih podataka
PUT _ilm/policy/security-logs-policy
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "7d"
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

### Filebeat Backpressure

```yaml
# filebeat.yml
queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 1s

output.elasticsearch:
  bulk_max_size: 50
  worker: 2
```

## Backup i Recovery

```bash
# Snapshot repository
PUT _snapshot/backup_repo
{
  "type": "gcs",
  "settings": {
    "bucket": "semaphore-elk-backups",
    "base_path": "elasticsearch"
  }
}

# Create snapshot
PUT _snapshot/backup_repo/snapshot_1
{
  "indices": "falco-*,filebeat-*",
  "ignore_unavailable": true,
  "include_global_state": false
}
```

## Troubleshooting

### Problem: Filebeat ne šalje logove

```bash
# Provjeri Filebeat status
kubectl logs -n elk -l app=filebeat --tail=50

# Provjeri connectivity sa Elasticsearch
kubectl exec -n elk -it filebeat-xxx -- filebeat test output
```

### Problem: Elasticsearch cluster yellow/red

```bash
# Provjeri cluster health
kubectl exec -n elk -it semaphore-es-0 -- curl -k -u elastic:$PASSWORD https://localhost:9200/_cluster/health?pretty

# Provjeri shard allocation
kubectl exec -n elk -it semaphore-es-0 -- curl -k -u elastic:$PASSWORD https://localhost:9200/_cat/shards?v
```

### Problem: Kibana dashboards ne prikazuju podatke

```bash
# Refresh index patterns
# Kibana UI → Stack Management → Index Patterns → Refresh field list

# Provjeri da li postoje dokumenti
GET falco-*/_count
```

## Cost Optimization

### GKE Specifično

- **Node pools**: Koristi preemptible nodes za non-critical Elasticsearch nodes
- **Disk**: Standard persistent disks umjesto SSD (jeftiniji, dovoljno brzi)
- **Retention**: 30 dana umjesto 90 (manje storage costs)
- **ILM**: Automatic rollover i deletion

**Estimated costs (GKE):**
- Elasticsearch (3 nodes): ~$120/month
- Storage (500GB): ~$85/month
- **Total**: ~$200/month (pokriva se sa $300 free credits)

## Reference

- [ECK Documentation](https://www.elastic.co/guide/en/cloud-on-k8s/current/index.html)
- [Filebeat Kubernetes Module](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-kubernetes.html)
- [Elastic SIEM](https://www.elastic.co/guide/en/security/current/index.html)
- [Falco Elasticsearch Integration](https://falco.org/docs/outputs/)
