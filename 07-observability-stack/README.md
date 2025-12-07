# Observability Stack - Full Visibility za Semaphore

**Faza 3, Komponenta 1**

Implementacija kompletnog **observability stack-a** za Semaphore CI/CD platformu - Metrics, Logs, Traces (Golden Signals).

## 🎯 Cilj

Postići **full stack observability** kroz tri stuba:

1. 📊 **METRICS** (Prometheus + Grafana) - Šta se dešava?
2. 📝 **LOGS** (Loki + Promtail) - Zašto se dešava?
3. 🔍 **TRACES** (Jaeger) - Gdje je bottleneck?

## 📊 Tri Stuba Observability

```
┌─────────────────────────────────────────────────────────┐
│                    GRAFANA                               │
│              (Unified Visualization)                     │
├─────────────────┬──────────────────┬────────────────────┤
│   PROMETHEUS    │      LOKI        │      JAEGER       │
│   (Metrics)     │     (Logs)       │     (Traces)      │
├─────────────────┼──────────────────┼────────────────────┤
│ • CPU, Memory   │ • Application    │ • Request flow    │
│ • Request rate  │   logs           │ • Latency         │
│ • Error rate    │ • Error logs     │ • Dependencies    │
│ • Saturation    │ • Audit logs     │ • Bottlenecks     │
└─────────────────┴──────────────────┴────────────────────┘
         ▲                 ▲                  ▲
         │                 │                  │
    ┌────┴────┐      ┌─────┴─────┐      ┌────┴────┐
    │ Guard   │      │ Promtail  │      │ Jaeger  │
    │ Front   │      │ DaemonSet │      │ Agent   │
    │ Hooks   │      └───────────┘      └─────────┘
    │ ...     │
    └─────────┘
```

## 🗂️ Struktura direktorija

```
07-observability-stack/
├── README.md                           # Ovaj fajl
├── prometheus-grafana/
│   ├── prometheus-operator.yaml       # Prometheus Operator deployment
│   ├── prometheus-instance.yaml       # Prometheus instance
│   ├── servicemonitors/
│   │   ├── semaphore-services.yaml   # Monitor Semaphore services
│   │   ├── kubernetes-components.yaml
│   │   └── falco-monitor.yaml
│   ├── alerting-rules/
│   │   ├── semaphore-alerts.yaml     # Custom alerts
│   │   ├── slo-alerts.yaml           # SLO-based alerts
│   │   └── infrastructure-alerts.yaml
│   ├── grafana-deployment.yaml
│   └── grafana-datasources.yaml
├── loki-logging/
│   ├── loki-stack.yaml                # Loki deployment
│   ├── promtail-daemonset.yaml        # Log collector
│   ├── log-retention-policy.yaml
│   └── query-examples.md
├── jaeger-tracing/
│   ├── jaeger-operator.yaml           # Jaeger Operator
│   ├── jaeger-instance.yaml           # Jaeger all-in-one
│   ├── instrumentation-guide.md       # How to instrument apps
│   └── trace-analysis-examples.md
├── dashboards/
│   ├── semaphore-platform-health.json # Main dashboard
│   ├── cicd-job-metrics.json          # CI/CD specific
│   ├── database-performance.json      # PostgreSQL dashboard
│   ├── message-queue-health.json      # RabbitMQ dashboard
│   ├── security-events.json           # Falco + security
│   └── golden-signals.json            # Latency, Traffic, Errors, Saturation
└── service-mesh/                       # Optional: Istio/Linkerd
    ├── istio-setup/
    └── linkerd-setup/
```

## 🚀 Quick Start

### Preduslovi

1. GKE Autopilot cluster sa Semaphore deployovan
2. NetworkPolicies implementirane (Faza 1)
3. Falco aktivan (Faza 1)
4. kubectl pristup

---

## 📝 Komponenta 1: Prometheus + Grafana

### Korak 1: Deploy Prometheus Operator

Prometheus Operator pojednostavljuje deployment i upravljanje Prometheus-om.

```bash
cd /home/osboxes/Documents/amir/diplomski_prakticno/07-observability-stack/prometheus-grafana

# Install Prometheus Operator sa Helm-om
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Deploy kube-prometheus-stack (Prometheus + Grafana + Alertmanager)
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
  --set grafana.adminPassword='admin123' \
  --set prometheus.prometheusSpec.retention=30d \
  --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi

# Provjera
kubectl get pods -n monitoring
```

**Što smo dobili**:
- Prometheus server (metrics storage)
- Grafana (visualization)
- Alertmanager (alerting)
- Node Exporter (node metrics)
- kube-state-metrics (K8s resource metrics)

### Korak 2: ServiceMonitor za Semaphore

ServiceMonitor je CRD koji kaže Prometheus-u šta da scrape-uje.

```yaml
# servicemonitors/semaphore-services.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: semaphore-services
  namespace: monitoring
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      monitoring: "true"
  namespaceSelector:
    matchNames:
    - semaphore
  endpoints:
  - port: metrics
    interval: 15s
    path: /metrics
    scheme: http
    relabelings:
    - sourceLabels: [__meta_kubernetes_pod_name]
      targetLabel: pod
    - sourceLabels: [__meta_kubernetes_pod_label_app]
      targetLabel: app
    - sourceLabels: [__meta_kubernetes_pod_label_component]
      targetLabel: component
```

**Apply**:
```bash
kubectl apply -f servicemonitors/semaphore-services.yaml
```

**Napomena**: Semaphore servisi moraju exposati `/metrics` endpoint (Prometheus format).

### Korak 3: Grafana Dashboards

#### Dashboard 1: Semaphore Platform Health

**Golden Signals za sve Semaphore servise**:

```json
{
  "dashboard": {
    "title": "Semaphore Platform Health",
    "panels": [
      {
        "title": "Request Rate (QPS)",
        "targets": [{
          "expr": "sum(rate(http_requests_total{namespace=\"semaphore\"}[5m])) by (app)"
        }]
      },
      {
        "title": "Error Rate",
        "targets": [{
          "expr": "sum(rate(http_requests_total{namespace=\"semaphore\",status=~\"5..\"}[5m])) / sum(rate(http_requests_total{namespace=\"semaphore\"}[5m]))"
        }]
      },
      {
        "title": "P95 Latency",
        "targets": [{
          "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{namespace=\"semaphore\"}[5m]))"
        }]
      },
      {
        "title": "CPU Usage by Service",
        "targets": [{
          "expr": "sum(rate(container_cpu_usage_seconds_total{namespace=\"semaphore\"}[5m])) by (pod)"
        }]
      },
      {
        "title": "Memory Usage by Service",
        "targets": [{
          "expr": "sum(container_memory_working_set_bytes{namespace=\"semaphore\"}) by (pod)"
        }]
      },
      {
        "title": "Pod Restart Count",
        "targets": [{
          "expr": "kube_pod_container_status_restarts_total{namespace=\"semaphore\"}"
        }]
      }
    ]
  }
}
```

**Import u Grafana**:
```bash
# Port-forward Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80

# Pristup: http://localhost:3000
# Username: admin
# Password: admin123 (ili iz secret-a)

# Import dashboard: dashboards/semaphore-platform-health.json
```

#### Dashboard 2: Security Events (Falco)

```json
{
  "dashboard": {
    "title": "Security Events - Falco",
    "panels": [
      {
        "title": "Falco Alerts by Priority",
        "targets": [{
          "expr": "sum(falco_events_total) by (priority)"
        }]
      },
      {
        "title": "Falco Alerts by Rule",
        "targets": [{
          "expr": "topk(10, sum(rate(falco_events_total[5m])) by (rule))"
        }]
      },
      {
        "title": "Shell Execution Attempts",
        "targets": [{
          "expr": "sum(increase(falco_events_total{rule=~\".*shell.*\"}[1h]))"
        }]
      },
      {
        "title": "Unauthorized Secret Access Attempts",
        "targets": [{
          "expr": "sum(increase(falco_events_total{rule=~\".*secret.*\"}[1h]))"
        }]
      }
    ]
  }
}
```

### Korak 4: Alerting Rules

```yaml
# alerting-rules/semaphore-alerts.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: semaphore-alerts
  namespace: monitoring
spec:
  groups:
  - name: semaphore
    interval: 30s
    rules:
    # High Error Rate
    - alert: HighErrorRate
      expr: |
        sum(rate(http_requests_total{namespace="semaphore",status=~"5.."}[5m]))
        /
        sum(rate(http_requests_total{namespace="semaphore"}[5m]))
        > 0.05
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High error rate in Semaphore"
        description: "Error rate is {{ $value | humanizePercentage }} (threshold: 5%)"

    # Pod Down
    - alert: SemaphorePodDown
      expr: kube_pod_status_phase{namespace="semaphore",phase!="Running"} == 1
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "Semaphore pod is down"
        description: "Pod {{ $labels.pod }} is in {{ $labels.phase }} state"

    # High Memory Usage
    - alert: HighMemoryUsage
      expr: |
        sum(container_memory_working_set_bytes{namespace="semaphore"}) by (pod)
        /
        sum(container_spec_memory_limit_bytes{namespace="semaphore"}) by (pod)
        > 0.9
      for: 10m
      labels:
        severity: warning
      annotations:
        summary: "High memory usage"
        description: "Pod {{ $labels.pod }} using {{ $value | humanizePercentage }} of memory limit"

    # Database Connection Pool Exhausted
    - alert: DatabaseConnectionPoolExhausted
      expr: |
        pg_stat_database_numbackends{namespace="semaphore"}
        /
        pg_settings_max_connections{namespace="semaphore"}
        > 0.8
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "PostgreSQL connection pool near exhaustion"
        description: "Using {{ $value | humanizePercentage }} of max connections"

    # Falco Critical Alert
    - alert: FalcoCriticalSecurityEvent
      expr: increase(falco_events_total{priority="Critical"}[5m]) > 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Falco detected critical security event"
        description: "Rule: {{ $labels.rule }}"
```

**Apply**:
```bash
kubectl apply -f alerting-rules/semaphore-alerts.yaml
```

---

## 📝 Komponenta 2: Loki Logging

### Korak 1: Deploy Loki Stack

```bash
# Add Loki Helm repo
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Deploy Loki + Promtail
helm install loki grafana/loki-stack \
  --namespace monitoring \
  --set loki.persistence.enabled=true \
  --set loki.persistence.size=50Gi \
  --set promtail.enabled=true \
  --set grafana.enabled=false

# Provjera
kubectl get pods -n monitoring | grep loki
```

**Komponente**:
- **Loki**: Log aggregation system (like Prometheus, but for logs)
- **Promtail**: DaemonSet koji prikuplja logove sa svih nodes

### Korak 2: Configure Loki Datasource u Grafana

```bash
# Loki service URL
LOKI_URL="http://loki.monitoring.svc.cluster.local:3100"

# Add datasource (može i kroz Grafana UI)
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasources
  namespace: monitoring
data:
  loki-datasource.yaml: |
    apiVersion: 1
    datasources:
    - name: Loki
      type: loki
      access: proxy
      url: $LOKI_URL
      isDefault: false
EOF

# Restart Grafana da pick-uje novi datasource
kubectl rollout restart deployment/prometheus-grafana -n monitoring
```

### Korak 3: Log Queries u Grafana

**Query primjeri**:

```logql
# Svi logovi iz semaphore namespace-a
{namespace="semaphore"}

# Logovi sa errors iz Guard servisa
{namespace="semaphore", app="guard"} |= "error"

# Logovi sa HTTP 500 errors
{namespace="semaphore"} | json | status_code="500"

# Count errors po servisu (last 5m)
sum(rate({namespace="semaphore"} |= "error" [5m])) by (app)

# Falco alerts
{namespace="falco"} | json | priority="Critical"

# Failed authentication attempts
{namespace="semaphore", app="guard"} |= "authentication failed"
```

### Korak 4: Log Retention Policy

```yaml
# loki-logging/log-retention-policy.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: loki-config
  namespace: monitoring
data:
  loki.yaml: |
    schema_config:
      configs:
      - from: 2023-01-01
        store: boltdb-shipper
        object_store: filesystem
        schema: v11
        index:
          prefix: index_
          period: 24h

    # Retention: 30 dana
    limits_config:
      retention_period: 720h  # 30 days

    # Compaction (cleanup old logs)
    compactor:
      working_directory: /data/loki/compactor
      shared_store: filesystem
      compaction_interval: 10m
      retention_enabled: true
      retention_delete_delay: 2h
      retention_delete_worker_count: 150
```

---

## 📝 Komponenta 3: Jaeger Distributed Tracing

### Korak 1: Deploy Jaeger Operator

```bash
# Deploy Jaeger Operator
kubectl create namespace observability
kubectl create -f https://github.com/jaegertracing/jaeger-operator/releases/download/v1.51.0/jaeger-operator.yaml -n observability

# Provjera
kubectl get pods -n observability
```

### Korak 2: Deploy Jaeger Instance

```yaml
# jaeger-tracing/jaeger-instance.yaml
apiVersion: jaegertracing.io/v1
kind: Jaeger
metadata:
  name: semaphore-jaeger
  namespace: observability
spec:
  strategy: production  # all-in-one za dev, production za prod
  storage:
    type: elasticsearch
    options:
      es:
        server-urls: http://elasticsearch.monitoring.svc.cluster.local:9200
        index-prefix: jaeger
  ingress:
    enabled: true
    annotations:
      kubernetes.io/ingress.class: nginx
    hosts:
    - jaeger.semaphore.example.com
  agent:
    strategy: DaemonSet  # Agent na svakom node-u
  query:
    replicas: 2
  collector:
    replicas: 2
    resources:
      requests:
        memory: "512Mi"
        cpu: "500m"
      limits:
        memory: "1Gi"
        cpu: "1000m"
```

**Apply**:
```bash
kubectl apply -f jaeger-tracing/jaeger-instance.yaml
```

### Korak 3: Instrument Semaphore Services

**Za Elixir/Erlang servise (Guard, RBAC, itd.)**:

```elixir
# mix.exs - Add OpenTelemetry dependencies
defp deps do
  [
    {:opentelemetry, "~> 1.3"},
    {:opentelemetry_exporter, "~> 1.6"},
    {:opentelemetry_api, "~> 1.2"},
    {:opentelemetry_phoenix, "~> 1.1"}
  ]
end

# config/runtime.exs
config :opentelemetry, :resource,
  service: [
    name: "semaphore-guard",
    namespace: "semaphore"
  ]

config :opentelemetry, :processors,
  otel_batch_processor: %{
    exporter: {:opentelemetry_exporter, %{
      endpoints: ["http://semaphore-jaeger-collector.observability.svc.cluster.local:4318"]
    }}
  }
```

**Za Node.js servise (Front, Hooks Processor)**:

```javascript
// instrumentation.js
const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
const { registerInstrumentations } = require('@opentelemetry/instrumentation');
const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express');
const { JaegerExporter } = require('@opentelemetry/exporter-jaeger');

const provider = new NodeTracerProvider();

provider.addSpanProcessor(
  new opentelemetry.tracing.BatchSpanProcessor(
    new JaegerExporter({
      endpoint: 'http://semaphore-jaeger-collector.observability.svc.cluster.local:14268/api/traces'
    })
  )
);

provider.register();

registerInstrumentations({
  instrumentations: [
    new HttpInstrumentation(),
    new ExpressInstrumentation()
  ]
});
```

### Korak 4: Analyze Traces

**Primjer trace analysis**:

```
GitHub Webhook Request Trace:
┌─────────────────────────────────────────────────────┐
│ Ingress (2ms)                                       │
└──┬──────────────────────────────────────────────────┘
   │
   ├─► Hooks Processor (15ms)
   │   └─► Parse webhook (5ms)
   │   └─► Validate signature (3ms)
   │   └─► RabbitMQ publish (7ms)
   │
   ├─► Workflow Creator (50ms)
   │   └─► Guard Auth Check (25ms) ⚠️ SLOW!
   │       └─► RBAC Permission Check (20ms) ⚠️ BOTTLENECK
   │       └─► Redis Cache Miss (5ms)
   │   └─► Database Insert (15ms)
   │   └─► RabbitMQ publish (10ms)
   │
   └─► GitHub Notifier (10ms)

Total: 77ms
Bottleneck: RBAC Permission Check (20ms / 26% of total)
```

**Action**: Cache RBAC permissions u Redis!

---

## 📊 Faza 3 Metrike

| Metrika | Prije Faze 3 | Poslije Faze 3 | Target |
|---------|--------------|----------------|--------|
| **MTTR (Mean Time To Resolve)** | 2-4h | < 30min | < 1h |
| **Incident detection time** | Manual | < 5min | < 10min |
| **Observability coverage** | 0% | 100% | 95%+ |
| **Log searchability** | kubectl logs | Loki (full-text) | Centralized |
| **Trace visibility** | Ne | Da (end-to-end) | Da |
| **Bottleneck identification** | Manual | Automatic (Jaeger) | Automatic |
| **Dashboard count** | 0 | 5+ custom | 5+ |
| **Alert rules** | 0 | 10+ | 10+ |

---

## 🎯 Sljedeći koraci u Fazi 3

Nakon Observability Stack-a:

1. **SIEM Integration** → `../10-threat-detection/siem-integration/`
2. **Cloud-native Threat Detection** → `../10-threat-detection/cloud-native-security/`
3. **Service Mesh** (optional) → `service-mesh/`

## 📚 Reference

- [Prometheus Operator](https://prometheus-operator.dev/)
- [Grafana Loki](https://grafana.com/oss/loki/)
- [Jaeger](https://www.jaegertracing.io/)
- [OpenTelemetry](https://opentelemetry.io/)
- [Golden Signals](https://sre.google/sre-book/monitoring-distributed-systems/)
