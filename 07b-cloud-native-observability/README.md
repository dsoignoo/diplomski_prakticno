# Phase 07b: Google Cloud Native Observability

## Overview

This phase demonstrates migrating from in-cluster observability (Prometheus, Grafana, Loki) to Google Cloud's fully managed observability suite. This comparison showcases the trade-offs between self-hosted and cloud-native approaches.

## Architecture Comparison

### Phase 07 (In-Cluster)
```
┌─────────────────────────────────────────────────┐
│  GKE Cluster (semaphore-hardened)               │
│                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ Falco    │→ │Falco-    │→ │ Loki     │     │
│  │ (eBPF)   │  │sidekick  │  │          │     │
│  └──────────┘  └──────────┘  └──────────┘     │
│                                    ↓            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ Promtail │→ │ Loki     │→ │ Grafana  │     │
│  │(DaemonSet│  │          │  │          │     │
│  └──────────┘  └──────────┘  └──────────┘     │
│                                    ↑            │
│  ┌──────────┐                 ┌──────────┐     │
│  │Prometheus│─────────────────│ Grafana  │     │
│  │          │                 │          │     │
│  └──────────┘                 └──────────┘     │
│                                                 │
│  Storage: 25Gi PVCs (Prometheus, Loki, Grafana)│
└─────────────────────────────────────────────────┘
```

### Phase 07b (Google Cloud Native)
```
┌─────────────────────────────────────────────────┐
│  GKE Cluster (semaphore-hardened)               │
│                                                 │
│  ┌──────────┐  ┌──────────┐                    │
│  │ Falco    │→ │Falco-    │─┐                  │
│  │ (eBPF)   │  │sidekick  │ │                  │
│  └──────────┘  └──────────┘ │                  │
│                              │                  │
│  ┌──────────┐                │                  │
│  │ GKE Node │                │                  │
│  │ (metrics)│────────────────┼──────┐           │
│  └──────────┘                │      │           │
│                              │      │           │
│  ┌──────────┐                │      │           │
│  │ Container│                │      │           │
│  │ (logs)   │────────────────┼──────┼──┐        │
│  └──────────┘                │      │  │        │
└──────────────────────────────┼──────┼──┼────────┘
                               ↓      ↓  ↓
                         ┌──────────────────────┐
                         │ Google Cloud Ops     │
                         │                      │
                         │ ┌────────────────┐   │
                         │ │ Cloud Pub/Sub  │←──┘
                         │ │ (Falco alerts) │
                         │ └────────────────┘
                         │                      │
                         │ ┌────────────────┐   │
                         │ │ Cloud Logging  │←──┘
                         │ │ (30d retention)│
                         │ └────────────────┘
                         │                      │
                         │ ┌────────────────┐   │
                         │ │Cloud Monitoring│←──┘
                         │ │ (metrics)      │
                         │ └────────────────┘
                         │                      │
                         │ ┌────────────────┐   │
                         │ │ Cloud Trace    │
                         │ │ (distributed)  │
                         │ └────────────────┘
                         └──────────────────────┘
                                   ↓
                         ┌──────────────────────┐
                         │ Cloud Console        │
                         │ Unified Dashboard    │
                         └──────────────────────┘

Storage: Fully managed (no PVCs needed)
```

## Components

### 1. Cloud Monitoring (Replaces Prometheus)
- **Purpose**: Metrics collection, storage, and alerting
- **Auto-configured**: GKE sends metrics automatically
- **Retention**: 24 months (vs 7 days in-cluster)
- **Query Language**: MQL (Monitoring Query Language)
- **Dashboards**: Pre-built + custom

### 2. Cloud Logging (Replaces Loki + Promtail)
- **Purpose**: Centralized log aggregation
- **Auto-configured**: GKE sends logs automatically
- **Retention**: 30 days default (configurable up to 3650 days)
- **Query Language**: Log query syntax (similar to LogQL)
- **Export**: BigQuery, Cloud Storage, Pub/Sub

### 3. Cloud Trace (Optional - Distributed Tracing)
- **Purpose**: Request flow analysis across microservices
- **Integration**: OpenTelemetry, Jaeger, Zipkin compatible
- **Analysis**: Latency breakdown, bottleneck detection

### 4. Cloud Pub/Sub (Falco Alert Distribution)
- **Purpose**: Event bus for security alerts
- **Integration**: Falcosidekick → Pub/Sub → Cloud Functions/Workflows
- **Use Cases**: Automated remediation, ticketing, notifications

## Files in This Phase

```
07b-cloud-native-observability/
├── README.md                          # This file
├── COMPARISON.md                      # Detailed feature comparison
├── MIGRATION.md                       # Migration guide from Phase 07
├── enable-cloud-ops.sh                # Script to enable Cloud Operations
├── falco-cloud-pubsub.yaml            # Falco → Pub/Sub integration
├── cloud-monitoring/
│   ├── custom-dashboards.json         # GKE + Semaphore dashboards
│   ├── alert-policies.yaml            # Alerting rules
│   └── slo-definitions.yaml           # Service Level Objectives
├── cloud-logging/
│   ├── log-based-metrics.yaml         # Metrics from logs
│   ├── falco-queries.md               # Query examples for Falco alerts
│   └── export-to-bigquery.sh          # Long-term storage setup
└── cost-analysis/
    ├── monthly-estimate.md            # Cost projections
    └── cost-optimization.md           # Tips to reduce costs
```

## Quick Start

### Option 1: View Existing Data (Already Enabled!)

Your GKE cluster already sends data to Cloud Operations:

```bash
# View in Cloud Console
# Logs: https://console.cloud.google.com/logs
# Metrics: https://console.cloud.google.com/monitoring
# Trace: https://console.cloud.google.com/traces
```

### Option 2: Integrate Falco with Cloud Pub/Sub

```bash
# Run the setup script
cd 07b-cloud-native-observability
./enable-cloud-ops.sh
```

### Option 3: Full Migration (Remove In-Cluster Stack)

See `MIGRATION.md` for detailed migration steps.

## When to Use Each Approach

### Use In-Cluster (Phase 07) When:
✅ You need full control over data retention
✅ You want to avoid vendor lock-in
✅ You have dedicated ops team for maintenance
✅ You need custom visualizations/plugins
✅ You're running multi-cloud
✅ Cost optimization is critical (at small scale)

### Use Google Cloud Ops (Phase 07b) When:
✅ You want zero operational overhead
✅ You need multi-cluster observability
✅ You want native GCP integration (IAM, SCC, etc.)
✅ You need 99.9% SLA
✅ You want to focus on application, not infrastructure
✅ You need long-term retention (>30 days)
✅ You want automatic scaling

## Cost Comparison

### In-Cluster Stack (Phase 07)
| Component | Cost/Month | Notes |
|-----------|------------|-------|
| Compute overhead | $50 | 3 nodes need extra resources |
| Storage (25Gi PVCs) | $10 | Prometheus, Loki, Grafana |
| Operational time | $500+ | Estimated 20hrs/month @ $25/hr |
| **Total** | **$560+** | **Plus operational burden** |

### Google Cloud Operations (Phase 07b)
| Component | Cost/Month | Notes |
|-----------|------------|-------|
| Cloud Monitoring | $15 | ~6M samples/month |
| Cloud Logging | $25 | ~50GB/month (after 50GB free) |
| Cloud Trace (optional) | $5 | ~1M spans/month |
| Pub/Sub (Falco) | $1 | ~100K messages/month |
| **Total** | **$46** | **Zero operational burden** |

**Savings**: ~$514/month + significantly reduced operational overhead

## Key Features

### Cloud Logging Features
- **Log-based metrics**: Convert logs to metrics automatically
- **Log sinks**: Export to BigQuery, Cloud Storage, Pub/Sub
- **Log exclusion**: Reduce costs by filtering noisy logs
- **Advanced search**: Full-text search across all logs
- **Log anomaly detection**: AI-powered anomaly detection

### Cloud Monitoring Features
- **Uptime checks**: Monitor endpoint availability
- **Alerting policies**: Multi-condition alerts with channels (email, SMS, Slack, PagerDuty)
- **Dashboards**: Drag-and-drop dashboard builder
- **Service monitoring**: SLO/SLI tracking
- **Anomaly detection**: ML-based threshold suggestions

### Integration with Security Tools
- **Security Command Center**: Unified security findings
- **Binary Authorization**: Policy enforcement
- **Cloud Armor**: DDoS protection and WAF
- **VPC Flow Logs**: Network traffic analysis
- **Cloud Asset Inventory**: Resource tracking

## Security Benefits

### Enhanced Security Posture
1. **Immutable logs**: Cloud Logging provides tamper-proof audit trail
2. **IAM integration**: Fine-grained access control to logs/metrics
3. **Data residency**: Choose data location for compliance
4. **Encryption**: Automatic encryption at rest and in transit
5. **Access transparency**: Log every access to your data

### Compliance
- **SOC 2/3**: Google Cloud is SOC certified
- **ISO 27001**: Information security management
- **PCI DSS**: Payment card data security
- **HIPAA**: Healthcare data (with BAA)
- **GDPR**: EU data protection

## MITRE ATT&CK Enhanced Detection

Cloud Operations enhances detection of:

| Technique | In-Cluster Detection | Cloud Ops Enhancement |
|-----------|---------------------|----------------------|
| **T1078** (Valid Accounts) | Falco alerts only | + Cloud Audit Logs (IAM changes) |
| **T1530** (Data from Cloud Storage) | Not detected | Cloud Audit Logs track access |
| **T1552** (Unsecured Credentials) | Limited | Secret Manager audit logs |
| **T1098** (Account Manipulation) | Not detected | IAM audit logs |
| **T1562** (Impair Defenses) | Falco detects | + Logs detect service disabling |

## Next Steps

1. Review `COMPARISON.md` for detailed feature comparison
2. Read `MIGRATION.md` if planning to migrate from Phase 07
3. Run `enable-cloud-ops.sh` to integrate Falco with Pub/Sub
4. Explore Cloud Console dashboards
5. Set up alerting policies for critical metrics

## References

- **Cloud Monitoring**: https://cloud.google.com/monitoring/docs
- **Cloud Logging**: https://cloud.google.com/logging/docs
- **Cloud Trace**: https://cloud.google.com/trace/docs
- **GKE Observability**: https://cloud.google.com/stackdriver/docs/solutions/gke
- **Pricing Calculator**: https://cloud.google.com/products/calculator

---

**Status**: Documentation complete
**Recommended For**: Production deployments, enterprise environments
**Trade-off**: Lower operational overhead at slightly higher cost (at scale)
