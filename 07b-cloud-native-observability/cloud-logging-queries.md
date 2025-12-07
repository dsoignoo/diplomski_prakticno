# Cloud Logging Query Reference

This document provides ready-to-use Cloud Logging queries for monitoring the Semaphore platform and Falco security alerts.

## Access Cloud Logging

**Web Console**: https://console.cloud.google.com/logs
**CLI**: `gcloud logging read`

## Basic Query Syntax

```
resource.type="RESOURCE_TYPE"
resource.labels.KEY="VALUE"
severity="LEVEL"
timestamp>="2025-11-14T00:00:00Z"
jsonPayload.field="value"
textPayload=~"regex pattern"
```

## Semaphore Application Queries

### 1. All Semaphore Logs (Last 1 Hour)

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="default"
timestamp>="2025-11-14T12:00:00Z"
```

**CLI**:
```bash
gcloud logging read '
  resource.type="k8s_container"
  resource.labels.namespace_name="default"
' --limit=50 --format=json
```

### 2. Logs from Specific Semaphore Service (e.g., Guard)

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="default"
resource.labels.pod_name=~"guard-.*"
```

**CLI**:
```bash
gcloud logging read '
  resource.type="k8s_container"
  resource.labels.namespace_name="default"
  labels.k8s-pod/app="guard"
' --limit=50
```

### 3. Error Logs Across All Semaphore Services

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="default"
severity>=ERROR
```

**CLI**:
```bash
gcloud logging read '
  resource.type="k8s_container"
  resource.labels.namespace_name="default"
  severity>=ERROR
' --limit=100
```

### 4. PostgreSQL Database Logs

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="default"
resource.labels.pod_name=~"postgres-.*"
```

### 5. Authentication Events (Guard Service)

**Console Query**:
```
resource.type="k8s_container"
labels.k8s-pod/app="guard"
jsonPayload.message=~"(authentication|login|logout)"
```

### 6. API Request Logs

**Console Query**:
```
resource.type="k8s_container"
labels.k8s-pod/app="public-api"
jsonPayload.method=~"(GET|POST|PUT|DELETE)"
```

## Falco Security Alert Queries

### 7. All Falco Alerts

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="falco"
resource.labels.container_name="falco"
jsonPayload.output:*
```

**CLI**:
```bash
gcloud logging read '
  resource.type="k8s_container"
  resource.labels.namespace_name="falco"
  resource.labels.container_name="falco"
  jsonPayload.output:*
' --limit=50 --format=json
```

### 8. Shell Execution Alerts in Semaphore

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="falco"
jsonPayload.rule="Shell Spawned in Semaphore Container"
```

**CLI**:
```bash
gcloud logging read '
  resource.type="k8s_container"
  resource.labels.namespace_name="falco"
  jsonPayload.rule="Shell Spawned in Semaphore Container"
' --limit=20 --format="table(timestamp, jsonPayload.output)"
```

### 9. CRITICAL Priority Alerts

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="falco"
jsonPayload.priority="CRITICAL"
```

**CLI**:
```bash
gcloud logging read '
  resource.type="k8s_container"
  resource.labels.namespace_name="falco"
  jsonPayload.priority="CRITICAL"
' --limit=20
```

### 10. Privilege Escalation Attempts

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="falco"
jsonPayload.rule="Semaphore Privilege Escalation Attempt"
```

### 11. Suspicious File Writes

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="falco"
jsonPayload.rule="Unexpected File Write in Semaphore"
```

### 12. Alerts in Specific Pod

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="falco"
jsonPayload.output=~"pod=guard-.*"
```

### 13. Alerts by Specific User

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="falco"
jsonPayload.output=~"user=root"
```

## GKE System Queries

### 14. GKE Node Logs

**Console Query**:
```
resource.type="k8s_node"
resource.labels.cluster_name="semaphore-hardened"
```

### 15. Kubernetes API Server Logs

**Console Query**:
```
resource.type="k8s_cluster"
log_name="projects/PROJECT_ID/logs/events"
```

### 16. Pod Scheduling Events

**Console Query**:
```
resource.type="k8s_pod"
jsonPayload.reason="Scheduled"
```

### 17. Pod Crashes (OOMKilled, CrashLoopBackOff)

**Console Query**:
```
resource.type="k8s_pod"
jsonPayload.reason=~"(OOMKilled|CrashLoopBackOff|Error)"
```

### 18. Container Image Pull Events

**Console Query**:
```
resource.type="k8s_node"
jsonPayload.message=~"(Pulling|Pulled) image"
```

## Performance and Debugging Queries

### 19. Slow Queries (if application logs them)

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="default"
jsonPayload.duration>1000
```

### 20. HTTP 5xx Errors

**Console Query**:
```
resource.type="k8s_container"
resource.labels.namespace_name="default"
jsonPayload.status>=500
jsonPayload.status<600
```

### 21. Memory Pressure Events

**Console Query**:
```
resource.type="k8s_node"
jsonPayload.reason="MemoryPressure"
```

### 22. Network Policy Denials (if logged)

**Console Query**:
```
resource.type="k8s_pod"
textPayload=~"connection refused"
```

## Time-based Queries

### 23. Last Hour

```
timestamp>="2025-11-14T12:00:00Z"
timestamp<"2025-11-14T13:00:00Z"
```

### 24. Last 24 Hours

```
timestamp>=timestamp("2025-11-13T13:00:00Z")
```

### 25. Specific Time Window

```
timestamp>="2025-11-14T10:00:00Z"
timestamp<"2025-11-14T11:00:00Z"
```

## Advanced Queries

### 26. Correlation: Falco Alert + Application Logs

**Step 1 - Get pod name from Falco alert**:
```
resource.type="k8s_container"
resource.labels.namespace_name="falco"
jsonPayload.rule="Shell Spawned in Semaphore Container"
```

**Step 2 - Query that pod's logs**:
```
resource.type="k8s_container"
resource.labels.pod_name="POD_NAME_FROM_STEP_1"
timestamp>="TIMESTAMP_FROM_STEP_1"
```

### 27. Aggregate Counts (CLI only)

```bash
# Count logs by severity
gcloud logging read '
  resource.type="k8s_container"
  resource.labels.namespace_name="default"
' --format="value(severity)" | sort | uniq -c
```

### 28. Export to JSON

```bash
gcloud logging read '
  resource.type="k8s_container"
  resource.labels.namespace_name="falco"
  jsonPayload.priority="CRITICAL"
' --format=json > falco-critical-alerts.json
```

### 29. Real-time Streaming

```bash
# Tail logs in real-time
gcloud logging tail '
  resource.type="k8s_container"
  resource.labels.namespace_name="default"
'
```

### 30. Log-based Metrics

Create a metric from logs (in Cloud Console):

**Name**: `semaphore_errors`
**Filter**:
```
resource.type="k8s_container"
resource.labels.namespace_name="default"
severity>=ERROR
```
**Metric Type**: Counter
**Labels**: `resource.labels.pod_name`, `severity`

## Query Optimization Tips

### Use Specific Resource Types
```
# Good (fast)
resource.type="k8s_container"
resource.labels.namespace_name="default"

# Bad (slow)
textPayload=~".*error.*"
```

### Limit Time Ranges
```
# Good
timestamp>="2025-11-14T12:00:00Z"

# Bad (scans all historical data)
# No timestamp filter
```

### Use Labels Over Text Search
```
# Good
resource.labels.pod_name=~"guard-.*"

# Less efficient
textPayload=~".*guard.*"
```

### Order Filters by Selectivity
```
# Good (most selective first)
resource.type="k8s_container"
resource.labels.namespace_name="falco"
jsonPayload.priority="CRITICAL"

# Less efficient
jsonPayload.priority="CRITICAL"
resource.type="k8s_container"
```

## Export and Long-term Storage

### Export to BigQuery

```bash
# Create BigQuery dataset
bq mk --dataset --location=US semaphore_logs

# Create log sink to BigQuery
gcloud logging sinks create semaphore-logs-sink \
  bigquery.googleapis.com/projects/PROJECT_ID/datasets/semaphore_logs \
  --log-filter='resource.type="k8s_container" resource.labels.namespace_name="default"'
```

**Query in BigQuery**:
```sql
SELECT
  timestamp,
  resource.labels.pod_name,
  jsonPayload.message
FROM `PROJECT_ID.semaphore_logs.k8s_container_*`
WHERE DATE(timestamp) = CURRENT_DATE()
  AND severity = 'ERROR'
ORDER BY timestamp DESC
LIMIT 100
```

### Export to Cloud Storage

```bash
gcloud logging sinks create semaphore-logs-archive \
  storage.googleapis.com/semaphore-logs-archive \
  --log-filter='resource.type="k8s_container" resource.labels.namespace_name="default"'
```

## Alerting Policies from Logs

### Alert on Critical Falco Events

**In Cloud Console: Monitoring → Alerting → Create Policy**

**Condition**:
- Metric: `logging.googleapis.com/user/falco_critical_alerts` (log-based metric)
- Filter: `resource.type="k8s_container" AND jsonPayload.priority="CRITICAL"`
- Threshold: Any occurrence

**Notification Channels**: Email, Slack, PagerDuty

### Alert on High Error Rate

**Condition**:
- Metric: `logging.googleapis.com/user/semaphore_errors`
- Filter: `resource.type="k8s_container" AND severity>=ERROR`
- Threshold: > 10 errors/minute

## CLI Shortcuts

Add to your `.bashrc` or `.zshrc`:

```bash
# Alias for common queries
alias falco-alerts='gcloud logging read "resource.type=\"k8s_container\" resource.labels.namespace_name=\"falco\" jsonPayload.priority=\"CRITICAL\"" --limit=20'

alias semaphore-errors='gcloud logging read "resource.type=\"k8s_container\" resource.labels.namespace_name=\"default\" severity>=ERROR" --limit=50'

alias tail-guard='gcloud logging tail "resource.type=\"k8s_container\" labels.k8s-pod/app=\"guard\""'
```

## References

- **Cloud Logging Query Language**: https://cloud.google.com/logging/docs/view/logging-query-language
- **Resource Types**: https://cloud.google.com/logging/docs/api/v2/resource-list
- **gcloud logging CLI**: https://cloud.google.com/sdk/gcloud/reference/logging
- **Log-based Metrics**: https://cloud.google.com/logging/docs/logs-based-metrics

---

**Pro Tip**: Save frequently used queries as **"Saved Searches"** in Cloud Console for quick access.
