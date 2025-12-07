# Cloud-Native Security - GKE Specifične Sigurnosne Kontrole

## Pregled

Ova faza demonstrira korištenje cloud-native sigurnosnih servisa koje pruža Google Cloud Platform (GKE):

1. **GKE Security Command Center** - Centralizovani security monitoring i compliance
2. **Workload Identity** - Secure authentication bez static credentials
3. **Binary Authorization** - Image signature verification prije deployment-a
4. **Security Posture Management** - Continuous compliance monitoring
5. **GKE Security Dashboards** - Integrisani security insights

## Arhitektura

```
┌─────────────────────────────────────────────────────────────┐
│                    Google Cloud Console                      │
│                  Security Command Center                     │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        v                v                v
┌───────────────┐  ┌──────────────┐  ┌──────────────┐
│   Findings    │  │  Compliance  │  │   Threats    │
│  (CVEs, Misc) │  │   (CIS GKE)  │  │  (Anomalies) │
└───────┬───────┘  └──────┬───────┘  └──────┬───────┘
        │                 │                  │
        └─────────────────┴──────────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        │                                   │
        v                                   v
┌─────────────────┐              ┌─────────────────┐
│  GKE Autopilot  │              │  Cloud Logging  │
│    Cluster      │──────────────│   & Monitoring  │
└────────┬────────┘              └────────┬────────┘
         │                                │
    ┌────┴────┐                      ┌────┴────┐
    v         v                      v         v
┌───────┐ ┌──────────┐        ┌─────────┐ ┌────────┐
│ Falco │ │ Network  │        │  SIEM   │ │ Alert  │
│       │ │ Policies │        │   ELK   │ │Manager │
└───────┘ └──────────┘        └─────────┘ └────────┘
```

## 1. GKE Security Command Center

### Automatski Findings

Security Command Center automatski detektuje:

- **Vulnerabilities**: CVE-ovi u container image-ima
- **Misconfigurations**: Nesigurne Kubernetes konfiguracije
- **Public IPs**: Resursi sa javnim IP adresama
- **Open Firewall Rules**: Previše permisivni firewall rulovi
- **Anomalous Behavior**: Neuobičajene aktivnosti bazirane na ML

### Enabling Security Command Center

```bash
# Enable Security Command Center API
gcloud services enable securitycenter.googleapis.com

# Enable Container Scanning
gcloud services enable containerscanning.googleapis.com

# Enable Security Command Center for project
gcloud scc settings services modules enable \
    --project=YOUR_PROJECT_ID \
    --service=security-health-analytics \
    --module=CONTAINER_SCANNING

# Enable GKE Security Posture
gcloud container clusters update semaphore-autopilot \
    --enable-security-posture \
    --enable-workload-vulnerability-scanning \
    --region=us-central1
```

### Konfiguracija u Terraform

Već konfigurisano u `02-infrastructure-security/gke-hardened/terraform/main.tf`:

```hcl
resource "google_container_cluster" "primary" {
  # ...

  # Security Posture Management
  security_posture_config {
    mode               = "ENTERPRISE"
    vulnerability_mode = "VULNERABILITY_ENTERPRISE"
  }

  # Binary Authorization
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }
}
```

### Viewing Security Findings

```bash
# List all security findings
gcloud scc findings list \
    --organization=YOUR_ORG_ID \
    --filter="category=\"CONTAINER_VULNERABILITY\""

# Export findings to JSON
gcloud scc findings list \
    --organization=YOUR_ORG_ID \
    --format=json > security-findings.json
```

## 2. Workload Identity

Omogućava Kubernetes Service Accounts da koriste Google Cloud service accounts bez potrebe za ključevima.

### Konfiguracija

```bash
# Create Google Service Account
gcloud iam service-accounts create semaphore-sa \
    --project=YOUR_PROJECT_ID

# Grant necessary permissions (minimal - Cloud SQL, GCS)
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:semaphore-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/cloudsql.client"

# Bind Kubernetes SA to Google SA
gcloud iam service-accounts add-iam-policy-binding \
    semaphore-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com \
    --role roles/iam.workloadIdentityUser \
    --member "serviceAccount:YOUR_PROJECT_ID.svc.id.goog[semaphore/guard]"

# Annotate Kubernetes Service Account
kubectl annotate serviceaccount guard \
    --namespace semaphore \
    iam.gke.io/gcp-service-account=semaphore-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

Vidi `workload-identity/semaphore-workload-identity.yaml` za YAML konfiguraciju.

## 3. Binary Authorization

Enforces deployment policies - samo signed i verified image-i mogu biti pokrenuti.

### Setup Binary Authorization

```bash
# Enable Binary Authorization API
gcloud services enable binaryauthorization.googleapis.com

# Create attestor (koji će potpisivati image-e)
gcloud container binauthz attestors create semaphore-attestor \
    --project=YOUR_PROJECT_ID \
    --attestation-authority-note=semaphore-note \
    --attestation-authority-note-project=YOUR_PROJECT_ID

# Create signing key (Cosign key)
cosign generate-key-pair

# Create policy (samo signed images)
cat > /tmp/policy.yaml <<EOF
defaultAdmissionRule:
  evaluationMode: REQUIRE_ATTESTATION
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
  requireAttestationsBy:
    - projects/YOUR_PROJECT_ID/attestors/semaphore-attestor
EOF

gcloud container binauthz policy import /tmp/policy.yaml
```

Vidi `binary-authorization/binauthz-policy.yaml` za detalje.

## 4. Security Posture Dashboard

### Compliance Standards

Security Posture automatski provjerava compliance sa:

- **CIS GKE Benchmark** - Industry standard za GKE security
- **PCI-DSS** - Payment Card Industry compliance
- **NIST 800-53** - Federal security controls

### Viewing Compliance Status

```bash
# Get compliance status
gcloud container clusters describe semaphore-autopilot \
    --region=us-central1 \
    --format="value(securityPostureConfig)"

# List compliance violations
gcloud scc findings list \
    --organization=YOUR_ORG_ID \
    --filter="category=\"POSTURE_VIOLATION\""
```

### Key Compliance Checks

1. **Network Policies Enabled** ✅
   - Default-deny policies configured
   - Egress restrictions in place

2. **Pod Security Standards** ✅
   - No privileged containers (osim Falco)
   - ReadOnlyRootFilesystem where possible
   - RunAsNonRoot enforced

3. **Secrets Management** ✅
   - Secrets encrypted at rest (GKE default)
   - External Secrets Operator za rotation
   - Workload Identity umjesto service account keys

4. **Binary Authorization** ✅
   - Image signing enforced
   - SBOM generation
   - Vulnerability scanning before deployment

5. **Audit Logging Enabled** ✅
   - Cloud Audit Logs enabled
   - Kubernetes audit policy configured

## 5. Threat Detection

### GKE Threat Detection

Automatski detektuje:

- **Cryptocurrency mining** aktivnosti
- **Malware** u containerima
- **Data exfiltration** pokušaje
- **Brute force** napade
- **Lateral movement**

### Integration sa SIEM

Security Command Center findings se automatski forwarduju u Cloud Logging, odakle Filebeat shipuje u Elasticsearch.

```yaml
# Cloud Logging → Elasticsearch pipeline
apiVersion: v1
kind: ConfigMap
metadata:
  name: filebeat-gcp-module
data:
  gcp.yml: |-
    - module: gcp
      audit:
        enabled: true
        var.project_id: YOUR_PROJECT_ID
        var.topic: gcp-audit-logs

      # Security Command Center findings
      securitycenter:
        enabled: true
        var.project_id: YOUR_PROJECT_ID
        var.topic: scc-findings
```

## 6. Incident Response Playbooks

### Critical CVE Detected

1. **Alert**: Security Command Center detektuje CRITICAL CVE u running container
2. **Auto-response**:
   ```bash
   # Get pod sa vulnerable image
   kubectl get pods -n semaphore -o json | \
     jq -r '.items[] | select(.spec.containers[].image | contains("vulnerable-image")) | .metadata.name'

   # Immediate action: Cordon node, delete pod
   kubectl cordon NODE_NAME
   kubectl delete pod VULNERABLE_POD -n semaphore
   ```
3. **Remediation**: Rebuild image sa patched base image, rescan, redeploy

### Unauthorized Secret Access

1. **Alert**: Falco + K8s Audit Log detektuje unauthorized secret access
2. **Investigation**:
   ```bash
   # Check audit logs
   kubectl logs -n kube-system kube-apiserver-xxx | grep "secrets" | grep "403"

   # Check Falco events
   kubectl logs -n falco -l app=falco | grep "secret"
   ```
3. **Response**:
   - Revoke compromised credentials
   - Rotate secrets immediately
   - Investigate blast radius

### Crypto Mining Detected

1. **Alert**: Security Command Center detektuje cryptocurrency mining pattern
2. **Auto-response**:
   ```bash
   # Kill suspicious pod
   kubectl delete pod SUSPICIOUS_POD -n semaphore --force

   # Block image
   kubectl patch deployment DEPLOYMENT -n semaphore -p \
     '{"spec":{"template":{"spec":{"containers":[{"name":"container","image":"SAFE_IMAGE"}]}}}}'
   ```

## 7. Cost Optimization

### Security Command Center Tiers

- **Standard Tier**: FREE
  - Basic vulnerability scanning
  - Misconfigurations
  - Basic threat detection

- **Premium Tier**: ~$15/month per project
  - Advanced threat detection
  - Compliance dashboards
  - Event Threat Detection
  - Security Health Analytics

**Preporuka**: Koristiti Standard tier za diplomski (besplatan, dovoljan za demonstraciju).

## 8. Monitoring i Metrike

### Key Security Metrics

```promql
# Security findings count
sum(gcp_security_command_center_findings_total) by (category, severity)

# Compliance violations
sum(gcp_security_posture_violations_total) by (standard, control)

# Binary Authorization denials
sum(rate(binauthz_policy_evaluation_total{result="deny"}[5m]))

# Workload Identity requests
sum(rate(workload_identity_federation_requests_total[5m]))
```

### Dashboards

Vidi `security-posture/gke-security-dashboard.json` za Grafana dashboard koji prikazuje:
- Security findings timeline
- CIS GKE compliance score
- Binary Authorization policy evaluations
- Workload Identity usage

## 9. Best Practices

### Security Hardening Checklist

- [x] **GKE Autopilot** - Managed control plane
- [x] **Workload Identity** - No service account keys
- [x] **Binary Authorization** - Signed images only
- [x] **Network Policies** - Default-deny + allow rules
- [x] **Pod Security Standards** - Restricted PSS
- [x] **Secrets Encryption** - KMS encryption at rest
- [x] **Audit Logging** - Full audit logs enabled
- [x] **Security Posture** - Continuous compliance monitoring
- [x] **Vulnerability Scanning** - Container Analysis enabled
- [x] **Threat Detection** - Security Command Center enabled

### Continuous Improvement

1. **Weekly**: Review Security Command Center findings
2. **Monthly**: Update base images, rotate credentials
3. **Quarterly**: Review compliance reports, update policies
4. **On CVE**: Immediate patch and redeploy

## Reference

- [GKE Security Hardening Guide](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)
- [Security Command Center Docs](https://cloud.google.com/security-command-center/docs)
- [Binary Authorization](https://cloud.google.com/binary-authorization/docs)
- [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [CIS GKE Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
