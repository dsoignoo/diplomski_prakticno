# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains a practical implementation of Kubernetes security controls applied to the Semaphore CI/CD platform, as part of a master's thesis on "Security of Kubernetes and Services in Public Cloud". The project demonstrates securing a complex microservices application (15+ components) through three progressive security phases.

## Repository Structure

```
diplomski_prakticno/
├── semaphore/                      # Upstream Semaphore CI/CD platform (submodule)
│   ├── helm-chart/                 # Helm deployment configuration
│   ├── ephemeral_environment/      # Baseline deployment configs (GKE, EKS, single-VM)
│   └── [15+ microservices]         # front, guard, controller, projecthub, etc.
│
├── 00-semaphore-baseline/          # Baseline security posture documentation
├── 01-threat-modeling/             # STRIDE analysis and MITRE ATT&CK mapping
├── 02-infrastructure-security/     # Hardened cloud deployments (GKE, EKS, AKS)
├── 03-cicd-security/              # Trivy scanning, image signing, SBOM
├── 04-secrets-management/         # External Secrets Operator + Vault
├── 05-pod-security-standards/     # PSS policies and enforcement
├── 06-runtime-security/           # Falco deployment and custom rules
├── 07-observability-stack/        # Prometheus, Grafana, Loki, Jaeger
├── 08-network-policies/           # Zero-trust network segmentation
├── 09-cloud-native-security/      # Cloud-specific security (GKE SCC, Workload Identity)
├── 10-threat-detection/           # SIEM integration, honeypots
├── 11-backup-disaster-recovery/   # Velero, GKE Backup
├── 12-opa-gatekeeper/            # Policy enforcement
└── 13-devsecops-pipeline/        # Secure CI/CD pipeline examples
```

## Architecture

**Semaphore Platform Components:**
- **Front** - Web UI (Node.js)
- **Guard** - Authentication service (Elixir)
- **Controller** - Job orchestration (Elixir)
- **Hub services** - Repository, Artifact, Project, Branch hubs (Elixir)
- **Data layer** - PostgreSQL, RabbitMQ, Redis, MinIO
- **Ingress** - Emissary (Ambassador) for TLS termination

**Security Layers:**
1. **Network** - NetworkPolicies for zero-trust segmentation
2. **Runtime** - Falco for anomaly detection
3. **Access** - RBAC, Workload Identity, Pod Security Standards
4. **Data** - Secrets encryption, External Secrets Operator
5. **Observability** - Multi-signal correlation (metrics, logs, traces, SIEM)

## Common Commands

### Infrastructure Deployment

**Deploy baseline Semaphore on GKE:**
```bash
cd semaphore/ephemeral_environment/terraform/gke
terraform init
terraform apply -var="project_name=YOUR_PROJECT" \
  -var="path_to_private_key=cert.key" \
  -var="path_to_fullchain_cer=cert.pem"
gcloud container clusters get-credentials test-YOUR_BRANCH --region us-east4
helm install semaphore ../../../helm-chart --timeout 20m
```

**Deploy hardened GKE cluster:**
```bash
cd 02-infrastructure-security/gke-hardened/terraform
terraform init
terraform apply -var="project_id=YOUR_PROJECT" -var="cluster_name=semaphore-prod"
gcloud container clusters get-credentials semaphore-prod --region us-central1
```

### Security Controls Deployment

**Apply NetworkPolicies:**
```bash
cd 08-network-policies
kubectl apply -f 00-default-deny.yaml
kubectl apply -f allow-dns-all.yaml
kubectl apply -f component-specific/
```

**Deploy Falco runtime security:**
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=modern_ebpf \
  --set falcosidekick.enabled=true
```

**Deploy observability stack:**
```bash
cd 07-observability-stack/prometheus-grafana
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace
kubectl apply -f servicemonitors/semaphore-services.yaml
kubectl apply -f alerting-rules/semaphore-alerts.yaml
```

### Testing and Validation

**Test network policies:**
```bash
cd 08-network-policies/testing-framework
./test-network-policies.sh
```

**Test Falco detection:**
```bash
cd 06-runtime-security/testing
./test-shell-detection.sh  # Should trigger Falco alert
```

**Check GKE Security Command Center:**
```bash
cd 09-cloud-native-security/gke-security-command-center
./scc-setup.sh YOUR_PROJECT_ID YOUR_ORG_ID
gcloud scc findings list --organization=YOUR_ORG_ID --limit=10
```

## Development Workflow

### Working with Semaphore

The `semaphore/` directory is based on the open-source Semaphore CI/CD platform. Key services:

**Elixir services** (guard, controller, *hub services):
- Mix-based build system
- Phoenix framework
- RabbitMQ for async communication
- Ecto for database access

**Node.js services** (front):
- Express.js backend
- Vue.js frontend
- Webpack bundling

**Local development:**
```bash
cd semaphore
minikube start --cpus 8 --memory 16384 --profile semaphore
kubectl apply -f https://app.getambassador.io/yaml/emissary/3.9.1/emissary-crds.yaml
skaffold dev  # Hot-reload development
```

### Implementing Security Controls

When adding new security controls:

1. **Create directory structure** under appropriate phase (01-13)
2. **Include README.md** with:
   - Problem statement
   - Solution approach
   - Deployment steps
   - Validation/testing procedures
3. **Add to metrics tracking** in main README.md
4. **Test against baseline** to demonstrate improvement

### Terraform Modules

Terraform configurations follow a standard structure:
- `main.tf` - Primary resources
- `variables.tf` - Input variables
- `outputs.tf` - Output values
- `providers.tf` - Provider configuration

Always test with `terraform plan` before `apply`.

### Kubernetes Manifests

YAML files follow standard Kubernetes API conventions:
- Use `networking.k8s.io/v1` for NetworkPolicies
- Include labels: `app`, `component`, `monitoring: "true"`
- Add annotations for observability integration
- Reference existing Semaphore services by label selectors

## Key Implementation Patterns

### NetworkPolicy Pattern

Semaphore services communicate via label selectors:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: guard-policy
spec:
  podSelector:
    matchLabels:
      app: guard
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: front
    ports:
    - protocol: TCP
      port: 8080
```

### ServiceMonitor Pattern

Expose metrics for Prometheus scraping:
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: semaphore-services
  labels:
    release: kube-prometheus-stack
spec:
  selector:
    matchLabels:
      monitoring: "true"
  endpoints:
  - port: metrics
    interval: 15s
```

### Workload Identity Pattern

Bind Kubernetes ServiceAccounts to GCP Service Accounts:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: guard
  annotations:
    iam.gke.io/gcp-service-account: semaphore-guard-sa@PROJECT.iam.gserviceaccount.com
```

## Testing Philosophy

This project emphasizes **measurable security improvements**:

### Attack Simulations

Demonstrate vulnerabilities in baseline, then show mitigations:

**Before NetworkPolicies:**
```bash
kubectl exec -it deployment/front -- nc -zv postgres 5432  # SUCCESS (bad)
```

**After NetworkPolicies:**
```bash
kubectl exec -it deployment/front -- nc -zv postgres 5432  # TIMEOUT (blocked)
```

### Multi-Signal Correlation

Security events should be detectable across multiple observability signals:
1. **Prometheus** - Resource anomalies (high CPU)
2. **Falco** - Runtime behavior (shell execution)
3. **Loki** - Application logs (errors)
4. **Jaeger** - Request tracing (latency spikes)
5. **K8s Audit** - API access (unauthorized secret access)
6. **SIEM** - Event correlation (multi-stage attack detection)

## Important Constraints

### Cloud Costs

Project designed to fit within Google Cloud $300 free credits:
- Estimated monthly cost: ~$246 (all phases)
- GKE Autopilot: ~$105/mo
- Elasticsearch (SIEM): ~$200/mo
- Loki, Jaeger, monitoring: ~$40/mo combined

Use `terraform destroy` when not actively testing to minimize costs.

### Resource Requirements

**Minimum for full stack:**
- 6-8 vCPU
- 24-32 GB RAM
- 500 GB persistent storage
- 1 static IP address

**GKE Autopilot automatically scales** based on workload demands.

## Security Best Practices

### Secrets Management

NEVER commit secrets to this repository. Use:
- Environment variables for local testing
- Kubernetes secrets for cluster deployment
- External Secrets Operator for production
- Google Secret Manager or HashiCorp Vault as backend

### Image Security

All container images should be:
- Scanned with Trivy for vulnerabilities
- Signed with Cosign
- Verified via Binary Authorization (GKE)
- Run as non-root user
- Use minimal base images (alpine, distroless)

### Network Security

Default-deny NetworkPolicies should be applied FIRST, then allowlist specific traffic:
1. Apply `00-default-deny.yaml`
2. Apply `allow-dns-all.yaml` (DNS resolution)
3. Apply component-specific policies
4. Test connectivity with `test-network-policies.sh`

## Documentation Standards

When documenting security controls:

**Problem Statement**: What vulnerability exists in baseline?
**MITRE ATT&CK Mapping**: Which tactics/techniques does this mitigate?
**Solution**: What technology/control addresses the problem?
**Deployment**: Step-by-step implementation commands
**Validation**: How to verify the control is working?
**Metrics**: Before/after measurements (MTTD, MTTR, etc.)

## Reference Materials

- **Semaphore Docs**: https://docs.semaphoreci.com/CE/getting-started/about-semaphore
- **CIS Kubernetes Benchmark**: https://www.cisecurity.org/benchmark/kubernetes
- **MITRE ATT&CK**: https://attack.mitre.org/matrices/enterprise/containers/
- **Falco Rules**: https://github.com/falcosecurity/rules
- **Prometheus Operator**: https://prometheus-operator.dev/
- **GKE Security**: https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster

## Notes for AI Assistants

This repository represents a **master's thesis practical implementation**. When working with this code:

1. **Preserve educational value** - Comments and documentation are as important as code
2. **Maintain traceability** - Link security controls to specific threats/attacks
3. **Emphasize measurement** - Always provide before/after metrics
4. **Follow progressive phases** - Security is implemented incrementally (Phase 1 → 2 → 3)
5. **Real-world focus** - Solutions should be production-viable, not just proof-of-concept
6. **Cost-awareness** - Consider GCP free credits constraints
7. **Multi-cloud perspective** - While focused on GKE, patterns should be cloud-agnostic where possible

This is a **security research project**, not production code. Prioritize clarity, demonstrability, and educational completeness over optimization.
