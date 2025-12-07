# Kubernetes Security Controls for Semaphore CI/CD

This repository contains a practical implementation of Kubernetes security controls applied to the Semaphore CI/CD platform. It demonstrates securing a complex microservices application (15+ components) through progressive security phases.

**Thesis**: "Security of Kubernetes and Services in Public Cloud"
**University**: Faculty of Electrical Engineering, University of Sarajevo

## Repository Structure

```
diplomski_prakticno/
├── 00-semaphore-baseline/          # Baseline deployment documentation and scripts
├── 01-threat-modeling/             # STRIDE analysis, attack trees, security testing simulations
├── 02-infrastructure-security/     # GKE hardened cluster configurations (Terraform)
├── 03-cicd-security/               # Trivy scanning, image signing (Cosign), SBOM, SAST/DAST
├── 04-secrets-management/          # External Secrets Operator, Sealed Secrets configs
├── 05-pod-security-standards/      # PSS namespace policies, compliant deployments
├── 06-runtime-security/            # Falco deployment, custom rules, Falcosidekick
├── 07-observability-stack/         # Prometheus, Grafana, Loki, Jaeger configurations
├── 08-network-policies/            # Zero-trust NetworkPolicies, default-deny, testing framework
├── 09-ingress-security/            # TLS termination, cert-manager, DDoS protection
├── 10-threat-detection/            # SIEM integration, cloud-native threat detection
├── 11-backup-disaster-recovery/    # Velero backup schedules, DR testing scripts
├── 12-opa-gatekeeper/              # Constraint templates, constraints, policy testing
├── 13-devsecops-pipeline/          # Secure CI/CD pipeline examples (Semaphore, GitHub Actions, GitLab)
├── 14-cluster-hardening/           # CIS benchmark (kube-bench), cloud-specific hardening scripts
└── 99-documentation/               # Additional documentation and diagrams
```

## Security Controls Implemented

| Control | Directory | Description |
|---------|-----------|-------------|
| Network Segmentation | `08-network-policies/` | Zero-trust NetworkPolicies with default-deny |
| Runtime Security | `06-runtime-security/` | Falco anomaly detection with custom rules |
| Image Security | `03-cicd-security/` | Trivy vulnerability scanning, Cosign signing |
| Policy Enforcement | `12-opa-gatekeeper/` | OPA Gatekeeper constraint templates |
| Secrets Management | `04-secrets-management/` | External Secrets Operator integration |
| Observability | `07-observability-stack/` | Full monitoring stack with security dashboards |
| Backup/DR | `11-backup-disaster-recovery/` | Velero backup and restore procedures |
| Cluster Hardening | `14-cluster-hardening/` | CIS benchmark compliance |

## Quick Start

### Prerequisites

- Kubernetes cluster (1.28+)
- Helm 3+
- kubectl configured
- Terraform (for infrastructure)

### Deploy Network Policies

```bash
cd 08-network-policies
kubectl apply -f 00-default-deny.yaml
kubectl apply -f allow-dns-all.yaml
kubectl apply -f component-specific/
./test-network-policies.sh
```

### Deploy Falco Runtime Security

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  -f 06-runtime-security/falco-values.yaml
kubectl apply -f 06-runtime-security/custom-rules/
```

### Run Security Scan

```bash
cd 03-cicd-security
./scan-semaphore-images.sh
```

## Testing

### Network Policy Testing

```bash
cd 08-network-policies/testing-framework
./test-connectivity.sh
```

### Attack Simulations

```bash
cd 01-threat-modeling/security-testing
./run-all-simulations.sh
```

### Metrics Collection

```bash
cd 01-threat-modeling/security-testing
./collect-metrics-simple.sh
```

## Cloud Deployments

Terraform configurations for hardened GKE clusters are available in:

- `02-infrastructure-security/gke-hardened/terraform/` - Autopilot hardened
- `02-infrastructure-security/gke-standard-hardened/terraform/` - Standard mode hardened

## References

- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Falco Rules](https://github.com/falcosecurity/rules)

## License

MIT License
