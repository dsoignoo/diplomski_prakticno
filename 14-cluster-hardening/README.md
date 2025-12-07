# Cluster Hardening

Ovaj direktorij sadrži konfiguracije za učvršćivanje (hardening) Kubernetes klastera na različitim cloud providerima.

## Sadržaj

- `gke-hardened-cluster.sh` - GKE hardened cluster sa Workload Identity
- `eks-hardened-cluster.sh` - EKS hardened cluster sa IRSA
- `aks-hardened-cluster.sh` - AKS hardened cluster sa Azure AD
- `kube-bench-job.yaml` - CIS Benchmark provjera

## Sigurnosne kontrole

| Kontrola | GKE | EKS | AKS |
|----------|-----|-----|-----|
| Private cluster | ✅ | ✅ | ✅ |
| Workload Identity | ✅ | IRSA | Managed Identity |
| Network Policy | Calico | Calico/VPC CNI | Azure CNI |
| Shielded Nodes | ✅ | IMDSv2 | Trusted Launch |
| Binary Authorization | ✅ | - | - |
| Encryption at rest | CMEK | KMS | Azure Key Vault |

## CIS Benchmark

Koristite kube-bench za provjeru CIS Kubernetes Benchmark:

```bash
kubectl apply -f kube-bench-job.yaml
kubectl logs -l app=kube-bench
```
