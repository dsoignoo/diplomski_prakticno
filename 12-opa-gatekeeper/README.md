# OPA Gatekeeper

OPA (Open Policy Agent) Gatekeeper omogućava policy-as-code pristup za Kubernetes admission control.

## Instalacija

```bash
# Helm instalacija
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper --name-template=gatekeeper --namespace gatekeeper-system --create-namespace
```

## Sadržaj

- `constraint-templates/` - ConstraintTemplate definicije (Rego politike)
- `constraints/` - Constraint instance za Semaphore namespace
- `test-policies.sh` - Skripta za testiranje politika

## ConstraintTemplates

| Template | Opis |
|----------|------|
| `K8sPSPPrivilegedContainer` | Zabranjuje privilegovane kontejnere |
| `K8sRequiredResources` | Zahtijeva CPU/memory limits |
| `K8sBlockNodePort` | Blokira NodePort servise |
| `K8sRequiredLabels` | Zahtijeva obavezne labele |

## Testiranje

```bash
# Test privilegovanog poda (treba biti blokiran)
kubectl apply -f test-privileged-pod.yaml
# Error: admission webhook denied...
```
