# Pod Security Standards (PSS)

Kubernetes Pod Security Standards definišu tri nivoa sigurnosti:
- **Privileged**: Neograničena politika
- **Baseline**: Minimalno restriktivna, sprječava poznate eskalacije privilegija
- **Restricted**: Strogo ograničena, prati best practices za hardening podova

## Primjena na namespace

```bash
# Enforce restricted profile
kubectl label namespace semaphore \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

## Sadržaj

- `namespace-restricted.yaml` - Namespace sa restricted PSS
- `compliant-deployment.yaml` - Deployment koji zadovoljava restricted profile
- `psp-restricted-legacy.yaml` - Legacy PodSecurityPolicy (deprecated u K8s 1.25+)
