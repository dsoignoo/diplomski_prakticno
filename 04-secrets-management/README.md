# Secrets Management

Ovaj direktorij sadrži primjere sigurnog upravljanja tajnama (secrets) u Kubernetes okruženju.

## Sadržaj

- `pod-security-context.yaml` - Pod sa sigurnosnim kontekstom
- `external-secrets.yaml` - Integracija sa eksternim secret management sistemima
- `sealed-secrets.yaml` - Sealed Secrets za Git-friendly enkriptirane tajne

## Best Practices

1. **Nikada ne commitujte secrets u Git** - koristite Sealed Secrets ili External Secrets
2. **Koristite RBAC** za ograničavanje pristupa secrets
3. **Rotirajte secrets redovno**
4. **Koristite Workload Identity** umjesto statičkih credentials gdje je moguće
