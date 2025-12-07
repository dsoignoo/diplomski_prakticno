# Ingress Security

Ovaj direktorij sadrži konfiguracije za sigurno izlaganje servisa putem Ingress-a.

## Sadržaj

- `ddos-protected-ingress.yaml` - Ingress sa DDoS zaštitom (rate limiting)
- `ssl-tls-ingress.yaml` - Ingress sa SSL/TLS i cert-manager integracijom
- `cert-manager-issuer.yaml` - Let's Encrypt ClusterIssuer

## DDoS Zaštita

Rate limiting parametri:
- `limit-rps`: Maksimalni broj zahtjeva po sekundi po IP adresi
- `limit-connections`: Maksimalni broj istovremenih konekcija
- `proxy-body-size`: Maksimalna veličina request body-ja

## TLS Best Practices

1. Koristite TLS 1.2+ (TLS 1.3 preporučeno)
2. Forsirajte HTTPS redirect
3. Koristite HSTS header
4. Automatski renew certifikata sa cert-manager
