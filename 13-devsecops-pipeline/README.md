# DevSecOps Pipeline

Ovaj direktorij sadrži kompletne CI/CD pipeline konfiguracije sa integriranim sigurnosnim skeniranjem.

## Faze Pipeline-a

1. **Build** - Build aplikacije i Docker image-a
2. **Security Scan** - Trivy vulnerability scanning
3. **SAST** - Static Application Security Testing
4. **Image Signing** - Cosign potpisivanje image-a
5. **SBOM** - Software Bill of Materials generisanje
6. **Deploy** - Kubernetes deployment sa verifikacijom

## Sadržaj

- `semaphore-devsecops.yml` - Kompletni DevSecOps pipeline za SemaphoreCI
- `github-actions-security.yml` - GitHub Actions security workflow
- `gitlab-ci-security.yml` - GitLab CI security pipeline

## Alati

| Alat | Namjena |
|------|---------|
| Trivy | Vulnerability scanning |
| Cosign | Image signing |
| Syft | SBOM generation |
| Gitleaks | Secret detection |
| Semgrep | SAST |
