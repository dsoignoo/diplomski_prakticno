  Automated deployment script that:
  - Validates prerequisites
  - Configures GCP project
  - Enables required APIs
  - Prompts for DNS/SSL configuration
  - Deploys infrastructure via Terraform
  - Deploys Semaphore via Helm
  - Retrieves and displays credentials
  - Validates deployment

  Key Highlights

  Successfully Deployed:
  - ✅ 66 pods running (1 expected failure)
  - ✅ GKE cluster with Cloud NAT
  - ✅ Let's Encrypt wildcard SSL
  - ✅ GKE Ingress with static IP
  - ✅ Semaphore v1.5.0 accessible at https://hamir.online

  Credentials:
  - Email: admin@hamir.online
  - Password: VGktkau-IjbLhm3MrweZafRyWGA=
  - API Token: 0-Zmo5VCm0fmmYGHqHX7

  Intentional Vulnerabilities Documented:
  - Network Security (no NetworkPolicies, exposed master API)
  - Access Control (no auth integration, single root user)
  - Runtime Security (no Falco, no PSS)
  - Secrets Management (base64 only)
  - Observability (minimal logging)
  - Image Security (no scanning/signing)
  - Data Protection (no backups)
  - Cluster Hardening (legacy datapath)

  This baseline serves as the foundation for demonstrating measurable security improvements in your thesis!
