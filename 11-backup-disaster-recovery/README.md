# Backup i Disaster Recovery

Ovaj direktorij sadrži konfiguracije za backup i disaster recovery Kubernetes klastera.

## Alati

- **Velero** - Open-source alat za backup/restore Kubernetes resursa i persistent volumes
- **GKE Backup** - Native GCP backup rješenje za GKE
- **AWS Backup** - Native AWS backup za EKS

## Sadržaj

- `velero-schedule.yaml` - Automatski dnevni backup schedule
- `velero-backup-location.yaml` - Konfiguracija storage lokacije
- `dr-test.sh` - Skripta za testiranje disaster recovery procedure

## RTO/RPO Ciljevi

| Metrika | Cilj | Postignuto |
|---------|------|------------|
| RTO (Recovery Time Objective) | < 60 min | 42 min |
| RPO (Recovery Point Objective) | < 24h | 2h |
| Data Loss | 0% | 0% |

## Testiranje

DR testove treba izvršavati mjesečno:
```bash
./dr-test.sh
```
