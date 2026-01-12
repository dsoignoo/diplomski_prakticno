# Diplomski Rad - Dijagrami i Vizuelizacije

Ovaj direktorij sadrži sve dijagrame korištene u diplomskom radu o sigurnosti Kubernetes-a i servisa u javnom oblaku.

## Struktura direktorija

```
figures/
├── diagrams/           # Python skriptovi za kreiranje dijagrama
├── generated/          # Generirani PNG dijagrami
└── README.md          # Ova dokumentacija
```

## Python Dijagrami (diagrams/)

Svi dijagrami su kreirani koristeći Python `diagrams` biblioteku koja omogućava kreiranje profesionalnih arhitektonskih dijagrama sa standardnim ikonima.

### Upravljanje dijagramima

1. **Kreiranje novog dijagrama:**
```bash
cd figures/diagrams/
python naziv_dijagrama.py
```

2. **Kreiranje svih dijagrama odjednom:**
```bash
# Iz glavnog direktorija diplomski/
./generate_python_diagrams.sh
```

### Lista dijagrama

| Fajl | Opis | Koristi se u |
|------|------|--------------|
| `kubernetes_architecture.py` | Osnovna Kubernetes arhitektura | Poglavlje 1 |
| `kubernetes_resources.py` | Kubernetes resursi i objekti | Poglavlje 1 |
| `kubernetes_security_architecture.py` | Sigurnosna arhitektura Kubernetes-a | Poglavlje 2 |
| `threat_model_semaphore.py` | STRIDE model prijetnji za Semaphore | Poglavlje 2 |
| `semaphore_security_architecture.py` | Sigurnosna arhitektura Semaphore platforme | Poglavlje 2 |
| `ingress_architecture.py` | Ingress arhitektura i sigurnost | Poglavlje 3 |
| `bastion_host_architecture.py` | Bastion host arhitektura | Poglavlje 3 |
| `metadata_api_attack_vectors.py` | Napadi na metadata API | Poglavlje 3 |
| `cicd_security_pipeline.py` | CI/CD sigurnosni pipeline | Poglavlje 4 |
| `devsecops_semaphore_pipeline.py` | DevSecOps pipeline na Semaphore | Poglavlje 4 |
| `devsecops_workflow.py` | DevSecOps radni tok | Poglavlje 4 |
| `devsecops_simple.py` | Pojednostavljeni DevSecOps | Poglavlje 4 |
| `sdlc_security_controls.py` | SDLC sigurnosne kontrole | Poglavlje 4 |
| `semaphore_network_policies.py` | Network Policies na Semaphore | Poglavlje 6 |
| `observability_architecture.py` | Observability arhitektura | Poglavlje 7 |
| `threat_detection_stack.py` | Stack za detekciju prijetnji | Poglavlje 7 |
| `ids_ips_architecture.py` | IDS/IPS arhitektura | Poglavlje 7 |
| `mitre_attack_chain.py` | MITRE ATT&CK lanac napada | Poglavlje 8 |

## Generirani dijagrami (generated/)

Ovaj direktorij sadrži PNG fajlove generirane iz Python skriptova. Ovi fajlovi se koriste direktno u LaTeX dokumentu.

### Konvencije imenovanja

- Imena fajlova odgovaraju imenima Python skriptova (bez .py ekstenzije)
- Format: PNG (optimalno za LaTeX)
- Rezolucija: Visoka kvaliteta za štampu

## Korišćenje u LaTeX-u

Dijagrami se uključuju u LaTeX dokument pomoću:

```latex
\input{figures/naziv_dijagrama}
```

Gdje svaki `figures/naziv_dijagrama.tex` fajl sadrži LaTeX kod za uključivanje PNG dijagrama.

## Zavisnosti

Za kreiranje dijagrama potrebno je:

```bash
pip install diagrams
```

## Napomene

- Svi dijagrami koriste službene ikone za Kubernetes, AWS, Google Cloud, itd.
- Boje i stilovi su konzistentni kroz sve dijagrame
- Tekst na dijagramima je na bosanskom jeziku prema zahtjevima diplomskog rada
- Dijagrami su optimizovani za B&W štampu ali funkcioniraju i u boji