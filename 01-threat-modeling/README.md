# Phase 01: Threat Modeling

## Overview

This phase performs comprehensive threat modeling of the Semaphore CI/CD platform to identify security vulnerabilities and prioritize security controls for subsequent implementation phases.

## Methodology

We employ multiple threat modeling frameworks:

1. **STRIDE** - Systematic threat categorization (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
2. **MITRE ATT&CK for Containers** - Mapping to real-world adversary tactics and techniques
3. **Attack Trees** - Visualizing multi-step attack paths
4. **Data Flow Diagrams** - Understanding trust boundaries and attack surface

## Semaphore Architecture Overview

### System Components

**External-Facing Services:**
- **Emissary Ingress** - TLS termination, routing (`*.semaphore.local`)
- **Front (Web UI)** - Node.js/Express application, user authentication entry point

**Core Application Services (Elixir/Phoenix):**
- **Guard** - Authentication/authorization service (JWT tokens, session management)
- **Controller** - Job orchestration, agent communication, workflow execution
- **ProjectHub** - Git repository integration, webhook processing
- **ArtifactHub** - Build artifact storage/retrieval
- **RepositoryHub** - Source code caching
- **BranchHub** - Branch/commit tracking

**Data Layer:**
- **PostgreSQL** - Primary database (users, projects, jobs, secrets)
- **RabbitMQ** - Message queue (async job processing)
- **Redis** - Session cache, rate limiting
- **MinIO** - Object storage (logs, artifacts, Docker layer cache)

**External Integrations:**
- **GitHub/GitLab** - Source code webhooks
- **Docker Registry** - Container image pulls
- **Cloud Provider APIs** - Infrastructure provisioning

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│ Internet (Untrusted)                                    │
│   - End users                                           │
│   - Git webhooks                                        │
│   - External registries                                 │
└─────────────────┬───────────────────────────────────────┘
                  │ HTTPS (TLS)
┌─────────────────▼───────────────────────────────────────┐
│ Kubernetes Ingress (Trust Boundary 1)                   │
│   - Emissary/Ambassador                                 │
└─────────────────┬───────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────┐
│ Application Layer (Trust Boundary 2)                    │
│   - Front, Guard, Controller, *Hub services             │
│   - Service-to-service communication (HTTP)             │
└─────────────────┬───────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────┐
│ Data Layer (Trust Boundary 3)                           │
│   - PostgreSQL, RabbitMQ, Redis, MinIO                  │
│   - Database credentials, encryption keys               │
└─────────────────────────────────────────────────────────┘
```

### Critical Data Flows

1. **User Authentication Flow:**
   - User → Emissary → Front → Guard → PostgreSQL
   - Returns JWT token, stored in Redis session

2. **Job Execution Flow:**
   - Webhook → Emissary → ProjectHub → RabbitMQ → Controller → Kubernetes (Agent Pods)
   - Agents pull code from RepositoryHub, push artifacts to ArtifactHub

3. **Secret Access Flow:**
   - Controller → PostgreSQL (encrypted secrets) → Injected into agent pods as env vars

4. **Build Artifact Flow:**
   - Agent → ArtifactHub → MinIO → External download

## STRIDE Analysis

### Spoofing Threats

| Component | Threat | Baseline Risk | Attack Scenario |
|-----------|--------|---------------|-----------------|
| **Front** | User impersonation via stolen credentials | **HIGH** | Attacker steals session token, gains full user access (no MFA) |
| **Guard** | JWT token forgery | **MEDIUM** | Weak signing key allows forged tokens with elevated privileges |
| **Controller** | Agent pod spoofing | **HIGH** | Malicious pod claims to be legitimate agent, exfiltrates secrets |
| **ProjectHub** | Webhook spoofing | **MEDIUM** | Attacker sends fake GitHub webhook, triggers malicious build |
| **PostgreSQL** | Service account impersonation | **MEDIUM** | Compromised pod uses shared DB credentials to access all data |
| **Emissary** | SNI routing abuse | **LOW** | Attacker routes traffic to unintended backend via Host header manipulation |

**MITRE ATT&CK Mapping:**
- **T1078** - Valid Accounts (stolen credentials)
- **T1552.007** - Container API (service account tokens)

### Tampering Threats

| Component | Threat | Baseline Risk | Attack Scenario |
|-----------|--------|---------------|-----------------|
| **Controller** | Job definition modification | **HIGH** | Attacker modifies YAML config to inject malicious commands |
| **RepositoryHub** | Source code tampering | **CRITICAL** | Man-in-the-middle attack on Git clone, injects backdoor |
| **ArtifactHub** | Build artifact replacement | **HIGH** | Attacker replaces legitimate build with malicious binary |
| **PostgreSQL** | Database tampering | **CRITICAL** | Direct DB access allows modification of user roles, secrets |
| **RabbitMQ** | Message queue poisoning | **MEDIUM** | Inject malicious job messages, trigger unintended workflows |
| **MinIO** | Object storage tampering | **HIGH** | Modify stored artifacts, logs to hide malicious activity |

**MITRE ATT&CK Mapping:**
- **T1565.001** - Stored Data Manipulation
- **T1525** - Implant Internal Image (malicious container images)

### Repudiation Threats

| Component | Threat | Baseline Risk | Attack Scenario |
|-----------|--------|---------------|-----------------|
| **Front** | User action logging gaps | **MEDIUM** | Attacker deletes project, no audit trail of who performed action |
| **Controller** | Job execution logging | **LOW** | Baseline logs exist, but not immutable or centralized |
| **PostgreSQL** | Database audit trail | **HIGH** | No database-level audit logging enabled by default |
| **Guard** | Authentication events | **MEDIUM** | Failed login attempts not aggregated or alerted |

**MITRE ATT&CK Mapping:**
- **T1070** - Indicator Removal (log deletion)
- **T1562.001** - Disable or Modify Tools (disable logging)

### Information Disclosure Threats

| Component | Threat | Baseline Risk | Attack Scenario |
|-----------|--------|---------------|-----------------|
| **PostgreSQL** | Secret exposure in database | **CRITICAL** | Secrets stored in plaintext/weakly encrypted, exfiltrated via SQL injection |
| **Controller** | Secrets in pod env vars | **HIGH** | `kubectl get pod -o yaml` reveals secrets in environment variables |
| **MinIO** | Unrestricted bucket access | **MEDIUM** | Default credentials or overly permissive policies allow data access |
| **Front** | Session token exposure | **MEDIUM** | XSS attack steals session cookie, no HttpOnly/Secure flags |
| **RabbitMQ** | Message interception | **MEDIUM** | Unencrypted inter-service traffic allows sniffing of job data |
| **ArtifactHub** | Public artifact exposure | **HIGH** | Misconfigured bucket allows unauthenticated download of proprietary code |
| **Redis** | Session hijacking via cache | **MEDIUM** | Direct Redis access allows session token enumeration |

**MITRE ATT&CK Mapping:**
- **T1552.001** - Credentials In Files (secrets in configs)
- **T1552.007** - Container API (Kubernetes secret access)
- **T1040** - Network Sniffing (unencrypted traffic)

### Denial of Service Threats

| Component | Threat | Baseline Risk | Attack Scenario |
|-----------|--------|---------------|-----------------|
| **Controller** | Resource exhaustion | **HIGH** | Attacker spawns unlimited agent pods, exhausts cluster resources |
| **RabbitMQ** | Queue flooding | **MEDIUM** | Flood queue with fake jobs, prevents legitimate job processing |
| **PostgreSQL** | Connection pool exhaustion | **MEDIUM** | Open max connections, block all application access |
| **Emissary** | HTTP flood | **LOW** | Rate limiting not configured, volumetric attack overwhelms ingress |
| **MinIO** | Storage exhaustion | **MEDIUM** | Upload massive artifacts, fill persistent volumes |

**MITRE ATT&CK Mapping:**
- **T1496** - Resource Hijacking (cryptomining in agent pods)
- **T1499** - Endpoint Denial of Service

### Elevation of Privilege Threats

| Component | Threat | Baseline Risk | Attack Scenario |
|-----------|--------|---------------|-----------------|
| **Agent Pods** | Container escape | **CRITICAL** | Privileged pod + kernel exploit → node compromise → cluster admin |
| **Controller** | RBAC bypass | **HIGH** | Overly permissive ServiceAccount allows secret access across namespaces |
| **PostgreSQL** | SQL injection → RCE | **HIGH** | Vulnerable query → `COPY TO PROGRAM` → shell access on DB pod |
| **Front** | XSS → admin session hijacking | **HIGH** | Stored XSS in project name → steal admin JWT → full cluster control |
| **Guard** | Authorization bypass | **MEDIUM** | Broken access control allows user to access other orgs' projects |
| **Kubernetes API** | Unauthenticated access | **CRITICAL** | Default RBAC allows anonymous access to cluster resources |

**MITRE ATT&CK Mapping:**
- **T1611** - Escape to Host (container breakout)
- **T1068** - Exploitation for Privilege Escalation
- **T1078.004** - Cloud Accounts (GKE metadata API abuse)

## Attack Scenarios by Severity

### Critical Risk Scenarios

#### Scenario 1: Container Escape → Cluster Takeover
**Attack Path:**
1. Attacker gains access to agent pod (via malicious project)
2. Exploits privileged container + kernel vulnerability (e.g., CVE-2022-0847 Dirty Pipe)
3. Escapes to host node, access node credentials
4. Uses node ServiceAccount token to access Kubernetes API
5. Reads all secrets, deploys cryptominer, exfiltrates source code

**Baseline Gaps:**
- No Pod Security Standards enforcement
- Privileged containers allowed
- Overly permissive RBAC
- No runtime security monitoring

**Mitigated by:**
- Phase 05: Pod Security Standards (restricted profile)
- Phase 06: Falco runtime detection
- Phase 02: GKE Shielded Nodes

---

#### Scenario 2: Database Compromise → Full Data Breach
**Attack Path:**
1. SQL injection in ProjectHub webhook processing
2. Exfiltrate PostgreSQL credentials from pod environment
3. Direct database connection from internet (no NetworkPolicy)
4. Extract all secrets (API keys, SSH keys, cloud credentials)
5. Decrypt weakly encrypted secrets offline

**Baseline Gaps:**
- Secrets stored in Kubernetes Secrets (base64, etcd unencrypted)
- No network segmentation
- Weak database encryption
- No database activity monitoring

**Mitigated by:**
- Phase 04: External Secrets Operator + Vault
- Phase 08: NetworkPolicies (deny direct DB access)
- Phase 07: PostgreSQL Exporter + anomaly detection

---

#### Scenario 3: Supply Chain Attack via Artifact Tampering
**Attack Path:**
1. Compromise ArtifactHub credentials (weak MinIO access keys)
2. Replace legitimate build artifact with backdoored version
3. Customer downloads malicious artifact
4. Backdoor exfiltrates customer secrets to attacker C2

**Baseline Gaps:**
- No image/artifact signing
- No SBOM or provenance tracking
- MinIO uses default credentials
- No integrity verification at download

**Mitigated by:**
- Phase 03: Cosign signing + verification
- Phase 03: Trivy SBOM generation
- Phase 04: Secrets rotation

---

### High Risk Scenarios

#### Scenario 4: Agent Pod Secret Exfiltration
**Attack Path:**
1. Malicious project YAML injects command to read `/var/run/secrets`
2. Agent pod has overly permissive RBAC (can list secrets)
3. Exfiltrates secrets via DNS tunneling (bypasses egress controls)

**Mitigated by:**
- Phase 05: Restricted PSS (block hostPath mounts)
- Phase 08: NetworkPolicy (egress restrictions)
- Phase 06: Falco (detect secret file access)

---

#### Scenario 5: Lateral Movement via Service-to-Service Attacks
**Attack Path:**
1. Compromise Front pod via XSS → RCE
2. No network segmentation allows direct access to PostgreSQL
3. Use application DB credentials to access all data
4. Pivot to RabbitMQ, inject malicious jobs

**Mitigated by:**
- Phase 08: Zero-trust NetworkPolicies
- Phase 02: Workload Identity (no long-lived credentials)
- Phase 07: Distributed tracing (detect anomalous service calls)

---

## MITRE ATT&CK Mapping Summary

| Tactic | Techniques | Semaphore Components at Risk |
|--------|-----------|------------------------------|
| **Initial Access** | T1190 (Exploit Public-Facing App) | Emissary, Front, ProjectHub webhooks |
| **Execution** | T1609 (Container Administration Command) | Controller, Agent pods |
| **Persistence** | T1525 (Implant Internal Image) | ArtifactHub, RepositoryHub |
| **Privilege Escalation** | T1611 (Escape to Host) | Agent pods, Controller |
| **Defense Evasion** | T1070 (Indicator Removal) | All pods (log deletion) |
| **Credential Access** | T1552 (Unsecured Credentials) | PostgreSQL, Kubernetes Secrets |
| **Discovery** | T1613 (Container API) | Kubernetes API Server |
| **Lateral Movement** | T1021 (Remote Services) | Inter-service HTTP communication |
| **Collection** | T1530 (Data from Cloud Storage) | MinIO, ArtifactHub |
| **Exfiltration** | T1537 (Transfer Data to Cloud Account) | Agent pods → external S3 |
| **Impact** | T1496 (Resource Hijacking) | Agent pods (cryptomining) |

## Threat Prioritization

### Risk Matrix

| Threat | Likelihood | Impact | Risk Score | Priority |
|--------|-----------|--------|------------|----------|
| Container escape | Medium | Critical | **9** | P0 |
| Database secret exfiltration | High | Critical | **12** | P0 |
| Artifact tampering | Medium | Critical | **9** | P0 |
| Agent pod secret access | High | High | **9** | P0 |
| Lateral movement (no segmentation) | High | High | **9** | P1 |
| SQL injection → RCE | Medium | High | **6** | P1 |
| Webhook spoofing | Medium | Medium | **4** | P2 |
| Session hijacking (no MFA) | High | Medium | **6** | P2 |
| RabbitMQ queue poisoning | Low | Medium | **2** | P3 |
| DoS via resource exhaustion | Medium | Medium | **4** | P3 |

**Risk Scoring:** Likelihood (Low=1, Med=2, High=3) × Impact (Low=1, Med=2, High=3, Critical=4)

## Security Control Mapping

This threat model drives the implementation priorities for subsequent phases:

| Threat Category | Security Controls (Phases) | Expected Risk Reduction |
|-----------------|---------------------------|-------------------------|
| **Container Escape** | Pod Security Standards (05), GKE Shielded Nodes (02), Falco (06) | 9 → 2 |
| **Secret Exposure** | External Secrets Operator (04), Workload Identity (09), encryption at rest | 12 → 3 |
| **Lateral Movement** | NetworkPolicies (08), Service Mesh mTLS (future) | 9 → 3 |
| **Supply Chain** | Trivy scanning (03), Cosign signing (03), Binary Authorization (09) | 9 → 2 |
| **Lack of Observability** | Prometheus/Grafana (07), Falco (06), audit logging (09) | N/A (enabler) |

## Attack Trees

See `attack-trees/` subdirectory for detailed attack path diagrams:
- `container-escape.md` - Paths to node compromise
- `secret-exfiltration.md` - Ways to steal secrets
- `supply-chain.md` - Artifact/image tampering scenarios

## Validation Criteria

After implementing security controls, we will validate threat mitigation by:

1. **Attack Simulation:**
   - Attempt container escape with restricted PSS
   - Try to access PostgreSQL from Front pod (should be blocked)
   - Test webhook spoofing detection

2. **Detection Testing:**
   - Trigger Falco alerts for privilege escalation attempts
   - Verify SIEM correlation of multi-stage attacks
   - Test audit log capture of sensitive operations

3. **Metrics:**
   - Mean Time to Detect (MTTD) for each threat scenario
   - False positive rate for detection rules
   - Coverage % of MITRE ATT&CK techniques

## References

- **STRIDE Methodology**: Microsoft Threat Modeling Tool
- **MITRE ATT&CK Containers**: https://attack.mitre.org/matrices/enterprise/containers/
- **Kubernetes Threat Matrix**: https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
- **CNCF Cloud Native Security Whitepaper**: https://github.com/cncf/tag-security/tree/main/security-whitepaper

## Next Steps

1. Review this threat model with security team/advisor
2. Prioritize P0/P1 threats for immediate mitigation
3. Begin Phase 02 (Infrastructure Security) to address container escape risks
4. Establish baseline security metrics before implementing controls
