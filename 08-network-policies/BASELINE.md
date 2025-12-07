# Network Security Baseline Assessment

**Date**: 2025-11-14
**Cluster**: semaphore-hardened (GKE Private Cluster)
**Phase**: Pre-NetworkPolicy Implementation

## Current Network Posture

### Network Policy Status
```bash
$ kubectl get networkpolicies -A
No resources found
```

**Finding**: **Zero network policies are currently deployed**. All pod-to-pod communication is unrestricted.

## Connectivity Testing

### Test 1: Frontend Access to Database (SHOULD BE BLOCKED)

**Test**: Can the front-end web UI directly access PostgreSQL?

```bash
$ kubectl exec -it deployment/front -n default -- nc -zv postgres 5432
postgres (10.8.0.12:5432) open
```

**Result**: ✅ **ACCESSIBLE** (🚨 **VULNERABLE**)

**Security Implication**: A compromised front-end container can:
- Read/modify all database records
- Extract user credentials
- Plant backdoors in database
- Exfiltrate sensitive CI/CD data

### Test 2: Arbitrary Pod Access to RabbitMQ (SHOULD BE BLOCKED)

**Test**: Can any pod access the message queue?

```bash
$ kubectl run test-pod --image=busybox --rm -it --restart=Never -- nc -zv rabbitmq 5672
rabbitmq (10.8.1.23:5672) open
```

**Result**: ✅ **ACCESSIBLE** (🚨 **VULNERABLE**)

**Security Implication**: A compromised pod can:
- Inject malicious messages into job queue
- Trigger unauthorized CI/CD pipeline executions
- Read sensitive build artifacts from queue
- Cause denial of service by flooding queues

### Test 3: Cross-Service Access (Guard to Controller)

**Test**: Can the Guard authentication service directly access the Controller job orchestrator?

```bash
$ kubectl exec -it deployment/guard-api -n default -- nc -zv controller-api 8080
controller-api (10.8.2.45:8080) open
```

**Result**: ✅ **ACCESSIBLE** (Expected, but unrestricted)

**Security Implication**: While some inter-service communication is legitimate:
- No enforcement of allowed communication paths
- Compromised microservice can impersonate any other service
- No visibility into lateral movement attempts

### Test 4: DNS Resolution (SHOULD ALWAYS WORK)

```bash
$ kubectl exec -it deployment/front -n default -- nslookup kubernetes.default
Server:    10.8.0.10
Address:   10.8.0.10:53

Name:      kubernetes.default.svc.cluster.local
Address:   10.8.0.1
```

**Result**: ✅ **WORKING** (Required)

## Current Architecture (No Network Policies)

```
┌────────────────────────────────────────────────────┐
│  GKE Cluster: semaphore-hardened                   │
│                                                    │
│  ┌──────┐     ┌──────┐     ┌──────┐              │
│  │Front │────▶│Guard │────▶│Ctrl  │              │
│  │ UI   │     │Auth  │     │Jobs  │              │
│  └───┬──┘     └───┬──┘     └───┬──┘              │
│      │            │            │                   │
│      │ UNRESTRICTED ACCESS     │                   │
│      ▼            ▼            ▼                   │
│  ┌─────────────────────────────────┐              │
│  │  Data Layer (Postgres, Redis,   │              │
│  │  RabbitMQ, MinIO)                │              │
│  │  🚨 ACCESSIBLE FROM ALL PODS 🚨  │              │
│  └─────────────────────────────────┘              │
│                                                    │
│  ANY compromised pod can:                          │
│  - Access database directly                        │
│  - Read/write to message queues                    │
│  - Connect to any service on any port              │
│  - Lateral movement unrestricted                   │
└────────────────────────────────────────────────────┘
```

## MITRE ATT&CK Exposure

Without network policies, the following attack techniques are **NOT** mitigated:

| Technique | Tactic | Description | Current Exposure |
|-----------|--------|-------------|------------------|
| **T1021** | Lateral Movement | Remote Services | Any pod can connect to any service |
| **T1210** | Lateral Movement | Exploitation of Remote Services | No network barriers between pods |
| **T1570** | Lateral Movement | Lateral Tool Transfer | Unrestricted pod-to-pod file transfer |
| **T1530** | Collection | Data from Cloud Storage Object | MinIO accessible from all pods |
| **T1552.007** | Credential Access | Container API | Redis credentials cache exposed |
| **T1098** | Persistence | Account Manipulation | Direct database access allows backdoor creation |

## Security Assumptions

### Current Assumptions (Implicit)
1. **Perimeter Security**: Cluster is private with limited external access
2. **Node Security**: GKE nodes are patched and hardened
3. **Pod Security**: All containers are trusted (no runtime verification)
4. **Service Mesh**: No service mesh (e.g., Istio) providing network isolation

### What Happens If These Assumptions Fail?

**Scenario 1: Container Escape Vulnerability (CVE-2024-XXXX)**
- Attacker gains node access
- Can directly access database from node network
- **Network policies would NOT help** (they operate at pod level)
- **But**: Limits what attacker can do from compromised container before escalation

**Scenario 2: Compromised Application Dependency (Supply Chain Attack)**
- Malicious npm package in `front` container
- Can exfiltrate data via direct database access
- **Network policies WOULD help**: Block front-end from database access

**Scenario 3: SSRF Vulnerability in API Service**
- Attacker uses SSRF to scan internal services
- Discovers and exploits unpatched RabbitMQ management API
- **Network policies WOULD help**: Limit which pods can reach RabbitMQ

## Cluster Security Controls (Already Implemented)

| Control | Status | Coverage |
|---------|--------|----------|
| Private GKE Cluster | ✅ Enabled | Limits external access to API server |
| Workload Identity | ✅ Enabled | Prevents pod from using node credentials |
| Pod Security Standards | ❓ Unknown | Limits privileged containers |
| Binary Authorization | ❌ Not shown | Would prevent unsigned images |
| Falco Runtime Security | ✅ Enabled | Detects shell execution, privilege escalation |
| Cloud Armor | ❌ Not shown | Would prevent DDoS at LB level |
| **Network Policies** | ❌ **NONE** | **No network segmentation** |

## Defense-in-Depth Analysis

### Layers of Defense (Current State)

```
Layer 1: Perimeter        [GKE Private Cluster, IAP, Ingress]  ✅ STRONG
Layer 2: Authentication   [Workload Identity, RBAC]            ✅ STRONG
Layer 3: Authorization    [K8s RBAC, IAM]                      ✅ MODERATE
Layer 4: Runtime          [Falco eBPF monitoring]              ✅ STRONG (detection only)
Layer 5: Network          [NetworkPolicies]                    ❌ MISSING
Layer 6: Data             [Encryption at rest]                 ✅ STRONG (GKE default)
```

**Gap**: **Layer 5 (Network Segmentation) is completely missing**

### What Network Policies Would Add

**Positive Security Model** (Default-Deny):
- Start with "deny all traffic"
- Explicitly allow only required communication paths
- Document and enforce least privilege at network level

**Lateral Movement Prevention**:
- Compromised `front` pod **cannot** access `postgres` directly
- Compromised `github-hooks` pod **cannot** access `rabbitmq` management API
- Arbitrary test pods **cannot** scan internal services

**Compliance & Audit**:
- PCI DSS 1.2.1: "Restrict inbound and outbound traffic to that which is necessary"
- CIS Kubernetes Benchmark 5.3.2: "Ensure that all Namespaces have Network Policies defined"
- Provides audit trail of intended communication patterns

## Recommendation

### Option 1: Implement Network Policies (Defense-in-Depth)
**Rationale**: Even with strong perimeter security, defense-in-depth assumes breach has occurred. Network policies:
- Limit blast radius of compromised container
- Prevent lateral movement (MITRE ATT&CK T1021, T1210)
- Meet compliance requirements (PCI DSS, CIS Benchmark)
- Provide documentation of intended architecture

**Estimated Effort**: 2-3 hours to implement + test
**Security Gain**: Moderate (reduces lateral movement risk)

### Option 2: Document Why Network Policies Are Not Needed
**Rationale**: If cluster is assumed to be a trusted environment:
- Focus security efforts on preventing cluster breach
- Invest in stronger perimeter controls (Binary Authorization, Admission Controllers)
- Rely on runtime detection (Falco) rather than prevention

**Thesis Contribution**: Still valuable to document the decision and trade-offs

### Option 3: Hybrid Approach (Protect Data Layer Only)
**Rationale**: Apply network policies to **only** the most sensitive components:
- Postgres, Redis, RabbitMQ: Deny all, then allowlist
- Application services: Remain unrestricted
- Balances security with complexity

**Effort**: 30-60 minutes
**Security Gain**: Moderate (protects crown jewels)

## Conclusion

**Current State**: Cluster has **zero network segmentation**. Any pod can connect to any other pod on any port.

**Risk**: If an attacker compromises a single container (via SSRF, RCE, or supply chain attack), they can immediately access sensitive data stores (Postgres, Redis) and message queues (RabbitMQ).

**Your Question**: "Do we need network policies if the cluster is a safe/trusted environment?"

**Answer**: It depends on your threat model:
- **If you assume**: "Cluster will never be breached" → Network policies add complexity with limited benefit
- **If you assume**: "Cluster might be breached (zero-trust)" → Network policies are critical defense-in-depth layer

For a **master's thesis on Kubernetes security**, documenting both perspectives (with or without network policies) demonstrates understanding of security trade-offs. The choice is yours.

---

**Next Step**: Decide on Option 1, 2, or 3 above.
