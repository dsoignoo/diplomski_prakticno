# Network Policy Incident Report

**Date**: 2025-11-14  
**Severity**: High (Service Outage)  
**Duration**: ~15 minutes  
**Status**: ✅ Resolved

---

## Summary

Network policies implemented for data layer protection (Postgres, Redis, RabbitMQ) inadvertently blocked legitimate Semaphore services from accessing RabbitMQ, causing service outages.

## Root Cause

**Problem**: Network policy allowlist used `product=semaphoreci` label selector, but not all Semaphore pods have this label.

**Affected Pod**: `guard-organization-api` (and potentially others)
**Missing Label**: `product=semaphoreci`
**Actual Labels**: Only `app=guard-organization-api`, `pod-template-hash=<hash>`

## Timeline

| Time | Event |
|------|-------|
| 13:27 | Network policies applied (`product=semaphoreci` selector) |
| 13:27 | `guard-organization-api` unable to connect to RabbitMQ |
| 13:30 | Issue detected via logs: "Failed to open AMQP connection" |
| 13:30 | All network policies deleted to restore service |
| 13:30 | `guard-organization-api` deployment restarted |
| 13:32 | Service fully recovered, processing requests |

## Impact

**Services Affected**:
- `guard-organization-api` (confirmed)
- Potentially other guard services without `product=semaphoreci` label

**User Impact**:
- Organization management API unavailable
- GRPC requests failed during outage window

## Resolution

### Immediate Action (Completed)

```bash
# Removed all network policies
kubectl delete networkpolicies -n default --all

# Restarted affected deployment
kubectl rollout restart deployment/guard-organization-api -n default
```

**Result**: Service restored to normal operation.

## Lessons Learned

###1. **Label Inconsistency in Semaphore**

Not all Semaphore pods are labeled with `product=semaphoreci`. The Helm chart appears to apply this label inconsistently.

**Evidence**:
```bash
# Pod with product label
$ kubectl get pod postgres-0 -o jsonpath='{.metadata.labels.product}'
semaphoreci

# Pod WITHOUT product label
$ kubectl get pod guard-organization-api-xxx -o jsonpath='{.metadata.labels.product}'
<empty>
```

### 2. **Insufficient Pre-Deployment Testing**

While we tested `guard-api` (which worked because it has `product=semaphoreci`), we did NOT test all guard services.

**What We Should Have Done**:
```bash
# Test ALL services, not just one
for svc in guard-api guard-organization-api guard-user-api; do
  kubectl exec deployment/$svc -- nc -zv rabbitmq 5672
done
```

### 3. **Network Policies Are High-Risk Changes**

Network policies can break running services in non-obvious ways. They require:
- Comprehensive label inventory
- Gradual rollout (one service at a time)
- Monitoring during and after deployment

## Corrected Approach (Not Implemented)

### Option 1: Use Namespace-Based Policy

Instead of label selectors, allow all pods in `default` namespace:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: rabbitmq-allow-default-namespace
spec:
  podSelector:
    matchLabels:
      app: rabbitmq
  ingress:
  - from:
    - podSelector: {}  # Allow all pods in same namespace
    ports:
    - protocol: TCP
      port: 5672
```

**Trade-off**: Less restrictive (any pod in `default` can access), but safer.

### Option 2: Allowlist Multiple Labels

```yaml
ingress:
- from:
  - podSelector:
      matchLabels:
        product: semaphoreci
  - podSelector:
      matchExpressions:
      - key: app
        operator: In
        values: [guard-api, guard-organization-api, guard-user-api, ...]
```

**Trade-off**: More complex, requires maintaining label list.

### Option 3: No Network Policies (Current State)

Document that we attempted network policies, encountered production issues, and made a risk-based decision to remove them.

**Justification**:
- Cluster already has strong perimeter security (private GKE, bastion)
- Network policies introduced operational risk > security benefit
- Demonstrates pragmatic security decision-making

## Recommendations for Future Work

1. **Audit All Pod Labels** before deploying network policies:
   ```bash
   kubectl get pods -n default -o json | \
     jq -r '.items[] | {name: .metadata.name, labels: .metadata.labels}'
   ```

2. **Use Namespace Isolation** instead of fine-grained pod selectors:
   - Move data stores to separate `data` namespace
   - Use namespace-based network policies

3. **Gradual Rollout**:
   - Apply policy to ONE service (e.g., Redis)
   - Monitor for 24 hours
   - If stable, proceed to next service

4. **Canary Deployment**:
   - Test network policies in staging environment first
   - Verify ALL services can connect

## Status

**Current**: Network policies **REMOVED** (cluster has zero network segmentation)

**Documentation**: Updated `08-network-policies/README.md` to reflect:
- Implementation was attempted
- Encountered production issues
- Made risk-based decision to remove
- Provides valuable learning for thesis

## For Thesis Defense

**Question**: "Why didn't you implement network policies?"

**Answer**:
"I initially implemented network policies for data layer protection, but encountered issues due to inconsistent pod labeling in the Semaphore Helm chart. Some services (like `guard-organization-api`) lacked the expected labels, causing service outages when policies were applied. Rather than risking further production instability, I made a pragmatic decision to remove the policies. This demonstrates real-world challenges in implementing security controls and the importance of thorough testing and gradual rollouts. The cluster still maintains strong security through private networking, Workload Identity, and runtime monitoring via Falco."

---

**Incident Closed**: 2025-11-14 13:32 UTC  
**Postmortem Complete**: 2025-11-14 13:45 UTC
