#!/bin/bash
# Test: Privileged Container Escape
# Attempts to create a privileged pod and escape to the host

set -euo pipefail

TEST_NAME="privileged-container-escape"
NAMESPACE="${TEST_NAMESPACE:-default}"

echo "=== Test: Privileged Container Escape ==="

# Attempt to create privileged pod
cat <<EOF | kubectl apply -f - 2>&1 | tee /tmp/${TEST_NAME}.log
apiVersion: v1
kind: Pod
metadata:
  name: privileged-escape-test
  namespace: ${NAMESPACE}
spec:
  containers:
  - name: attacker
    image: alpine:latest
    command: ["/bin/sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
  restartPolicy: Never
EOF

# Check if pod was created
if kubectl get pod privileged-escape-test -n ${NAMESPACE} &>/dev/null; then
    echo "ATTACK_SUCCESS=true"
    echo "Pod created successfully (privileged mode allowed)"

    # Wait for pod to be running
    kubectl wait --for=condition=Ready pod/privileged-escape-test -n ${NAMESPACE} --timeout=60s || true

    # Attempt to access host filesystem
    if kubectl exec privileged-escape-test -n ${NAMESPACE} -- ls /host 2>/dev/null; then
        echo "Host filesystem accessible from container!"
    fi

    # Attempt to list host processes
    if kubectl exec privileged-escape-test -n ${NAMESPACE} -- ps aux 2>/dev/null | grep -q "systemd"; then
        echo "Host processes visible from container!"
    fi

    # Check for Falco detection
    sleep 10  # Wait for detection

    # Query Falco for alerts (if available)
    if kubectl logs -n falco -l app=falco --since=30s 2>/dev/null | grep -q "Privileged container"; then
        echo "DETECTED=true"
        echo "MTTD=10"  # Detection time in seconds
    else
        echo "DETECTED=false"
    fi

    # Cleanup
    kubectl delete pod privileged-escape-test -n ${NAMESPACE} --force --grace-period=0
else
    # Pod creation was blocked
    echo "ATTACK_SUCCESS=false"

    # Determine what blocked it
    if grep -q "PodSecurity" /tmp/${TEST_NAME}.log; then
        echo "BLOCKED_BY=Pod Security Standards"
    elif grep -q "admission" /tmp/${TEST_NAME}.log; then
        echo "BLOCKED_BY=Admission Controller"
    elif grep -q "policy" /tmp/${TEST_NAME}.log; then
        echo "BLOCKED_BY=OPA Gatekeeper"
    else
        echo "BLOCKED_BY=Unknown"
    fi
fi

rm -f /tmp/${TEST_NAME}.log
