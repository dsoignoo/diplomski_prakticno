#!/bin/bash
# Test: Unsigned Image Deployment
# Attempts to deploy a container image without a valid signature

set -euo pipefail

TEST_NAME="unsigned-image-deployment"
NAMESPACE="${TEST_NAMESPACE:-default}"

echo "=== Test: Unsigned Image Deployment ==="

# Attempt to deploy an unsigned image (using public nginx image which is typically unsigned)
cat <<EOF | kubectl apply -f - 2>&1 | tee /tmp/${TEST_NAME}.log
apiVersion: v1
kind: Pod
metadata:
  name: unsigned-image-test
  namespace: ${NAMESPACE}
spec:
  containers:
  - name: nginx
    image: nginx:latest
  restartPolicy: Never
EOF

# Check if pod was created
sleep 5

if kubectl get pod unsigned-image-test -n ${NAMESPACE} &>/dev/null; then
    POD_STATUS=$(kubectl get pod unsigned-image-test -n ${NAMESPACE} -o jsonpath='{.status.phase}')

    if [ "$POD_STATUS" = "Running" ] || [ "$POD_STATUS" = "Pending" ]; then
        echo "ATTACK_SUCCESS=true"
        echo "Unsigned image deployed successfully (no signature verification)"

        # Check image pull status
        IMAGE_PULLED=$(kubectl get pod unsigned-image-test -n ${NAMESPACE} -o jsonpath='{.status.containerStatuses[0].imageID}')
        if [ -n "$IMAGE_PULLED" ]; then
            echo "Image pulled and running: ${IMAGE_PULLED}"
        fi

        # Check for detection
        if kubectl logs -n falco -l app=falco --since=30s 2>/dev/null | grep -q "unsigned"; then
            echo "DETECTED=true"
            echo "MTTD=5"
        else
            echo "DETECTED=false"
        fi
    else
        echo "ATTACK_SUCCESS=false"
        echo "BLOCKED_BY=Pod failed to start (check pod status: ${POD_STATUS})"
    fi

    # Cleanup
    kubectl delete pod unsigned-image-test -n ${NAMESPACE} --force --grace-period=0 2>/dev/null || true
else
    # Pod creation was blocked
    echo "ATTACK_SUCCESS=false"

    # Determine what blocked it
    if grep -q "Binary Authorization" /tmp/${TEST_NAME}.log; then
        echo "BLOCKED_BY=Binary Authorization (GKE)"
    elif grep -q "signature" /tmp/${TEST_NAME}.log; then
        echo "BLOCKED_BY=Image signature verification"
    elif grep -q "admission" /tmp/${TEST_NAME}.log; then
        echo "BLOCKED_BY=Admission Controller"
    else
        echo "BLOCKED_BY=Unknown admission control"
    fi
fi

rm -f /tmp/${TEST_NAME}.log
