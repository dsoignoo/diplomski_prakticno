#!/bin/bash
# Test script za OPA Gatekeeper politike

set -e

echo "=== OPA Gatekeeper Policy Testing ==="
echo ""

# Test 1: Privilegovani kontejner (treba biti blokiran)
echo "Test 1: Pokušaj kreiranja privilegovanog poda..."
cat <<EOF | kubectl apply -f - 2>&1 || true
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
  namespace: semaphore
spec:
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      privileged: true
EOF
echo ""

# Test 2: Pod bez resource limits (treba biti blokiran)
echo "Test 2: Pokušaj kreiranja poda bez resource limits..."
cat <<EOF | kubectl apply -f - 2>&1 || true
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-no-limits
  namespace: semaphore
spec:
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: nginx
        image: nginx:latest
EOF
echo ""

# Test 3: NodePort servis (treba biti blokiran)
echo "Test 3: Pokušaj kreiranja NodePort servisa..."
cat <<EOF | kubectl apply -f - 2>&1 || true
apiVersion: v1
kind: Service
metadata:
  name: test-nodeport
  namespace: semaphore
spec:
  type: NodePort
  ports:
  - port: 80
    nodePort: 30080
  selector:
    app: test
EOF
echo ""

# Test 4: Validan pod (treba proći)
echo "Test 4: Kreiranje validnog poda..."
cat <<EOF | kubectl apply -f - 2>&1
apiVersion: v1
kind: Pod
metadata:
  name: test-valid
  namespace: semaphore
  labels:
    app: test
    component: validation
    version: v1.0.0
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
    resources:
      requests:
        memory: "64Mi"
        cpu: "100m"
      limits:
        memory: "128Mi"
        cpu: "200m"
EOF
echo ""

# Cleanup
echo "Čišćenje test resursa..."
kubectl delete pod test-valid -n semaphore --ignore-not-found

echo ""
echo "=== Testiranje završeno ==="
