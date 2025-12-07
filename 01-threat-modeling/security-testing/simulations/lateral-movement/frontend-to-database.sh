#!/bin/bash
# Test: Lateral Movement - Frontend to Database
# Attempts to connect directly from frontend pod to PostgreSQL

set -euo pipefail

TEST_NAME="frontend-to-database"
NAMESPACE="${TEST_NAMESPACE:-default}"

echo "=== Test: Lateral Movement - Frontend to Database ==="

# Find frontend pod
FRONTEND_POD=$(kubectl get pods -n ${NAMESPACE} -l app=front -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -z "$FRONTEND_POD" ]; then
    echo "Frontend pod not found. Skipping test."
    echo "ATTACK_SUCCESS=false"
    echo "BLOCKED_BY=Test environment not ready"
    exit 0
fi

# Determine PostgreSQL service endpoint
POSTGRES_HOST=$(kubectl get svc -n ${NAMESPACE} -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "postgres")
POSTGRES_PORT="5432"

echo "Attempting connection from ${FRONTEND_POD} to ${POSTGRES_HOST}:${POSTGRES_PORT}"

# Attempt 1: TCP connection test using nc (netcat)
CONNECTION_RESULT=$(kubectl exec ${FRONTEND_POD} -n ${NAMESPACE} -- timeout 5 nc -zv ${POSTGRES_HOST} ${POSTGRES_PORT} 2>&1 || echo "FAILED")

if echo "$CONNECTION_RESULT" | grep -q "open\|succeeded\|Connected"; then
    echo "ATTACK_SUCCESS=true"
    echo "TCP connection to PostgreSQL successful (NetworkPolicy not enforced)"

    # Attempt 2: Try actual database connection (if psql available)
    DB_CONNECT=$(kubectl exec ${FRONTEND_POD} -n ${NAMESPACE} -- sh -c "
        command -v psql >/dev/null 2>&1 && \
        PGPASSWORD='postgres' psql -h ${POSTGRES_HOST} -U postgres -c 'SELECT version();' 2>&1
    " || echo "psql not available")

    if echo "$DB_CONNECT" | grep -q "PostgreSQL"; then
        echo "Database query successful! Full access to PostgreSQL."
        echo "WARNING: Frontend can directly access database"
    fi

    # Check for detection
    sleep 5

    # Check if Falco detected the connection
    if kubectl logs -n falco -l app=falco --since=30s 2>/dev/null | grep -qi "unexpected.*connection.*postgres"; then
        echo "DETECTED=true"
        echo "MTTD=5"
    else
        echo "DETECTED=false"
    fi
elif echo "$CONNECTION_RESULT" | grep -q "timeout\|refused\|No route"; then
    echo "ATTACK_SUCCESS=false"

    # Determine blocking mechanism
    if echo "$CONNECTION_RESULT" | grep -q "timeout"; then
        echo "BLOCKED_BY=NetworkPolicy (connection timeout)"
    elif echo "$CONNECTION_RESULT" | grep -q "refused"; then
        echo "BLOCKED_BY=Service not exposed or firewall rule"
    else
        echo "BLOCKED_BY=Network segmentation"
    fi
else
    echo "ATTACK_SUCCESS=false"
    echo "BLOCKED_BY=Unknown (connection failed)"
fi
