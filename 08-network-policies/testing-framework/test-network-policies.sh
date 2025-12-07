#!/bin/bash
# Test script za validaciju NetworkPolicies u Semaphore deployment-u
# Testira allowed i blocked traffic prema security policies

set -e

NAMESPACE="semaphore"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🧪 Testing NetworkPolicies for Semaphore in namespace: $NAMESPACE"
echo "=================================================="
echo ""

# Helper function za testiranje connectivity
test_connection() {
    local test_name="$1"
    local pod_labels="$2"
    local target_host="$3"
    local target_port="$4"
    local should_succeed="$5"  # "true" ili "false"

    echo -n "Testing: $test_name ... "

    # Kreirati test pod
    kubectl run test-pod-$RANDOM \
        --rm -i --restart=Never \
        --image=busybox:latest \
        --labels="$pod_labels" \
        --namespace=$NAMESPACE \
        --timeout=15s \
        --command -- \
        timeout 5 nc -zv $target_host $target_port \
        > /dev/null 2>&1

    exit_code=$?

    if [ "$should_succeed" == "true" ]; then
        # Očekujemo uspjeh (connection allowed)
        if [ $exit_code -eq 0 ]; then
            echo -e "${GREEN}✅ PASS${NC} (connection allowed as expected)"
            return 0
        else
            echo -e "${RED}❌ FAIL${NC} (connection should be allowed but was blocked!)"
            return 1
        fi
    else
        # Očekujemo neuspjeh (connection blocked)
        if [ $exit_code -ne 0 ]; then
            echo -e "${GREEN}✅ PASS${NC} (connection blocked as expected)"
            return 0
        else
            echo -e "${RED}❌ FAIL${NC} (connection should be blocked but was allowed!)"
            return 1
        fi
    fi
}

# Provjera da li Semaphore podovi rade
echo "Checking Semaphore deployment status..."
kubectl get pods -n $NAMESPACE | grep -E "(front|guard|postgresql|redis|rabbitmq)" || {
    echo -e "${RED}Error: Semaphore pods not running in namespace $NAMESPACE${NC}"
    exit 1
}
echo ""

# Provjera da li NetworkPolicies postoje
echo "Checking NetworkPolicies..."
kubectl get networkpolicy -n $NAMESPACE || {
    echo -e "${YELLOW}Warning: No NetworkPolicies found. Run: kubectl apply -f ../${NC}"
    exit 1
}
echo ""

TEST_RESULTS=()

# TEST 1: Front → Guard (SHOULD BE ALLOWED)
test_connection \
    "Test 1: Front → Guard API" \
    "app=front,component=web" \
    "guard-api.$NAMESPACE.svc.cluster.local" \
    "4000" \
    "true"
TEST_RESULTS+=($?)

# TEST 2: Guard → PostgreSQL (SHOULD BE ALLOWED)
test_connection \
    "Test 2: Guard → PostgreSQL" \
    "app=guard,component=api" \
    "postgresql.$NAMESPACE.svc.cluster.local" \
    "5432" \
    "true"
TEST_RESULTS+=($?)

# TEST 3: Guard → Redis (SHOULD BE ALLOWED)
test_connection \
    "Test 3: Guard → Redis" \
    "app=guard,component=api" \
    "redis-master.$NAMESPACE.svc.cluster.local" \
    "6379" \
    "true"
TEST_RESULTS+=($?)

# TEST 4: Random pod → PostgreSQL (SHOULD BE BLOCKED)
test_connection \
    "Test 4: Attacker → PostgreSQL" \
    "role=attacker" \
    "postgresql.$NAMESPACE.svc.cluster.local" \
    "5432" \
    "false"
TEST_RESULTS+=($?)

# TEST 5: Front → PostgreSQL direct (SHOULD BE BLOCKED)
test_connection \
    "Test 5: Front → PostgreSQL (bypass Guard)" \
    "app=front,component=web" \
    "postgresql.$NAMESPACE.svc.cluster.local" \
    "5432" \
    "false"
TEST_RESULTS+=($?)

# TEST 6: Hooks Processor → PostgreSQL (SHOULD BE BLOCKED)
test_connection \
    "Test 6: Hooks → PostgreSQL (no DB access)" \
    "app=hooks-processor" \
    "postgresql.$NAMESPACE.svc.cluster.local" \
    "5432" \
    "false"
TEST_RESULTS+=($?)

# TEST 7: Hooks Processor → RabbitMQ (SHOULD BE ALLOWED)
test_connection \
    "Test 7: Hooks → RabbitMQ" \
    "app=hooks-processor" \
    "rabbitmq.$NAMESPACE.svc.cluster.local" \
    "5672" \
    "true"
TEST_RESULTS+=($?)

# TEST 8: DNS Resolution (SHOULD BE ALLOWED FOR ALL)
echo -n "Testing: Test 8: DNS resolution for all pods ... "
kubectl run test-dns-$RANDOM \
    --rm -i --restart=Never \
    --image=busybox:latest \
    --labels="role=test" \
    --namespace=$NAMESPACE \
    --timeout=10s \
    --command -- \
    nslookup google.com \
    > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ PASS${NC} (DNS works)"
    TEST_RESULTS+=(0)
else
    echo -e "${RED}❌ FAIL${NC} (DNS resolution failed!)"
    TEST_RESULTS+=(1)
fi

# Provjera rezultata
echo ""
echo "=================================================="
echo "📊 Test Results Summary:"
echo "=================================================="

TOTAL_TESTS=${#TEST_RESULTS[@]}
PASSED_TESTS=0
FAILED_TESTS=0

for result in "${TEST_RESULTS[@]}"; do
    if [ $result -eq 0 ]; then
        ((PASSED_TESTS++))
    else
        ((FAILED_TESTS++))
    fi
done

echo "Total tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}All tests passed! ✅${NC}"
    echo -e "${GREEN}NetworkPolicies correctly implemented.${NC}"
    echo -e "${GREEN}========================================${NC}"
    exit 0
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}Some tests failed! ❌${NC}"
    echo -e "${RED}Please review NetworkPolicy configuration.${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi
