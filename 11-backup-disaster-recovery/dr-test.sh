#!/bin/bash
# Disaster Recovery Test Script
# Izvršava kompletni DR drill i mjeri RTO
#
# Korištenje: ./dr-test.sh [--dry-run]

set -e

DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "=== DRY RUN MODE - neće se izvršiti stvarne promjene ==="
fi

START_TIME=$(date +%s)
NAMESPACE="semaphore"
LOG_FILE="dr-test-$(date +%Y%m%d-%H%M%S).log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=== DISASTER RECOVERY DRILL ==="
log "Start time: $(date)"
log "Namespace: $NAMESPACE"

# 1. Provjera trenutnog stanja
log "Step 1: Provjera trenutnog stanja klastera..."
kubectl get deployments -n $NAMESPACE -o wide | tee -a "$LOG_FILE"
INITIAL_PODS=$(kubectl get pods -n $NAMESPACE --no-headers | wc -l)
log "Broj aktivnih podova prije testa: $INITIAL_PODS"

# 2. Pronađi najnoviji backup
log "Step 2: Pronalaženje najnovijeg backup-a..."
LATEST_BACKUP=$(velero backup get --selector backup-type=scheduled -o json | \
    jq -r '.items | sort_by(.metadata.creationTimestamp) | last | .metadata.name')

if [[ -z "$LATEST_BACKUP" || "$LATEST_BACKUP" == "null" ]]; then
    log "ERROR: Nema dostupnih backup-a!"
    exit 1
fi

log "Najnoviji backup: $LATEST_BACKUP"
velero backup describe "$LATEST_BACKUP" | tee -a "$LOG_FILE"

# 3. Simulacija cluster failure
log "Step 3: Simulacija cluster failure (scale down sve komponente)..."
if [[ "$DRY_RUN" == "false" ]]; then
    kubectl get deployments -n $NAMESPACE -o name | while read dep; do
        kubectl scale "$dep" --replicas=0 -n $NAMESPACE
    done
    sleep 10
    log "Sve komponente scaled down."
else
    log "[DRY RUN] Preskačem scale down"
fi

# 4. Restore iz backup-a
RESTORE_NAME="semaphore-dr-restore-$(date +%Y%m%d-%H%M%S)"
log "Step 4: Pokretanje restore-a: $RESTORE_NAME..."
if [[ "$DRY_RUN" == "false" ]]; then
    velero restore create "$RESTORE_NAME" --from-backup "$LATEST_BACKUP" --wait
else
    log "[DRY RUN] Preskačem restore"
fi

# 5. Čekanje da se restore završi
log "Step 5: Čekanje na restore completion..."
if [[ "$DRY_RUN" == "false" ]]; then
    RESTORE_STATUS=""
    TIMEOUT=600
    ELAPSED=0
    while [[ "$RESTORE_STATUS" != "Completed" && $ELAPSED -lt $TIMEOUT ]]; do
        RESTORE_STATUS=$(velero restore get "$RESTORE_NAME" -o json | jq -r '.status.phase')
        log "Restore status: $RESTORE_STATUS (${ELAPSED}s elapsed)"
        sleep 10
        ELAPSED=$((ELAPSED + 10))
    done

    if [[ "$RESTORE_STATUS" != "Completed" ]]; then
        log "ERROR: Restore nije završen u predviđenom vremenu!"
        velero restore describe "$RESTORE_NAME" --details | tee -a "$LOG_FILE"
        exit 1
    fi
fi

# 6. Validacija - čekanje da svi podovi budu ready
log "Step 6: Validacija restored servisa..."
if [[ "$DRY_RUN" == "false" ]]; then
    kubectl wait --for=condition=available --timeout=600s \
        deployment --all -n $NAMESPACE

    RESTORED_PODS=$(kubectl get pods -n $NAMESPACE --no-headers | wc -l)
    log "Broj aktivnih podova nakon restore-a: $RESTORED_PODS"
fi

# 7. Smoke tests
log "Step 7: Pokretanje smoke testova..."
if [[ "$DRY_RUN" == "false" ]]; then
    # Health check
    FRONT_POD=$(kubectl get pod -n $NAMESPACE -l app=front -o jsonpath='{.items[0].metadata.name}')
    kubectl exec -n $NAMESPACE "$FRONT_POD" -- curl -s http://localhost:3000/health || {
        log "ERROR: Front health check failed!"
        exit 1
    }
    log "Front health check: PASS"

    # Guard API check
    GUARD_POD=$(kubectl get pod -n $NAMESPACE -l app=guard -o jsonpath='{.items[0].metadata.name}')
    kubectl exec -n $NAMESPACE "$GUARD_POD" -- curl -s http://localhost:4000/health || {
        log "ERROR: Guard health check failed!"
        exit 1
    }
    log "Guard health check: PASS"
else
    log "[DRY RUN] Preskačem smoke testove"
fi

# 8. Izračunaj RTO
END_TIME=$(date +%s)
RTO=$((END_TIME - START_TIME))
RTO_MIN=$((RTO / 60))
RTO_SEC=$((RTO % 60))

log ""
log "=========================================="
log "=== DISASTER RECOVERY DRILL COMPLETED ==="
log "=========================================="
log ""
log "Recovery Time Objective (RTO): ${RTO_MIN}m ${RTO_SEC}s"
log "Target RTO: < 60 minutes"
if [[ $RTO_MIN -lt 60 ]]; then
    log "Status: PASS - RTO unutar cilja"
else
    log "Status: FAIL - RTO prekoračen!"
fi
log ""
log "End time: $(date)"
log "Log file: $LOG_FILE"

# Generiši izvještaj
cat << EOF > "dr-report-$(date +%Y%m%d).md"
# Disaster Recovery Test Report

**Datum:** $(date)
**Backup korišten:** $LATEST_BACKUP
**Restore naziv:** $RESTORE_NAME

## Rezultati

| Metrika | Cilj | Postignuto |
|---------|------|------------|
| RTO | < 60 min | ${RTO_MIN}m ${RTO_SEC}s |
| Status | PASS | $(if [[ $RTO_MIN -lt 60 ]]; then echo "PASS"; else echo "FAIL"; fi) |

## Koraci

1. Početno stanje: $INITIAL_PODS podova
2. Backup: $LATEST_BACKUP
3. Restore: $RESTORE_NAME
4. Završno stanje: $RESTORED_PODS podova

## Zaključak

DR test je $(if [[ $RTO_MIN -lt 60 ]]; then echo "uspješno završen"; else echo "NEUSPJEŠAN"; fi).
EOF

log "Report generisan: dr-report-$(date +%Y%m%d).md"
