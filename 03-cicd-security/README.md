# Phase 03: CI/CD Security - Container Image Scanning

**Status**: ✅ Implemented  
**Tool**: Trivy (Aqua Security)  
**Pipeline**: Semaphore CI/CD

---

## Overview

This phase implements automated security scanning of container images in the CI/CD pipeline to detect vulnerabilities before deployment.

## Implementation

### Files

```
03-cicd-security/
├── README.md                           # This file
├── semaphore-pipeline.yml              # Basic sequential scanning
├── semaphore-pipeline-improved.yml     # Parallel scanning (recommended)
├── PIPELINE_IMPROVEMENTS.md            # Detailed improvement documentation
└── scan-semaphore-images.sh            # Standalone scanning script
```

### Pipeline Versions

#### v1.0: Basic Sequential Pipeline (`semaphore-pipeline.yml`)
- Scans all images sequentially in a single job
- ~10 minutes execution time
- Simple but slow

#### v2.0: Parallel Pipeline (`semaphore-pipeline-improved.yml`) ⭐ **Recommended**
- Scans images in parallel (one job per image)
- ~2 minutes execution time (5x faster)
- Individual reports pushed to workflow-level artifacts
- Aggregation job generates master `REPORT.md`
- Better failure isolation and debugging

---

## How It Works

### Architecture (v2.0)

```
┌─────────────────────────────────────────────────────┐
│  Block 1: Parallel Vulnerability Scanning          │
│                                                     │
│  Job 1: Scan Guard    ─────┐                       │
│  Job 2: Scan Front    ─────┤                       │
│  Job 3: Scan Auth     ─────┼─▶ Push to Workflow   │
│  Job 4: Scan ProjectHub ───┤    Artifacts          │
│  Job 5: Scan Bootstrapper ─┘                       │
└─────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│  Block 2: Generate Security Report                 │
│                                                     │
│  Job 1: Aggregate Results                          │
│    ├─ Pull all *.json, *.txt, *.csv               │
│    ├─ Generate master REPORT.md                    │
│    └─ Push REPORT.md to .semaphore/               │
└─────────────────────────────────────────────────────┘
```

### Per-Image Artifacts

Each scanning job produces:

1. **`{service}.json`**: Machine-readable vulnerability data (for automation)
2. **`{service}.txt`**: Human-readable table (for manual review)
3. **`{service}.csv`**: Summary counts (service,critical,high)

### Master Report

The aggregation job generates `REPORT.md` with:

- Summary table with vulnerability counts
- Detailed findings for each image
- Recommendations and next steps
- Deployment decision (block if CRITICAL found)

**Example**:

```markdown
# Semaphore Security Scan Report

**Generated**: 2025-11-14 14:30:00 UTC

## Summary

| Service | Critical | High | Status |
|---------|----------|------|--------|
| guard | 2 | 3 | ❌ CRITICAL |
| front | 0 | 5 | ✅ PASS |
| auth | 1 | 2 | ❌ CRITICAL |
| projecthub | 0 | 0 | ✅ PASS |
| bootstrapper | 0 | 1 | ✅ PASS |
| **TOTAL** | **3** | **11** | - |

## Detailed Findings
...
```

---

## Security Controls

| Control | Description | Effect |
|---------|-------------|--------|
| **Trivy Scanning** | Detects CVEs in container images | Identifies vulnerabilities before deployment |
| **Severity Filtering** | Focuses on HIGH and CRITICAL | Prioritizes critical issues |
| **Deployment Blocking** | Fails pipeline if CRITICAL found | Prevents vulnerable images from reaching production |
| **Artifact Preservation** | Stores scan results | Audit trail and compliance evidence |
| **Parallel Execution** | Scans images concurrently | Faster feedback loop (2 min vs 10 min) |

---

## MITRE ATT&CK Coverage

| Technique | Tactic | Mitigation |
|-----------|--------|------------|
| **T1190** | Initial Access | Prevents deployment of images with known exploitable vulnerabilities |
| **T1203** | Exploitation for Client Execution | Detects vulnerable libraries that could be exploited |
| **T1068** | Exploitation for Privilege Escalation | Identifies privilege escalation vulnerabilities in base images |
| **T1525** | Implant Internal Image | Scans for malicious packages in container layers |

---

## Usage

### Running the Pipeline

**Option 1: Automatic (Git Push)**
```bash
git push origin main  # Semaphore auto-triggers
```

**Option 2: Manual Trigger**
```bash
sem create workflow -f semaphore-pipeline-improved.yml
```

### Viewing Results

1. Go to Semaphore UI
2. Navigate to workflow → **Artifacts** tab
3. Download `.semaphore/REPORT.md`
4. View individual `.json`, `.txt`, `.csv` files

### Standalone Scanning

```bash
cd 03-cicd-security
./scan-semaphore-images.sh
```

---

## Performance Metrics

| Metric | Sequential (v1.0) | Parallel (v2.0) | Improvement |
|--------|-------------------|-----------------|-------------|
| **Execution Time** | 10 minutes | 2 minutes | 5x faster |
| **Parallelism** | 1 job | 5 jobs | 5x concurrency |
| **Failure Isolation** | All-or-nothing | Per-image | Better debugging |
| **Artifact Organization** | Single bundle | Per-service + master | Easier navigation |

---

## Configuration

### Scan Severity

Current: `HIGH,CRITICAL`

To include all severities:
```yaml
trivy image --severity LOW,MEDIUM,HIGH,CRITICAL ...
```

### Images to Scan

Defined in each job:
```yaml
- IMAGE="ghcr.io/semaphoreio/guard:71d97737dcd4c147dd48d8971b14a2e0f4b92710"
- SERVICE="guard"
```

To scan additional images, add a new job following the template in Block 1.

### Deployment Blocking

Current: Blocks if `CRITICAL > 0`

To change threshold:
```bash
if [ $TOTAL_CRITICAL -gt 5 ]; then  # Allow up to 5 CRITICAL
  exit 1
fi
```

---

## Compliance

| Standard | Requirement | Status |
|----------|-------------|--------|
| **CIS Docker Benchmark** | 4.1: Scan images for vulnerabilities | ✅ Implemented |
| **NIST 800-190** | Vulnerability management for containers | ✅ Automated scanning |
| **PCI DSS 6.2** | Ensure all system components are protected from known vulnerabilities | ✅ Pre-deployment checks |
| **SOC 2** | Change management controls | ✅ Audit trail via artifacts |

---

## Future Enhancements

### Phase 03 Step 2: Image Signing with Cosign

```bash
# Sign images after successful scan
cosign sign --key gcpkms://... ghcr.io/semaphoreio/guard:tag

# Verify signatures before deployment
cosign verify --key cosign.pub ghcr.io/semaphoreio/guard:tag
```

### Phase 03 Step 3: SBOM Generation

```bash
# Generate Software Bill of Materials
syft ghcr.io/semaphoreio/guard:tag -o json > sbom.json

# Attest SBOM
cosign attest --key gcpkms://... --predicate sbom.json ghcr.io/semaphoreio/guard:tag
```

---

## References

- **Trivy Documentation**: https://aquasecurity.github.io/trivy/
- **Semaphore Artifacts**: https://docs.semaphoreci.com/essentials/artifacts/
- **CIS Docker Benchmark**: https://www.cisecurity.org/benchmark/docker
- **NIST 800-190**: https://csrc.nist.gov/publications/detail/sp/800-190/final

---

**Implementation Date**: 2025-11-14  
**Pipeline Version**: v2.0 (Parallel)  
**Next Phase**: Phase 04 - Secrets Management
