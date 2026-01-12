#!/usr/bin/env python3
"""
DevSecOps Pipeline za Semaphore
End-to-end secure CI/CD pipeline sa security gates
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.programming.language import Python, Go
from diagrams.onprem.vcs import Github
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.container import Docker
from diagrams.k8s.compute import Deployment, Pod
from diagrams.k8s.infra import Master
# from diagrams.saas.security import Snyk  # Not available
from diagrams.custom import Custom
import os

graph_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "0.6",
    "ranksep": "0.8",
    "rankdir": "LR",
}

node_attr = {
    "fontsize": "12",
}

edge_attr = {
    "fontsize": "11",
}

with Diagram(
    "DevSecOps Pipeline - Semaphore Security-First Deployment",
    filename="../figures/svg/devsecops_semaphore_pipeline",
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    with Cluster("Source Code"):
        github = Github("GitHub\nRepository")
        commit = Custom("Git\nCommit", "./icons/commit.png") if os.path.exists("./icons/commit.png") else Github("Code\nPush")

    with Cluster("Security Scans", graph_attr={"bgcolor": "lightblue"}):
        with Cluster("SAST"):
            semgrep = Custom("Semgrep\nCode Scan", "./icons/semgrep.png") if os.path.exists("./icons/semgrep.png") else Python("SAST")

        with Cluster("Dependency Scan"):
            trivy_fs = Custom("Trivy FS\nVulnerability", "./icons/trivy.png") if os.path.exists("./icons/trivy.png") else Python("Dependency\nScan")

        with Cluster("Secret Detection"):
            gitleaks = Custom("Gitleaks\nSecret Scan", "./icons/gitleaks.png") if os.path.exists("./icons/gitleaks.png") else Python("Secret\nDetection")

        security_gate1 = Custom("✓ Gate 1\nPassed", "./icons/gate.png") if os.path.exists("./icons/gate.png") else GithubActions("Gate 1")

    with Cluster("Build & Sign", graph_attr={"bgcolor": "lightgreen"}):
        docker_build = Docker("Docker\nBuild")

        with Cluster("Image Scan"):
            trivy_image = Custom("Trivy Image\nVuln Scan", "./icons/trivy.png") if os.path.exists("./icons/trivy.png") else Docker("Image\nScan")

        docker_registry = Docker("Container\nRegistry")

        with Cluster("Signing"):
            cosign = Custom("Cosign\nImage Sign", "./icons/cosign.png") if os.path.exists("./icons/cosign.png") else Docker("Sign")
            sbom = Custom("SBOM\nGeneration", "./icons/sbom.png") if os.path.exists("./icons/sbom.png") else Docker("SBOM")

        security_gate2 = Custom("✓ Gate 2\nPassed", "./icons/gate.png") if os.path.exists("./icons/gate.png") else GithubActions("Gate 2")

    with Cluster("Policy Validation", graph_attr={"bgcolor": "lightyellow"}):
        with Cluster("IaC Scan"):
            trivy_config = Custom("Trivy Config\nHelm Scan", "./icons/trivy.png") if os.path.exists("./icons/trivy.png") else Python("IaC\nScan")

        with Cluster("Policy Check"):
            conftest = Custom("Conftest\nOPA Policy", "./icons/opa.png") if os.path.exists("./icons/opa.png") else Python("Policy")
            kyverno_dryrun = Custom("Kyverno\nDry-run", "./icons/kyverno.png") if os.path.exists("./icons/kyverno.png") else Python("Kyverno")

        security_gate3 = Custom("✓ Gate 3\nPassed", "./icons/gate.png") if os.path.exists("./icons/gate.png") else GithubActions("Gate 3")

    with Cluster("Deploy to Dev"):
        helm_deploy = Custom("Helm\nDeploy", "./icons/helm.png") if os.path.exists("./icons/helm.png") else Master("Helm")
        dev_cluster = Master("Dev\nCluster")
        dev_pod = Pod("Dev\nPod")

    with Cluster("Security Testing", graph_attr={"bgcolor": "lightcoral"}):
        with Cluster("DAST"):
            zap = Custom("OWASP ZAP\nAPI Scan", "./icons/zap.png") if os.path.exists("./icons/zap.png") else Python("DAST")

        with Cluster("Integration Tests"):
            security_tests = Custom("Security\nTests", "./icons/test.png") if os.path.exists("./icons/test.png") else Python("Integration\nTests")

        security_gate4 = Custom("✓ Gate 4\nPassed", "./icons/gate.png") if os.path.exists("./icons/gate.png") else GithubActions("Gate 4")

    with Cluster("Production Deployment"):
        prod_approval = Custom("Manual\nApproval", "./icons/approval.png") if os.path.exists("./icons/approval.png") else GithubActions("Approve")
        prod_cluster = Master("Prod\nCluster")

        with Cluster("Canary"):
            canary_deploy = Deployment("Canary\n10%")

        with Cluster("Full Rollout"):
            full_deploy = Deployment("Production\n100%")

    with Cluster("Runtime Monitoring"):
        falco = Custom("Falco\nMonitor", "./icons/falco.png") if os.path.exists("./icons/falco.png") else Pod("Falco")
        rollback = Custom("Auto\nRollback", "./icons/rollback.png") if os.path.exists("./icons/rollback.png") else GithubActions("Rollback")

    # Pipeline flow
    github >> commit >> Edge(label="1. Push", color="blue", fontcolor="blue") >> semgrep
    semgrep >> Edge(label="Code OK", color="green", fontcolor="green") >> trivy_fs
    trivy_fs >> Edge(label="Deps OK", color="green", fontcolor="green") >> gitleaks
    gitleaks >> Edge(label="No secrets", color="green", fontcolor="green") >> security_gate1

    security_gate1 >> Edge(label="2. Build", color="blue", fontcolor="blue") >> docker_build
    docker_build >> Edge(label="Image", color="blue", fontcolor="blue") >> trivy_image
    trivy_image >> Edge(label="Scan OK", color="green", fontcolor="green") >> docker_registry
    docker_registry >> Edge(label="Push", color="blue", fontcolor="blue") >> cosign
    cosign >> sbom
    sbom >> Edge(label="Signed", color="green", fontcolor="green") >> security_gate2

    security_gate2 >> Edge(label="3. Validate", color="blue", fontcolor="blue") >> trivy_config
    trivy_config >> Edge(label="Config OK", color="green", fontcolor="green") >> conftest
    conftest >> Edge(label="Policy OK", color="green", fontcolor="green") >> kyverno_dryrun
    kyverno_dryrun >> Edge(label="Compliant", color="green", fontcolor="green") >> security_gate3

    security_gate3 >> Edge(label="4. Deploy Dev", color="blue", fontcolor="blue") >> helm_deploy
    helm_deploy >> dev_cluster >> dev_pod

    dev_pod >> Edge(label="5. Test", color="blue", fontcolor="blue") >> zap
    zap >> Edge(label="DAST OK", color="green", fontcolor="green") >> security_tests
    security_tests >> Edge(label="Tests pass", color="green", fontcolor="green") >> security_gate4

    security_gate4 >> Edge(label="6. Approve", color="orange", fontcolor="orange") >> prod_approval
    prod_approval >> Edge(label="Promote", color="blue", fontcolor="blue") >> prod_cluster

    prod_cluster >> Edge(label="Canary", color="purple", fontcolor="purple") >> canary_deploy
    canary_deploy >> Edge(label="Monitor", color="orange", fontcolor="orange") >> falco
    falco >> Edge(label="10min OK", color="green", fontcolor="green") >> full_deploy

    # Rollback path
    falco >> Edge(label="Alert!", color="red", fontcolor="red", style="dashed") >> rollback
    rollback >> Edge(label="Revert", color="red", fontcolor="red", style="dashed") >> prod_cluster

    # Failure paths (red, dashed)
    semgrep >> Edge(label="✗ Vuln found", color="red", fontcolor="red", style="dashed") >> commit
    trivy_image >> Edge(label="✗ CVE CRITICAL", color="red", fontcolor="red", style="dashed") >> docker_build
    conftest >> Edge(label="✗ Policy violation", color="red", fontcolor="red", style="dashed") >> commit

print("✓ DevSecOps Pipeline diagram generated: ../figures/svg/devsecops_semaphore_pipeline.png")
