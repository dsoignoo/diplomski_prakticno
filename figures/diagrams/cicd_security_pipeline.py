#!/usr/bin/env python3
"""
CI/CD Security Pipeline with Trivy Integration - Thesis Diagram
Shows security checkpoints throughout the CI/CD process
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.onprem.vcs import Git
from diagrams.onprem.ci import Jenkins, GithubActions
from diagrams.onprem.container import Docker
from diagrams.k8s.compute import Deployment
from diagrams.k8s.infra import Node
from diagrams.onprem.security import Trivy as Security
from diagrams.generic.storage import Storage
from diagrams.onprem.monitoring import Grafana

# Configuration for pipeline styling
diagram_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "0.60",
    "ranksep": "0.75",
    "splines": "ortho"
}

node_attr = {
    "fontsize": "12",
    "height": "1.0",
    "width": "1.0"
}

edge_attr = {
    "fontsize": "11",
}

with Diagram(
    "",
    filename="figures/svg/cicd_security_pipeline",
    show=False,
    direction="LR",
    graph_attr=diagram_attr,
    node_attr=node_attr,
    edge_attr=edge_attr
):

    # Source Control
    with Cluster("Kontrola koda"):
        git = Git("Git\nRepozitorij")

    # CI Phase
    with Cluster("Kontinuirana Integracija"):
        ci = GithubActions("CI Server")

        with Cluster("Sigurnosne provjere"):
            sast = Security("SAST\nStatička analiza")
            deps = Security("Dependency\nScan")

    # Build Phase
    with Cluster("Izgradnja"):
        build = Docker("Docker\nBuild")

        with Cluster("Skeniranje slika"):
            trivy = Security("Trivy\nScan")
            vuln_db = Storage("CVE\nBaza")

    # Registry
    with Cluster("Registar"):
        registry = Docker("Container\nRegistry")
        sign = Security("Potpisivanje\nslika")

    # CD Phase
    with Cluster("Kontinuirana Dostava"):
        with Cluster("Staging"):
            staging = Deployment("Staging\nDeploy")
            test = Security("Sigurnosni\ntestovi")

        with Cluster("Produkcija"):
            prod = Deployment("Production\nDeploy")
            monitor = Grafana("Runtime\nMonitoring")

    # Pipeline flow
    git >> Edge(label="1. kod", color="blue", fontcolor="blue") >> ci

    # Security checks in CI
    ci >> Edge(label="2. analiza", color="orange", fontcolor="orange") >> sast
    ci >> Edge(label="3. zavisnosti", color="orange", fontcolor="orange") >> deps

    # Build and scan
    ci >> Edge(label="4. build", color="blue", fontcolor="blue") >> build
    build >> Edge(label="5. skeniranje", color="red", fontcolor="red", style="bold") >> trivy
    trivy >> Edge(style="dashed") >> vuln_db

    # Registry phase
    trivy >> Edge(label="6. push", color="green", fontcolor="green") >> registry
    registry >> Edge(label="7. potpis", color="purple", fontcolor="purple") >> sign

    # Deployment
    sign >> Edge(label="8. staging", color="blue", fontcolor="blue") >> staging
    staging >> Edge(label="9. testiranje", color="orange", fontcolor="orange") >> test
    test >> Edge(label="10. produkcija", color="green", fontcolor="green", style="bold") >> prod
    prod >> Edge(label="11. monitoring", color="purple", fontcolor="purple") >> monitor

    # Security gates (blocking points)
    block1 = Security("❌ Blokiraj\nako CRITICAL")
    block2 = Security("❌ Blokiraj\nako nepotpisan")

    trivy >> Edge(label="ranjivosti", color="red", fontcolor="red", style="dotted") >> block1
    sign >> Edge(label="verifikacija", color="red", fontcolor="red", style="dotted") >> block2