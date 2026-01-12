#!/usr/bin/env python3
"""
DevSecOps Workflow v2 - Optimized layout for readability
Clusters arranged vertically, nodes within clusters arranged horizontally
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.programming.framework import React, Django
from diagrams.onprem.vcs import Git
from diagrams.onprem.ci import Jenkins
from diagrams.onprem.security import Trivy as Security
from diagrams.k8s.compute import Deployment
from diagrams.onprem.monitoring import Prometheus
from diagrams.onprem.security import Vault
from diagrams.onprem.client import User
from diagrams.onprem.iac import Terraform
from diagrams.generic.compute import Rack

# Configuration optimized for vertical clusters, horizontal nodes
diagram_attr = {
    "fontsize": "14",
    "bgcolor": "white",
    "pad": "0.3",
    "nodesep": "0.8",
    "ranksep": "1.0",
    "splines": "ortho"
}

node_attr = {
    "fontsize": "10",
    "height": "0.8",
    "width": "1.2"
}

edge_attr = {
    "fontsize": "9",
}

with Diagram(
    "",
    filename="figures/svg/devsecops_workflow",
    show=False,
    direction="TB",
    graph_attr=diagram_attr,
    node_attr=node_attr,
    edge_attr=edge_attr
):

    # Row 1: Teams
    with Cluster("Timovi"):
        dev = User("Dev")
        sec = User("Sec")
        ops = User("Ops")

    # Row 2: Planning
    with Cluster("1. Planiranje"):
        threat_model = Security("Modeliranje\\nprijetnji")
        sec_req = Security("Sigurnosni\\nzahtjevi")
        arch_review = Security("Pregled\\narhitekture")

    # Row 3: Development
    with Cluster("2. Razvoj"):
        ide = React("IDE + Security")
        git_repo = Git("Git + Hooks")
        code_review = Security("Code Review")

    # Row 4: Testing
    with Cluster("3. Testiranje"):
        sast = Security("SAST")
        dast = Security("DAST")
        sca = Security("SCA")
        secrets_scan = Security("Secrets")

    # Row 5: Infrastructure
    with Cluster("4. Infrastructure"):
        iac = Terraform("IaC")
        policy = Security("OPA")
        compliance = Security("Compliance")

    # Row 6: Deployment
    with Cluster("5. Deploy"):
        vault_secrets = Vault("Vault")
        admission = Security("Admission")
        deploy = Deployment("Deploy")

    # Row 7: Runtime
    with Cluster("6. Runtime"):
        runtime_sec = Security("Runtime")
        monitoring = Prometheus("Monitor")
        incident = Security("Incident")

    # Workflow connections - simplified for clarity
    # Planning flow
    [dev, sec, ops] >> Edge(color="blue") >> threat_model
    threat_model >> sec_req >> arch_review

    # Development flow
    arch_review >> Edge(color="green") >> ide
    ide >> git_repo >> code_review

    # Testing flow
    code_review >> Edge(color="red") >> sast
    code_review >> dast
    code_review >> sca
    code_review >> secrets_scan

    # Infrastructure flow
    [sast, dast, sca, secrets_scan] >> Edge(color="purple") >> iac
    iac >> policy >> compliance

    # Deployment flow
    compliance >> Edge(color="orange") >> vault_secrets
    vault_secrets >> admission >> deploy

    # Runtime flow
    deploy >> Edge(color="red") >> runtime_sec
    runtime_sec >> monitoring >> incident

    # Feedback loop
    incident >> Edge(label="feedback", color="gray", style="dashed") >> threat_model