#!/usr/bin/env python3
"""
DevSecOps Workflow - Security Integration in Development Lifecycle
Shows shift-left security approach with continuous security integration
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

# Configuration for DevSecOps workflow
diagram_attr = {
    "fontsize": "12",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "0.60",
    "ranksep": "0.75",
    "splines": "ortho"
}

node_attr = {
    "fontsize": "10",
    "height": "1.0",
    "width": "1.0"
}

with Diagram(
    "",
    filename="figures/svg/devsecops_workflow",
    show=False,
    direction="LR",
    graph_attr=diagram_attr,
    node_attr=node_attr
):

    # Teams
    with Cluster("Timovi", graph_attr={"rank": "same"}):
        dev = User("Dev Tim")
        sec = User("Sec Tim")
        ops = User("Ops Tim")
        # Force horizontal layout
        dev - sec - ops

    # Plan & Design Phase
    with Cluster("1. Planiranje i Dizajn", graph_attr={"rank": "same"}):
        threat_model = Security("Modeliranje\nprijetnji")
        sec_req = Security("Sigurnosni\nzahtjevi")
        arch_review = Security("Pregled\narhitekture")
        # Force horizontal layout
        threat_model - sec_req - arch_review

    # Development Phase
    with Cluster("2. Razvoj", graph_attr={"rank": "same"}):
        ide = React("IDE sa\nSecurity\nPlugins")
        git_repo = Git("Git\n+ Pre-commit\nhooks")
        code_review = Security("Sigurnosni\npregled koda")
        # Force horizontal layout
        ide - git_repo - code_review

    # Build & Test Phase
    with Cluster("3. Build & Test", graph_attr={"rank": "same"}):
        sast = Security("SAST")
        dast = Security("DAST")
        sca = Security("SCA\n(Dependencies)")
        secrets = Security("Secret\nScanning")
        # Force horizontal layout
        sast - dast - sca - secrets

    # Infrastructure as Code
    with Cluster("4. Infrastructure", graph_attr={"rank": "same"}):
        iac = Terraform("IaC\n(Terraform)")
        policy = Security("Policy as\nCode (OPA)")
        compliance = Security("Compliance\nChecks")
        # Force horizontal layout
        iac - policy - compliance

    # Deployment Phase
    with Cluster("5. Deploy", graph_attr={"rank": "same"}):
        vault_secrets = Vault("HashiCorp\nVault")
        admission = Security("Admission\nControllers")
        deploy = Deployment("Secure\nDeploy")
        # Force horizontal layout
        vault_secrets - admission - deploy

    # Runtime Phase
    with Cluster("6. Runtime", graph_attr={"rank": "same"}):
        runtime_sec = Security("Runtime\nProtection")
        monitoring = Prometheus("Security\nMonitoring")
        incident = Security("Incident\nResponse")
        # Force horizontal layout
        runtime_sec - monitoring - incident

    # Feedback Loop
    feedback = Rack("Continuous\nFeedback")

    # Workflow connections
    # Planning phase
    [dev, sec, ops] >> Edge(label="saradnja", color="blue") >> threat_model
    threat_model >> Edge(color="blue") >> sec_req
    sec_req >> Edge(color="blue") >> arch_review

    # Development flow
    arch_review >> Edge(label="zahtjevi", color="green") >> ide
    ide >> Edge(label="commit", color="blue") >> git_repo
    git_repo >> Edge(label="review", color="orange") >> code_review

    # Testing flow
    code_review >> Edge(label="scan", color="red") >> sast
    code_review >> Edge(color="red") >> dast
    code_review >> Edge(color="red") >> sca
    code_review >> Edge(color="red") >> secrets

    # Infrastructure flow
    [sast, dast, sca, secrets] >> Edge(label="validated", color="green") >> iac
    iac >> Edge(label="policies", color="purple") >> policy
    policy >> Edge(label="comply", color="purple") >> compliance

    # Deployment flow
    compliance >> Edge(label="secrets", color="orange") >> vault_secrets
    vault_secrets >> Edge(label="inject", color="orange") >> admission
    admission >> Edge(label="deploy", color="green") >> deploy

    # Runtime flow
    deploy >> Edge(label="protect", color="red") >> runtime_sec
    runtime_sec >> Edge(label="monitor", color="blue") >> monitoring
    monitoring >> Edge(label="alert", color="red") >> incident

    # Feedback loops
    incident >> Edge(label="lessons", color="purple", style="dashed") >> feedback
    feedback >> Edge(label="improve", color="purple", style="dashed") >> threat_model

    # Security gates
    gate1 = Security("🚫 Gate")
    gate2 = Security("🚫 Gate")
    gate3 = Security("🚫 Gate")

    sast >> Edge(label="block if\nvulnerable", color="red", style="dotted") >> gate1
    policy >> Edge(label="block if\nnon-compliant", color="red", style="dotted") >> gate2
    admission >> Edge(label="block if\nunsafe", color="red", style="dotted") >> gate3