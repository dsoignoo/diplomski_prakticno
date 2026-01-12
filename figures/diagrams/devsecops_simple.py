#!/usr/bin/env python3
"""
Simple DevSecOps Workflow - Linear flow without complex clustering
"""

from diagrams import Diagram, Edge
from diagrams.programming.framework import React
from diagrams.onprem.vcs import Git
from diagrams.onprem.security import Trivy as Security
from diagrams.k8s.compute import Deployment
from diagrams.onprem.monitoring import Prometheus
from diagrams.onprem.security import Vault
from diagrams.onprem.client import User
from diagrams.onprem.iac import Terraform

# Simple configuration
diagram_attr = {
    "fontsize": "14",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "1.0",
    "ranksep": "0.8",
}

node_attr = {
    "fontsize": "11",
    "height": "0.8",
    "width": "1.2"
}

with Diagram(
    "",
    filename="figures/svg/devsecops_workflow",
    show=False,
    direction="TB",
    graph_attr=diagram_attr,
    node_attr=node_attr
):

    # Simple linear flow
    developer = User("Developer")

    threat_model = Security("Threat\\nModeling")

    ide = React("Secure\\nDevelopment")

    git = Git("Source\\nControl")

    sast = Security("SAST\\nScanning")

    build = Security("Secure\\nBuild")

    image_scan = Security("Image\\nScanning")

    iac = Terraform("Infrastructure\\nas Code")

    vault = Vault("Secrets\\nManagement")

    deploy = Deployment("Secure\\nDeployment")

    monitor = Prometheus("Runtime\\nMonitoring")

    incident = Security("Incident\\nResponse")

    # Simple flow with colored edges
    developer >> Edge(label="1. Plan", color="blue") >> threat_model
    threat_model >> Edge(label="2. Develop", color="green") >> ide
    ide >> Edge(label="3. Commit", color="blue") >> git
    git >> Edge(label="4. Test", color="red") >> sast
    sast >> Edge(label="5. Build", color="orange") >> build
    build >> Edge(label="6. Scan", color="red") >> image_scan
    image_scan >> Edge(label="7. Infrastructure", color="purple") >> iac
    iac >> Edge(label="8. Secrets", color="orange") >> vault
    vault >> Edge(label="9. Deploy", color="green") >> deploy
    deploy >> Edge(label="10. Monitor", color="blue") >> monitor
    monitor >> Edge(label="11. Respond", color="red") >> incident

    # Feedback loop
    incident >> Edge(label="Improve", color="gray", style="dashed") >> threat_model