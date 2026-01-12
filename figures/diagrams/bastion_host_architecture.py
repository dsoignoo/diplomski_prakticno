#!/usr/bin/env python3
"""
Bastion Host Architecture Diagram for Private GKE Cluster
Dijagram arhitekture bastionskog hosta za privatni GKE klaster
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.gcp.compute import GKE, ComputeEngine
from diagrams.gcp.network import VPC
from diagrams.gcp.security import IAP
from diagrams.onprem.client import User
from diagrams.onprem.network import Internet

graph_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.5",
}

node_attr = {
    "fontsize": "12",
}

edge_attr = {
    "fontsize": "11",
}

with Diagram(
    "Bastion Host Arhitektura",
    filename="../figures/svg/bastion_host_architecture",
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):
    admin = User("Administrator")
    internet = Internet("Internet")
    iap = IAP("Identity-Aware\nProxy (IAP)")

    with Cluster("Google Cloud VPC"):
        bastion = ComputeEngine("Bastionski host\n(Proxy server)")

        with Cluster("Privatni GKE klaster"):
            control_plane = GKE("Kontrolna raven\n(Private)")
            workers = [
                ComputeEngine("Radni cvor 1"),
                ComputeEngine("Radni cvor 2"),
            ]

    # Connection flow
    admin >> Edge(label="1. SSH zahtjev") >> internet
    internet >> Edge(label="2. IAP tunel", color="green", fontcolor="green") >> iap
    iap >> Edge(label="3. Siguran pristup", color="green", fontcolor="green") >> bastion
    bastion >> Edge(label="4. Proxy veza", color="blue", fontcolor="blue") >> control_plane

    for worker in workers:
        control_plane >> Edge(color="darkblue") >> worker

    # Show blocked connection
    internet >> Edge(label="Direktna veza\nBLOKIRANA", color="red", fontcolor="red", style="dashed") >> control_plane

print("✓ Bastion host architecture diagram generated successfully!")
