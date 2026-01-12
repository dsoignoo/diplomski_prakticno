#!/usr/bin/env python3
"""
Threat Model Diagram za Semaphore CI/CD Platformu
Prikazuje STRIDE analizu i attack paths za Guard authentication service
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.k8s.compute import Pod
from diagrams.k8s.network import Service
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.security import Vault
from diagrams.programming.language import Elixir
from diagrams.generic.blank import Blank
from diagrams.custom import Custom

# Grafički attributi
graph_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "0.8",
    "ranksep": "1.0",
    "splines": "ortho",
    "concentrate": "false"
}

node_attr = {
    "fontsize": "12",
    "fontname": "Sans-Serif",
    "margin": "0.2"
}

edge_attr = {
    "fontsize": "11",
    "fontname": "Sans-Serif"
}

with Diagram("STRIDE Threat Model - Semaphore Guard Service",
             filename="../figures/svg/threat_model_semaphore",
             direction="TB",
             graph_attr=graph_attr,
             node_attr=node_attr,
             edge_attr=edge_attr,
             show=False):

    # External attacker
    with Cluster("🔴 External Threats"):
        attacker = Blank("Napadač")

    # Trust boundary 1: Internet → Kubernetes
    with Cluster("🔵 Trust Boundary 1: Internet → GKE Cluster"):
        ingress = Service("Ingress\nController")

    # Trust boundary 2: Ingress → Application
    with Cluster("🟢 Semaphore Namespace (Trust Boundary 2)"):

        # Guard service - centralna komponenta
        with Cluster("Guard Service (Authentication)"):
            guard_pod = Pod("Guard\nPod")
            guard_svc = Service("Guard\nService")
            guard_pod - Edge(label="exposes", style="dotted") - guard_svc

        # Backend services
        with Cluster("Backend Services"):
            rbac_svc = Service("RBAC\nService")
            postgres = PostgreSQL("PostgreSQL\n(User Data)")

        # Secrets
        with Cluster("Secrets Store"):
            k8s_secret = Vault("Kubernetes\nSecrets")

    # === STRIDE ATTACK PATHS ===

    # S - Spoofing
    attacker >> Edge(label="S1: Fake User Login\n(Brute Force)", color="red", fontcolor="red", style="bold") >> ingress

    # T - Tampering
    guard_pod >> Edge(label="T1: Tamper Token\n(JWT Forgery)", color="orange", fontcolor="orange", style="dashed") >> guard_svc

    # R - Repudiation
    guard_pod >> Edge(label="R1: Delete Audit Logs", color="brown", fontcolor="brown", style="dashed") >> postgres

    # I - Information Disclosure
    guard_pod >> Edge(label="I1: Read K8s Secrets\n(SA Token Theft)", color="purple", fontcolor="purple", style="bold") >> k8s_secret
    postgres >> Edge(label="I2: Secret Exposure\nin Logs", color="purple", fontcolor="purple", style="dashed") >> Blank("Logs")

    # D - Denial of Service
    attacker >> Edge(label="D1: API Rate\nLimit Bypass", color="darkred", fontcolor="darkred", style="bold") >> ingress

    # E - Elevation of Privilege
    guard_pod >> Edge(label="E1: RBAC\nMisconfiguration", color="darkblue", fontcolor="darkblue", style="bold") >> rbac_svc

    # === LEGITIMATE FLOWS (GREEN) ===
    ingress >> Edge(label="✅ Auth Request", color="green", fontcolor="green") >> guard_svc
    guard_svc >> Edge(label="✅ Validate", color="green", fontcolor="green") >> guard_pod
    guard_pod >> Edge(label="✅ Check Permissions", color="green", fontcolor="green") >> rbac_svc
    guard_pod >> Edge(label="✅ Query User", color="green", fontcolor="green") >> postgres
    guard_pod >> Edge(label="✅ Get DB Password", color="green", fontcolor="green", style="dotted") >> k8s_secret

print("✅ Threat model dijagram kreiran: figures/svg/threat_model_semaphore.png")
