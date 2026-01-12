#!/usr/bin/env python3
"""
MITRE ATT&CK Kill Chain for Kubernetes - Thesis Diagram
Shows the attack phases and techniques specific to Kubernetes environments
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.onprem.client import User
from diagrams.onprem.network import Internet
from diagrams.k8s.compute import Pod
from diagrams.k8s.controlplane import APIServer
from diagrams.k8s.infra import ETCD
from diagrams.onprem.security import Trivy
from diagrams.generic.compute import Rack
from diagrams.generic.network import Firewall

# Configuration for attack chain styling
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
    filename="figures/svg/mitre_attack_chain",
    show=False,
    direction="LR",
    graph_attr=diagram_attr,
    node_attr=node_attr,
    edge_attr=edge_attr
):

    # Attacker
    attacker = User("Napadač")

    # Kill Chain Phases
    with Cluster("1. Izviđanje\n(Reconnaissance)"):
        recon = Internet("Skeniranje\nportova")

    with Cluster("2. Naoružavanje\n(Weaponization)"):
        weapon = Trivy("Maliciozni\nkontejner")

    with Cluster("3. Dostavljanje\n(Delivery)"):
        delivery = Pod("Kompromitovan\npod")

    with Cluster("4. Eksploatacija\n(Exploitation)"):
        exploit = Pod("Eskalacija\nprivilegija")

    with Cluster("5. Instalacija\n(Installation)"):
        install = Pod("Backdoor\nkontejner")

    with Cluster("6. Komanda i Kontrola\n(C2)"):
        c2 = Internet("C2 Server")

    with Cluster("7. Akcije na cilju\n(Actions)"):
        with Cluster("Kubernetes Klaster"):
            api = APIServer("API Server")
            etcd_db = ETCD("ETCD\n(ukradeni podaci)")
            lateral = Pod("Lateralno\nkretanje")

    # Attack flow
    attacker >> Edge(label="1", color="red", fontcolor="red") >> recon
    recon >> Edge(label="2", color="red", fontcolor="red") >> weapon
    weapon >> Edge(label="3", color="red", fontcolor="red") >> delivery
    delivery >> Edge(label="4", color="red", fontcolor="red") >> exploit
    exploit >> Edge(label="5", color="red", fontcolor="red") >> install
    install >> Edge(label="6", color="red", fontcolor="red", style="dashed") >> c2
    c2 >> Edge(label="7", color="red", fontcolor="red", style="dashed") >> api
    api >> Edge(color="red") >> etcd_db
    api >> Edge(color="red") >> lateral

    # Defense points (where we can break the chain)
    defense1 = Firewall("Firewall")
    defense2 = Trivy("IDS/IPS")
    defense3 = Trivy("RBAC")

    recon >> Edge(label="blokirati", color="green", fontcolor="green", style="dotted") >> defense1
    exploit >> Edge(label="detektovati", color="green", fontcolor="green", style="dotted") >> defense2
    api >> Edge(label="ograničiti", color="green", fontcolor="green", style="dotted") >> defense3