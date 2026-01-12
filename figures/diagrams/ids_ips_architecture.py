#!/usr/bin/env python3
"""
IDS/IPS Positioning in Kubernetes - Thesis Diagram
Shows placement of intrusion detection and prevention systems
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.k8s.controlplane import APIServer
from diagrams.k8s.infra import Node, ETCD
from diagrams.k8s.compute import Pod, DaemonSet
from diagrams.k8s.network import Service, NetworkPolicy
from diagrams.onprem.security import Trivy as Security
from diagrams.generic.network import Firewall
from diagrams.onprem.monitoring import Prometheus, Grafana
from diagrams.onprem.logging import FluentBit as Fluentd
from diagrams.elastic.elasticsearch import Elasticsearch
from diagrams.onprem.analytics import Spark

# Configuration for horizontal compact IDS/IPS architecture
diagram_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "0.60",
    "ranksep": "0.75"
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
    filename="../figures/svg/ids_ips_architecture",
    show=False,
    direction="LR",  # Horizontal layout
    graph_attr=diagram_attr,
    node_attr=node_attr,
    edge_attr=edge_attr
):

    # External threats
    threat = Security("Prijetnje")
    fw_external = Firewall("Firewall")

    # Kubernetes Cluster - arranged for horizontal flow
    with Cluster("Kubernetes Klaster"):

        # Top section - Control plane
        with Cluster("Kontrolna ravan"):
            api = APIServer("API")
            audit = Fluentd("Audit")
            falco = Security("Falco")

        # Bottom section - Workers and IDS
        with Cluster("Radni čvorovi & IDS"):
            nodes = [Node("N1"), Node("N2"), Node("N3")]
            ebpf = DaemonSet("eBPF")
            suricata = Security("IDS")
            netpol = NetworkPolicy("NetPol")

    # SIEM - simplified
    with Cluster("SIEM"):
        collector = Fluentd("Logs")
        elastic = Elasticsearch("Elastic")
        siem = Security("SIEM")

    # Main flow - horizontal
    threat >> Edge(label="napad", color="red", fontcolor="red") >> fw_external
    fw_external >> Edge(color="green") >> api

    # Monitoring connections
    api >> audit >> collector
    api >> falco >> collector

    # Node monitoring
    for node in nodes:
        node >> Edge(label="promet", style="dotted") >> ebpf
        node >> Edge(style="dotted") >> suricata

    ebpf >> collector
    suricata >> collector

    # SIEM flow
    collector >> elastic >> siem

    # Enforcement
    siem >> Edge(label="pravila", color="red", fontcolor="red") >> netpol
    netpol >> Edge(style="dashed") >> nodes