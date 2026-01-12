#!/usr/bin/env python3
"""
Kubernetes Resources Hierarchy Diagram - Thesis Example
Shows the hierarchical organization of Kubernetes resources
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.k8s.infra import Node
from diagrams.k8s.compute import Pod
from diagrams.k8s.network import Service
from diagrams.k8s.podconfig import ConfigMap, Secret
from diagrams.k8s.storage import PersistentVolume, PersistentVolumeClaim
from diagrams.k8s.group import Namespace

# Configuration for hierarchy styling
diagram_attr = {
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "1.0",
    "ranksep": "1.2",
    "splines": "true"
}

node_attr = {
    "height": "1.0",
    "width": "1.0"
}

edge_attr = {}

with Diagram(
    "",
    filename="../figures/svg/kubernetes_resources",
    show=False,
    direction="TB",
    graph_attr=diagram_attr,
    node_attr=node_attr,
    edge_attr=edge_attr
):

    # Main Cluster
    with Cluster("Klaster"):

        # Persistent Volume at cluster level
        pv = PersistentVolume("Persistent\nVolume")

        # Namespace
        with Cluster("Namespace (imenski prostor)"):

            # Services and ConfigMaps at namespace level
            service = Service("Service")
            configmap = ConfigMap("ConfigMap")
            secret = Secret("Secret")
            pvc = PersistentVolumeClaim("PVC")

            # Node 1
            with Cluster("Čvor 1"):
                node1 = Node("Node 1")

                with Cluster("Pod 1"):
                    pod1 = Pod("Pod 1")

                    # Containers in Pod 1
                    with Cluster("Kontejneri"):
                        from diagrams.onprem.container import Docker
                        container1 = Docker("Container 1")
                        container2 = Docker("Container 2")

                    # Container relationships
                    pod1 >> Edge(color="gray", style="dashed") >> [container1, container2]

            # Node 2
            with Cluster("Čvor 2"):
                node2 = Node("Node 2")

                with Cluster("Pod 2"):
                    pod2 = Pod("Pod 2")

                    # Container in Pod 2
                    with Cluster("Kontejneri"):
                        container3 = Docker("Container 3")

                    # Container relationship
                    pod2 >> Edge(color="gray", style="dashed") >> container3

            # Service selects pods
            service >> Edge(label="selektuje", color="blue", fontcolor="blue", style="bold") >> pod1
            service >> Edge(label="selektuje", color="blue", fontcolor="blue", style="bold") >> pod2

            # ConfigMap mounts to pods
            configmap >> Edge(label="montira na", color="orange", fontcolor="orange", style="dashed") >> pod1

            # Secret mounts to pods
            secret >> Edge(label="montira na", color="red", fontcolor="red", style="dashed") >> pod2

            # PVC claims PV
            pvc >> Edge(label="koristi", color="green", fontcolor="green", style="bold") >> pv

            # PVC mounts to pod
            pvc >> Edge(label="montira na", color="green", fontcolor="green", style="dashed") >> pod1