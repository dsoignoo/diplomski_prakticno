#!/usr/bin/env python3
"""
Kubernetes Architecture Diagram - Thesis Example
Generates professional Kubernetes cluster diagram using Python Diagrams library
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.k8s.controlplane import APIServer, ControllerManager, Scheduler, KubeProxy, Kubelet
from diagrams.k8s.infra import ETCD, Node
from diagrams.k8s.compute import Pod
from diagrams.k8s.network import Service
from diagrams.k8s.storage import PersistentVolume

# Configuration for consistent styling
diagram_attr = {
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "0.80",
    "ranksep": "1.0"
}

node_attr = {
    "height": "1.5",
    "width": "1.5"
}

edge_attr = {}

with Diagram(
    "",
    filename="figures/svg/kubernetes_architecture_python",
    show=False,
    direction="TB",
    graph_attr=diagram_attr,
    node_attr=node_attr,
    edge_attr=edge_attr
):
    
    with Cluster("Kontrolna Ravan"):
        # Control plane components
        api_server = APIServer("kube-api-server")
        etcd = ETCD("etcd")
        controller = ControllerManager("kube-controller")
        scheduler = Scheduler("kube-scheduler")
        
        # Control plane connections
        api_server >> Edge(style="dashed") >> etcd
        api_server >> Edge(style="dashed") >> controller  
        api_server >> Edge(style="dashed") >> scheduler
    
    # Worker nodes
    with Cluster("Čvor 1"):
        kubelet1 = Kubelet("kubelet")
        proxy1 = KubeProxy("kube-proxy")
        
        with Cluster("Kontejneri"):
            pods1 = [
                Pod("pod-1"),
                Pod("pod-2"), 
                Pod("pod-3")
            ]
        
        kubelet1 >> pods1
        proxy1 >> pods1
    
    with Cluster("Čvor 2"):
        kubelet2 = Kubelet("kubelet")
        proxy2 = KubeProxy("kube-proxy")
        
        with Cluster("Kontejneri"):
            pods2 = [
                Pod("pod-4")
            ]
        
        kubelet2 >> pods2
        proxy2 >> pods2
    
    # Connections between control plane and worker nodes
    api_server >> Edge(style="dotted", color="blue") >> kubelet1
    api_server >> Edge(style="dotted", color="blue") >> kubelet2