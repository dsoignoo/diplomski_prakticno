#!/usr/bin/env python3
"""
Kubernetes Diagram Template - Thesis
Template for creating consistent Kubernetes diagrams with Bosnian labels
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.k8s.controlplane import APIServer, ControllerManager, Scheduler, Kubelet, KubeProxy
from diagrams.k8s.infra import ETCD, Node
from diagrams.k8s.compute import Pod, Deployment, Service
from diagrams.k8s.network import NetworkPolicy, Ingress
from diagrams.k8s.podconfig import Secret, ConfigMap
from diagrams.k8s.rbac import ServiceAccount, ClusterRole, Role
from diagrams.k8s.storage import PersistentVolume, PersistentVolumeClaim

# Standard configuration for thesis diagrams
diagram_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "0.60",
    "ranksep": "0.75"
}

node_attr = {
    "fontsize": "12",
    "height": "1.2",
    "width": "1.2"
}

edge_attr = {
    "fontsize": "11",
}

# TODO: Change diagram name and filename
with Diagram(
    "Naslov Dijagrama na Bosanskom",
    filename="figures/svg/template_diagram",
    show=False,
    direction="TB",  # TB = top-bottom, LR = left-right
    graph_attr=diagram_attr,
    node_attr=node_attr,
    edge_attr=edge_attr
):
    
    # Example structure - modify as needed
    with Cluster("Kubernetes Klaster"):
        
        with Cluster("Kontrolna Ravan"):
            api = APIServer("API Server")
            etcd = ETCD("etcd")
            
        with Cluster("Radni Čvor"):
            kubelet = Kubelet("kubelet")
            
            with Cluster("Aplikacija"):
                pod = Pod("Pod")
                
        # Connections
        api >> kubelet
        kubelet >> pod

# Available Kubernetes components for reference:
#
# Control Plane:
# - APIServer, ControllerManager, Scheduler, Kubelet, KubeProxy
#
# Infrastructure: 
# - ETCD, Node, Master
#
# Compute:
# - Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob, ReplicaSet
#
# Network:
# - Service, Ingress, NetworkPolicy, Endpoint
#
# Storage:
# - PersistentVolume, PersistentVolumeClaim, StorageClass, Volume
#
# Configuration:
# - Secret, ConfigMap
#
# RBAC:
# - ServiceAccount, ClusterRole, Role
#
# Standard Bosnian terms to use:
# - Klaster = Cluster
# - Čvor = Node  
# - Kontrolna Ravan = Control Plane
# - Radni Čvor = Worker Node
# - Aplikacija = Application
# - Servis = Service
# - Mrežna Politika = Network Policy
# - Sigurnost = Security
# - Skladište = Storage