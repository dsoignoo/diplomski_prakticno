#!/usr/bin/env python3
"""
Kubernetes Security Architecture Diagram - Thesis Example
Focuses on security components and layers in Kubernetes
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.k8s.controlplane import APIServer, ControllerManager, Scheduler
from diagrams.k8s.infra import ETCD
from diagrams.k8s.compute import Pod
from diagrams.k8s.network import NetworkPolicy, Service
from diagrams.k8s.podconfig import Secret, ConfigMap
from diagrams.k8s.rbac import ServiceAccount, ClusterRole, Role
from diagrams.onprem.security import Vault

# Configuration for security-focused styling
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

with Diagram(
    "",
    filename="figures/svg/kubernetes_security_architecture",
    show=False,
    direction="TB",
    graph_attr=diagram_attr,
    node_attr=node_attr,
    edge_attr=edge_attr
):
    
    # External security layer
    with Cluster("Vanjski Sigurnosni Sloj"):
        vault = Vault("HashiCorp Vault")
    
    with Cluster("Kubernetes Klaster"):
        
        # Control plane with security focus
        with Cluster("Kontrolna Ravan"):
            api_server = APIServer("API Server\n(TLS, RBAC)")
            etcd = ETCD("etcd\n(enkriptovan)")
            controller = ControllerManager("Controller Manager")
            scheduler = Scheduler("Scheduler")
            
            # Control plane security connections
            api_server >> Edge(label="TLS", style="dashed") >> etcd
            api_server >> controller
            api_server >> scheduler
        
        # RBAC components  
        with Cluster("RBAC"):
            sa = ServiceAccount("ServiceAccount")
            cluster_role = ClusterRole("ClusterRole")
            role = Role("Role")
            
            sa >> cluster_role
            sa >> role
        
        # Security policies
        with Cluster("Mrežne Sigurnosne Politike"):
            netpol = NetworkPolicy("NetworkPolicy")
            
        # Application layer with security
        with Cluster("Čvor 1 - Aplikacijski Sloj"):
            # Security configurations
            secret = Secret("Secret")
            configmap = ConfigMap("ConfigMap")
            
            # Application pods
            with Cluster("Sigurni Pod-ovi"):
                app_pod = Pod("App Pod\n(non-root)")
                security_pod = Pod("Security Pod\n(restricted)")
            
            # Security connections
            secret >> app_pod
            configmap >> app_pod
            sa >> app_pod
            netpol >> app_pod
            
        with Cluster("Čvor 2 - Monitoring"):
            monitor_pod = Pod("Security\nMonitoring")
            
        # External to internal security flow
        vault >> Edge(label="Secrets", color="red", fontcolor="red", style="bold") >> secret
        
        # API server RBAC connections
        api_server >> Edge(label="autentifikacija", color="green", fontcolor="green") >> sa
        api_server >> Edge(label="autorizacija", color="green", fontcolor="green") >> cluster_role
        
        # Network security
        netpol >> Edge(label="mrežni promet", color="orange", fontcolor="orange") >> [app_pod, security_pod]