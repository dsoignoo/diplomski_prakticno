#!/usr/bin/env python3
"""
Kubernetes Ingress Architecture - Thesis Diagram
Shows how external traffic is routed through Ingress to services and pods
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.onprem.client import Users, Client
from diagrams.onprem.network import Internet
from diagrams.k8s.network import Ingress, Service
from diagrams.k8s.compute import Pod, Deployment
from diagrams.generic.network import Firewall
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.certificates import CertManager
from diagrams.aws.network import ELB

# Configuration for ingress architecture styling
diagram_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.3",
    "nodesep": "0.30",
    "ranksep": "0.30"
}

node_attr = {
    "fontsize": "20",
    "height": "1.0",
    "width": "1.0"
}

edge_attr = {
    "fontsizelabelfontsize": "16",
    "labeldistance": "0",
    "labelangle": "0",
}

with Diagram(
    "",
    filename="figures/svg/ingress_architecture",
    show=False,
    direction="TB",
    graph_attr=diagram_attr,
    node_attr=node_attr,
    edge_attr=edge_attr
):

    # External clients
    with Cluster("Eksterni klijenti"):
        users = Users("Korisnici")
        api_clients = Client("API\nKlijenti")
        mobile = Client("Mobilne\nAplikacije")

    # Internet
    internet = Internet("Internet")

    # Cloud Load Balancer
    with Cluster("Cloud Provider"):
        lb = ELB("Load\nBalancer")
        waf = Firewall("WAF\n(Web Application\nFirewall)")

    # Kubernetes Cluster
    with Cluster("Kubernetes Klaster"):

        # Ingress Controller
        with Cluster("Ingress Controller"):
            ingress_ctrl = Ingress("Cloud\nIngress\nController")
            cert = CertManager("Cert-Manager\n(SSL/TLS)")
            rate_limit = Redis("Rate\nLimiter")

        # Services and Deployments
        with Cluster("Frontend Namespace"):
            frontend_svc = Service("Frontend\nService")
            with Cluster("Frontend Pods"):
                frontend_pods = [
                    Pod("web-1"),
                    Pod("web-2"),
                    Pod("web-3")
                ]

        with Cluster("API Namespace"):
            api_svc = Service("API\nService")
            with Cluster("API Pods"):
                api_pods = [
                    Pod("api-1"),
                    Pod("api-2")
                ]

        with Cluster("Backend Namespace"):
            backend_svc = Service("Backend\nService")
            with Cluster("Backend Pods"):
                backend_pods = [
                    Pod("backend-1"),
                    Pod("backend-2")
                ]

    # Traffic flow
    [users, api_clients, mobile] >> Edge(color="blue") >> internet
    internet >> Edge(label="HTTPS", color="blue", fontcolor="blue") >> lb
    lb >> Edge(label="filtrirano", color="orange", fontcolor="orange", fontsize="20") >> waf
    waf >> Edge(label="provjereno", color="green", fontcolor="green", fontsize="20") >> ingress_ctrl

    # SSL/TLS termination
    ingress_ctrl >> Edge(label="TLS", color="purple", fontcolor="purple", style="dashed") >> cert

    # Rate limiting
    ingress_ctrl >> Edge(label="limit", color="red", fontcolor="red", style="dashed") >> rate_limit

    # Routing rules
    ingress_ctrl >> Edge(label="putanja: /", color="blue", fontcolor="blue", fontsize="20") >> frontend_svc
    ingress_ctrl >> Edge(xlabel="putanja: /api", color="blue", fontcolor="blue", fontsize="20") >> api_svc
    ingress_ctrl >> Edge(xlabel="putanja: /backend", color="blue", fontcolor="blue", fontsize="20") >> backend_svc

    # Service to pods connections
    frontend_svc >> Edge(color="gray") >> frontend_pods
    api_svc >> Edge(color="gray") >> api_pods
    backend_svc >> Edge(color="gray") >> backend_pods