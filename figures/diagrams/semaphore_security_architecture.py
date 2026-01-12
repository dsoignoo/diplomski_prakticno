#!/usr/bin/env python3
"""
Semaphore Security Architecture - Multi-Layer Security Implementation
Prikazuje kompletnu sigurnosnu arhitekturu Semaphore platforme sa svim slojevima zaštite
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.onprem.client import Users
from diagrams.onprem.network import Nginx, Traefik
from diagrams.k8s.network import Ingress, NetworkPolicy, Service
from diagrams.k8s.compute import Pod, Deployment
from diagrams.k8s.storage import PV, PVC, StorageClass
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.queue import RabbitMQ
from diagrams.onprem.monitoring import Prometheus, Grafana
from diagrams.onprem.logging import Loki
from diagrams.onprem.tracing import Jaeger
from diagrams.onprem.security import Vault
from diagrams.custom import Custom
import os

# Putanja do custom ikona (ako su potrebne)
graph_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "0.8",
    "ranksep": "1.0",
}

node_attr = {
    "fontsize": "12",
}

edge_attr = {
    "fontsize": "11",
}

with Diagram(
    "Semaphore Security Architecture",
    filename="../figures/svg/semaphore_security_architecture",
    outformat="png",
    show=False,
    direction="TB",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    users = Users("Eksterni\nkorisnici")

    with Cluster("Edge Security Layer"):
        with Cluster("Cloud Provider\nDDoS & WAF"):
            cloud_armor = Custom("Cloud Armor\nAWS Shield\nAzure DDoS", "./icons/shield.png") if os.path.exists("./icons/shield.png") else Nginx("Cloud\nProtection")

        waf = Nginx("ModSecurity\nWAF")
        cert_mgr = Custom("cert-manager\n(TLS)", "./icons/cert.png") if os.path.exists("./icons/cert.png") else Nginx("cert-manager")

    with Cluster("Ingress Layer"):
        ingress = Ingress("Ingress\nController")
        rate_limit = Nginx("Rate\nLimiting")

    with Cluster("Service Mesh (Optional)"):
        mesh = Custom("Istio/Linkerd\nmTLS", "./icons/mesh.png") if os.path.exists("./icons/mesh.png") else Service("Service\nMesh")

    with Cluster("Application Layer"):
        with Cluster("Semaphore Namespace"):
            with Cluster("Frontend"):
                front_deploy = Deployment("Front\nDeployment")
                front_pod = Pod("Web UI\nPod")
                front_svc = Service("Front\nService")
                front_netpol = NetworkPolicy("Front\nNetworkPolicy")

            with Cluster("Authentication"):
                guard_deploy = Deployment("Guard\nDeployment")
                guard_pod = Pod("Auth\nPod")
                guard_svc = Service("Guard\nService")
                guard_netpol = NetworkPolicy("Guard\nNetworkPolicy")

            with Cluster("CI/CD Processing"):
                hooks_deploy = Deployment("Hooks\nDeployment")
                hooks_pod = Pod("Webhook\nProcessor")
                hooks_svc = Service("Hooks\nService")
                hooks_netpol = NetworkPolicy("Hooks\nNetworkPolicy")

            with Cluster("RBAC Service"):
                rbac_deploy = Deployment("RBAC\nDeployment")
                rbac_pod = Pod("Permissions\nPod")
                rbac_svc = Service("RBAC\nService")
                rbac_netpol = NetworkPolicy("RBAC\nNetworkPolicy")

    with Cluster("Data Layer"):
        with Cluster("PostgreSQL"):
            postgres = PostgreSQL("Primary\nDatabase")
            pg_pvc = PVC("DB\nStorage")
            pg_netpol = NetworkPolicy("DB\nNetworkPolicy")

        with Cluster("Redis"):
            redis_node = Redis("Cache &\nSessions")
            redis_netpol = NetworkPolicy("Redis\nNetworkPolicy")

        with Cluster("RabbitMQ"):
            rabbitmq = RabbitMQ("Message\nQueue")
            rmq_netpol = NetworkPolicy("RabbitMQ\nNetworkPolicy")

    with Cluster("Security & Observability Layer"):
        with Cluster("Monitoring"):
            prometheus = Prometheus("Prometheus\nMetrics")
            grafana = Grafana("Grafana\nDashboards")

        with Cluster("Logging"):
            loki = Loki("Loki\nLogs")

        with Cluster("Tracing"):
            jaeger = Jaeger("Jaeger\nTraces")

        with Cluster("Runtime Security"):
            falco = Custom("Falco\nRuntime", "./icons/falco.png") if os.path.exists("./icons/falco.png") else Pod("Falco\nDaemonSet")

        with Cluster("Secrets"):
            secrets = Vault("External\nSecrets")

    with Cluster("Policy Enforcement Layer"):
        gatekeeper = Custom("OPA\nGatekeeper", "./icons/opa.png") if os.path.exists("./icons/opa.png") else Pod("Gatekeeper")
        pss = Custom("Pod Security\nStandards", "./icons/pss.png") if os.path.exists("./icons/pss.png") else Pod("PSS")

    # Traffic flow
    users >> Edge(label="HTTPS", color="green", fontcolor="green") >> cloud_armor
    cloud_armor >> Edge(label="Filtered", color="green", fontcolor="green") >> waf
    waf >> Edge(label="TLS", color="green", fontcolor="green") >> cert_mgr
    cert_mgr >> ingress
    ingress >> rate_limit
    rate_limit >> mesh

    # Application routing
    mesh >> Edge(label="Web UI", color="blue", fontcolor="blue") >> front_svc
    mesh >> Edge(label="API", color="blue", fontcolor="blue") >> guard_svc
    mesh >> Edge(label="Webhooks", color="blue", fontcolor="blue") >> hooks_svc

    front_svc >> front_netpol >> front_pod
    guard_svc >> guard_netpol >> guard_pod
    hooks_svc >> hooks_netpol >> hooks_pod

    # Inter-service communication (allowed by NetworkPolicies)
    front_pod >> Edge(label="Auth", color="purple", fontcolor="purple", style="dashed") >> guard_pod
    guard_pod >> Edge(label="Permissions", color="purple", fontcolor="purple", style="dashed") >> rbac_pod
    hooks_pod >> Edge(label="Enqueue", color="purple", fontcolor="purple", style="dashed") >> rabbitmq

    # Database access (controlled by NetworkPolicies)
    guard_pod >> Edge(label="Query", color="darkgreen", fontcolor="darkgreen") >> pg_netpol >> postgres
    postgres >> pg_pvc

    # Cache & Queue access
    guard_pod >> Edge(label="Cache", color="darkgreen", fontcolor="darkgreen") >> redis_netpol >> redis_node
    hooks_pod >> Edge(label="Publish", color="darkgreen", fontcolor="darkgreen") >> rmq_netpol >> rabbitmq

    # Observability connections
    front_pod >> Edge(label="Metrics", color="orange", fontcolor="orange", style="dotted") >> prometheus
    guard_pod >> Edge(label="Metrics", color="orange", fontcolor="orange", style="dotted") >> prometheus
    hooks_pod >> Edge(label="Metrics", color="orange", fontcolor="orange", style="dotted") >> prometheus
    rbac_pod >> Edge(label="Metrics", color="orange", fontcolor="orange", style="dotted") >> prometheus

    front_pod >> Edge(label="Logs", color="gray", fontcolor="gray", style="dotted") >> loki
    guard_pod >> Edge(label="Logs", color="gray", fontcolor="gray", style="dotted") >> loki
    hooks_pod >> Edge(label="Logs", color="gray", fontcolor="gray", style="dotted") >> loki

    front_pod >> Edge(label="Traces", color="brown", fontcolor="brown", style="dotted") >> jaeger
    guard_pod >> Edge(label="Traces", color="brown", fontcolor="brown", style="dotted") >> jaeger
    hooks_pod >> Edge(label="Traces", color="brown", fontcolor="brown", style="dotted") >> jaeger

    prometheus >> grafana

    # Security monitoring
    falco >> Edge(label="Alerts", color="red", fontcolor="red") >> prometheus
    guard_pod >> Edge(label="Secrets", color="darkblue", fontcolor="darkblue", style="dashed") >> secrets

    # Policy enforcement (admission control)
    gatekeeper >> Edge(label="Validate", color="red", fontcolor="red", style="bold") >> [front_deploy, guard_deploy, hooks_deploy, rbac_deploy]
    pss >> Edge(label="Enforce", color="red", fontcolor="red", style="bold") >> [front_deploy, guard_deploy, hooks_deploy, rbac_deploy]

print("✓ Semaphore Security Architecture diagram generated: ../figures/svg/semaphore_security_architecture.png")
