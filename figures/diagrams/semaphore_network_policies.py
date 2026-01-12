#!/usr/bin/env python3
"""
Semaphore Network Policies Flow
Prikazuje allowed i blocked traffic nakon implementacije NetworkPolicies
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.k8s.compute import Pod
from diagrams.k8s.network import NetworkPolicy, Service
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.queue import RabbitMQ

graph_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "1.0",
    "ranksep": "1.2",
}

node_attr = {
    "fontsize": "20",
    "height": "1.0",
    "width": "1.0",
    "pad": "1.2",
    "margin": "2",
}

edge_attr = {
    "fontsize": "11",
}

with Diagram(
    "",
    filename="figures/svg/semaphore_network_policies",
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    with Cluster("Semaphore Namespace", graph_attr={"fontsize": "20"}):
        default_deny = NetworkPolicy("Default-Deny\nAll Traffic")

        with Cluster("Frontend Services"):
            front_pod = Pod("Front\nWeb UI")
            front_policy = NetworkPolicy("Front\nPolicy")

        with Cluster("Authentication"):
            guard_pod = Pod("Guard\nAuth Service")
            guard_policy = NetworkPolicy("Guard\nPolicy")


        with Cluster("RBAC"):
            rbac_pod = Pod("RBAC\nPermissions")
            rbac_policy = NetworkPolicy("RBAC\nPolicy")

        with Cluster("Random Pod (No Policy)"):
            random_pod = Pod("Attacker\nPod")

    with Cluster("Data Layer"):
        postgres = PostgreSQL("Database")
        pg_policy = NetworkPolicy("DB\nPolicy")

        redis = Redis("Cache")
        redis_policy = NetworkPolicy("Redis\nPolicy")

        rabbitmq = RabbitMQ("Queue")
        rmq_policy = NetworkPolicy("RabbitMQ\nPolicy")

    with Cluster("DNS (kube-system)"):
        dns = Service("kube-dns\nService")

    # ALLOWED traffic (green, solid)
    front_pod >> Edge(xlabel="✓ HTTP", color="green", fontcolor="green", style="bold") >> front_policy
    front_policy >> Edge(label="✓ Allowed", color="green", fontcolor="green", style="bold") >> guard_pod

    guard_pod >> Edge(xlabel="✓ gRPC", color="green", fontcolor="green", style="bold") >> guard_policy
    guard_policy >> Edge(xlabel="✓ Allowed", color="green", fontcolor="green", style="bold") >> rbac_pod

    guard_pod >> Edge(xlabel="✓ SQL", color="green", fontcolor="green", style="bold") >> guard_policy
    guard_policy >> Edge(xlabel="✓ Port 5432", color="green", fontcolor="green", style="bold") >> pg_policy >> postgres


    guard_pod >> Edge(xlabel="✓ Redis", color="green", fontcolor="green", style="bold") >> redis_policy >> redis

    # DNS allowed for all (required)
    front_pod >> Edge(xlabel="✓ DNS", color="green", fontcolor="green", style="dotted") >> dns
    guard_pod >> Edge(xlabel="✓ DNS", color="green", fontcolor="green", style="dotted") >> dns

    # BLOCKED traffic (red, dashed) - Default-Deny in action
    random_pod >> Edge(xlabel="✗ BLOCKED", color="red", fontcolor="red", style="dashed") >> default_deny
    default_deny >> Edge(xlabel="✗ Denied", color="red", fontcolor="red", style="dashed") >> postgres
    default_deny >> Edge(xlabel="✗ Denied", color="red", fontcolor="red", style="dashed") >> redis
    default_deny >> Edge(xlabel="✗ Denied", color="red", fontcolor="red", style="dashed") >> rmq_policy >> rabbitmq

    # Lateral movement attempt (blocked)
    random_pod >> Edge(xlabel="✗ Lateral\nMovement", color="red", fontcolor="red", style="dashed") >> guard_pod


print("✓ Semaphore Network Policies diagram generated: ../figures/svg/semaphore_network_policies.png")
