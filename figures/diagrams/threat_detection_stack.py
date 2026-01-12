#!/usr/bin/env python3
"""
Threat Detection Stack - Falco + SIEM Integration
Prikazuje arhitekturu za detekciju prijetnji i SIEM integraciju
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.k8s.compute import Pod, DaemonSet
from diagrams.k8s.controlplane import APIServer
from diagrams.onprem.monitoring import Prometheus
from diagrams.onprem.logging import FluentBit, Loki
from diagrams.elastic.elasticsearch import Elasticsearch, Kibana
from diagrams.onprem.client import Users
from diagrams.saas.chat import Slack
from diagrams.custom import Custom
import os

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
    "Threat Detection Stack - Falco + SIEM",
    filename="../figures/svg/threat_detection_stack",
    outformat="png",
    show=False,
    direction="TB",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    security_team = Users("Security\nTeam")

    with Cluster("Kubernetes Cluster"):
        with Cluster("Semaphore Application"):
            guard_pod = Pod("Guard\nAuth Service")
            front_pod = Pod("Front\nWeb UI")
            hooks_pod = Pod("Hooks\nProcessor")

        api_server = APIServer("API Server\nAudit Logs")

        with Cluster("Security Monitoring"):
            falco = DaemonSet("Falco\nDaemonSet")
            falco_config = Custom("Falco\nRules", "./icons/config.png") if os.path.exists("./icons/config.png") else Pod("Custom\nRules")

    with Cluster("Log Collection Layer"):
        fluentbit = FluentBit("Fluent Bit\nLog Forwarder")
        prometheus = Prometheus("Prometheus\nMetrics")

    with Cluster("SIEM Platform"):
        with Cluster("Elasticsearch Stack"):
            elasticsearch = Elasticsearch("Elasticsearch\nLog Storage")
            kibana = Kibana("Kibana\nSIEM UI")

        with Cluster("Loki (Alternative)"):
            loki = Loki("Loki\nLog Storage")

    with Cluster("Alerting & Response"):
        alert_manager = Custom("AlertManager", "./icons/alert.png") if os.path.exists("./icons/alert.png") else Prometheus("Alert\nManager")
        slack = Slack("Slack\nNotifications")
        pagerduty = Custom("PagerDuty", "./icons/pagerduty.png") if os.path.exists("./icons/pagerduty.png") else Slack("On-Call\nAlerts")

    with Cluster("Event Correlation"):
        correlation_engine = Custom("Correlation\nRules", "./icons/correlation.png") if os.path.exists("./icons/correlation.png") else Elasticsearch("Event\nCorrelation")
        playbooks = Custom("Incident\nPlaybooks", "./icons/playbook.png") if os.path.exists("./icons/playbook.png") else Kibana("Response\nPlaybooks")

    # Falco monitoring flows
    guard_pod >> Edge(label="System calls", color="blue", fontcolor="blue", style="dotted") >> falco
    front_pod >> Edge(label="System calls", color="blue", fontcolor="blue", style="dotted") >> falco
    hooks_pod >> Edge(label="System calls", color="blue", fontcolor="blue", style="dotted") >> falco

    falco >> falco_config

    # Detection events
    falco >> Edge(label="Shell detected", color="red", fontcolor="red", style="bold") >> fluentbit
    falco >> Edge(label="Secret access", color="red", fontcolor="red", style="bold") >> fluentbit
    falco >> Edge(label="Suspicious\nnetwork", color="red", fontcolor="red", style="bold") >> fluentbit

    # Audit logs
    api_server >> Edge(label="K8s audit\nlogs", color="orange", fontcolor="orange") >> fluentbit

    # Application logs
    guard_pod >> Edge(label="App logs", color="gray", fontcolor="gray") >> fluentbit
    front_pod >> Edge(label="App logs", color="gray", fontcolor="gray") >> fluentbit
    hooks_pod >> Edge(label="App logs", color="gray", fontcolor="gray") >> fluentbit

    # Metrics
    falco >> Edge(label="Metrics", color="green", fontcolor="green", style="dashed") >> prometheus
    prometheus >> alert_manager

    # SIEM ingestion
    fluentbit >> Edge(label="Structured\nlogs", color="purple", fontcolor="purple") >> elasticsearch
    fluentbit >> Edge(label="Alt: Loki", color="purple", fontcolor="purple", style="dotted") >> loki

    # Correlation and analysis
    elasticsearch >> Edge(label="Index &\nSearch", color="darkblue", fontcolor="darkblue") >> correlation_engine
    correlation_engine >> kibana

    # Alerting workflows
    elasticsearch >> Edge(label="Critical\nAlert", color="red", fontcolor="red", style="bold") >> alert_manager
    alert_manager >> Edge(label="Notify", color="red", fontcolor="red") >> slack
    alert_manager >> Edge(label="Page", color="red", fontcolor="red", style="bold") >> pagerduty

    # Security team interaction
    kibana >> Edge(label="Dashboard", color="green", fontcolor="green") >> security_team
    playbooks >> Edge(label="Response\nGuide", color="blue", fontcolor="blue") >> security_team
    security_team >> Edge(label="Investigate", color="blue", fontcolor="blue", style="dashed") >> kibana

    # Example detection scenarios
    with Cluster("Example Detections", graph_attr={"bgcolor": "lightyellow"}):
        detection1 = Custom("Shell in\nProduction", "./icons/shell.png") if os.path.exists("./icons/shell.png") else Pod("Shell\nDetected")
        detection2 = Custom("Secret\nAccess", "./icons/secret.png") if os.path.exists("./icons/secret.png") else Pod("Secret\nAccess")
        detection3 = Custom("Lateral\nMovement", "./icons/lateral.png") if os.path.exists("./icons/lateral.png") else Pod("Lateral\nMovement")

    falco >> Edge(style="invis") >> detection1
    falco >> Edge(style="invis") >> detection2
    falco >> Edge(style="invis") >> detection3

print("✓ Threat Detection Stack diagram generated: ../figures/svg/threat_detection_stack.png")
