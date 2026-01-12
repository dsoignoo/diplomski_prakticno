#!/usr/bin/env python3
"""
Observability Architecture Diagram za Semaphore
Prikazuje Three Pillars (Metrics, Logs, Traces) + SIEM integration
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.k8s.compute import Pod, DaemonSet
from diagrams.k8s.ecosystem import Helm
from diagrams.onprem.monitoring import Prometheus, Grafana
from diagrams.elastic.elasticsearch import Elasticsearch, Kibana, Logstash
from diagrams.programming.framework import React
from diagrams.custom import Custom

# Grafički attributi
graph_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "0.6",
    "ranksep": "1.2",
    "splines": "polyline"
}

node_attr = {
    "fontsize": "12",
    "fontname": "Sans-Serif"
}

edge_attr = {
    "fontsize": "11",
}

with Diagram("Observability Architecture - Semaphore Platform",
             filename="../figures/svg/observability_architecture",
             direction="TB",
             graph_attr=graph_attr,
             node_attr=node_attr,
             edge_attr=edge_attr,
             show=False):

    # Semaphore aplikacija
    with Cluster("Semaphore Namespace"):
        with Cluster("Mikroservisi"):
            guard = Pod("Guard")
            front = Pod("Front")
            artifacthub = Pod("ArtifactHub")

        with Cluster("Data Layer"):
            postgres = Pod("PostgreSQL")
            redis = Pod("Redis")
            rabbitmq = Pod("RabbitMQ")

    # === PILLAR 1: METRICS ===
    with Cluster("📊 Pillar 1: Metrics (Prometheus + Grafana)"):
        prometheus = Prometheus("Prometheus")
        prom_operator = Helm("Prometheus\nOperator")

        with Cluster("ServiceMonitors"):
            sm_services = Pod("Semaphore\nServices")
            sm_infra = Pod("Infrastructure\nMetrics")

        grafana_metrics = Grafana("Grafana\nDashboards")

        # Metrics flow
        prom_operator >> Edge(label="manages", style="dotted") >> prometheus
        prometheus << Edge(label="scrape /metrics", color="blue", fontcolor="blue") << sm_services
        prometheus << Edge(label="scrape", color="blue", fontcolor="blue") << sm_infra
        sm_services >> Edge(style="dotted") >> [guard, front, artifacthub]
        sm_infra >> Edge(style="dotted") >> [postgres, redis, rabbitmq]
        prometheus >> Edge(label="query", color="green", fontcolor="green") >> grafana_metrics

    # === PILLAR 2: LOGS ===
    with Cluster("📝 Pillar 2: Logs (Loki + Promtail)"):
        loki = Custom("Loki", "./icons/loki.png") if False else Pod("Loki")
        promtail = DaemonSet("Promtail\nDaemonSet")
        grafana_logs = Grafana("Grafana\nLog Viewer")

        # Logs flow
        [guard, front, artifacthub, postgres, redis, rabbitmq] >> Edge(
            label="stdout/stderr", color="orange", fontcolor="orange", style="dashed"
        ) >> promtail
        promtail >> Edge(label="ship logs", color="orange", fontcolor="orange") >> loki
        loki >> Edge(label="query LogQL", color="green", fontcolor="green") >> grafana_logs

    # === PILLAR 3: TRACES ===
    with Cluster("🔍 Pillar 3: Traces (Jaeger + OpenTelemetry)"):
        jaeger = Custom("Jaeger", "./icons/jaeger.png") if False else Pod("Jaeger\nAll-in-One")
        otel_collector = Pod("OpenTelemetry\nCollector")
        grafana_traces = Grafana("Grafana\nTrace Viewer")

        # Traces flow
        [guard, front, artifacthub] >> Edge(
            label="OTLP traces", color="purple", fontcolor="purple", style="bold"
        ) >> otel_collector
        otel_collector >> Edge(label="export", color="purple", fontcolor="purple") >> jaeger
        jaeger >> Edge(label="query traces", color="green", fontcolor="green") >> grafana_traces

    # === SIEM INTEGRATION ===
    with Cluster("🛡️ SIEM (Security Information & Event Management)"):
        elasticsearch = Elasticsearch("Elasticsearch\nCluster")
        kibana_siem = Kibana("Kibana\nSIEM")
        filebeat = DaemonSet("Filebeat\nDaemonSet")

        # Falco security events
        falco = DaemonSet("Falco\nRuntime\nSecurity")

        # SIEM flow
        [guard, front, artifacthub, postgres, redis, rabbitmq] >> Edge(
            label="app logs", color="brown", fontcolor="brown", style="dotted"
        ) >> filebeat

        falco >> Edge(label="security events", color="red", fontcolor="red", style="bold") >> filebeat
        filebeat >> Edge(label="ship to ES", color="brown", fontcolor="brown") >> elasticsearch
        elasticsearch >> Edge(label="visualize + detect", color="green", fontcolor="green") >> kibana_siem

    # === CENTRALNI DASHBOARD ===
    with Cluster("🎯 Unified Observability"):
        grafana_unified = Grafana("Grafana\nUnified\nDashboard")

        grafana_metrics >> Edge(style="dashed") >> grafana_unified
        grafana_logs >> Edge(style="dashed") >> grafana_unified
        grafana_traces >> Edge(style="dashed") >> grafana_unified

    # === ALERTING ===
    with Cluster("🚨 Alerting & Incident Response"):
        alertmanager = Pod("Alertmanager")
        slack = Custom("Slack", "./icons/slack.png") if False else Pod("Slack")
        pagerduty = Pod("PagerDuty")

        prometheus >> Edge(label="fire alerts", color="red", fontcolor="red") >> alertmanager
        loki >> Edge(label="log alerts", color="red", fontcolor="red", style="dashed") >> alertmanager
        kibana_siem >> Edge(label="SIEM alerts", color="red", fontcolor="red", style="bold") >> alertmanager

        alertmanager >> Edge(label="notify", color="red", fontcolor="red") >> [slack, pagerduty]

    # === METRICS LABELS ===
    with Cluster("📈 Key Metrics Achieved"):
        metrics_box = Pod("MTTD: -98%\nMTTR: -87%\nVisibility: +217%")

print("✅ Observability architecture dijagram kreiran: figures/svg/observability_architecture.png")
