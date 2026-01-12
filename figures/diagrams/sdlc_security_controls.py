#!/usr/bin/env python3
"""
SDLC Security Controls Diagram
Prikazuje sigurnosne kontrole u svakoj fazi Software Development Life Cycle-a
"""

from diagrams import Diagram, Cluster, Edge, Node
from diagrams.onprem.security import Trivy
from diagrams.onprem.monitoring import Grafana
from diagrams.k8s.controlplane import API
from diagrams.programming.language import Python
from diagrams.onprem.vcs import Git
from diagrams.onprem.container import Docker
from diagrams.k8s.compute import Pod
from diagrams.k8s.network import NetworkPolicy
import os

# Output path
output_dir = os.path.dirname(os.path.abspath(__file__))
output_path = os.path.join(output_dir, "..", "figures", "svg", "sdlc_security_controls")

graph_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "pad": "0.5",
    "splines": "polyline",
    "nodesep": "0.6",
    "ranksep": "0.8",
    "overlap": "false",
    "sep": "0.1",
}

node_attr = {
    "fontsize": "12",
}

edge_attr = {
    "fontsize": "11",
}

with Diagram(
    "",  # Prazan naslov - caption je u LaTeX-u
    filename=output_path,
    show=False,
    direction="LR",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    # === FAZA 1: PLAN/DESIGN ===
    with Cluster("1. Planiranje\n• Modeliranje prijetnji\n• Sigurnosni zahtjevi"):
        plan = NetworkPolicy("STRIDE\nMITRE ATT&CK")

    # === FAZA 2: CODE ===
    with Cluster("2. Razvoj koda\n• SAST analiza\n• Detekcija pristupnih podataka\n• Pre-commit hooks"):
        code = Git("Izvorni\nkod")

    # === FAZA 3: BUILD ===
    with Cluster("3. Izgradnja\n• Trivy skeniranje\n• SBOM generiranje\n• Potpisivanje slika"):
        build = Docker("Kontejner\nslika")

    # === FAZA 4: TEST ===
    with Cluster("4. Testiranje\n• DAST analiza\n• Sigurnosni testovi\n• Provjera usklađenosti"):
        test = Trivy("Sigurnosno\nskeniranje")

    # === FAZA 5: RELEASE ===
    with Cluster("5. Izdavanje\n• OPA/Kyverno politike\n• Verifikacija slika\n• Odobrenja") as release_cluster:
        release = API("Admission\nkontroler")

    # === FAZA 6: DEPLOY ===
    with Cluster("6. Postavljanje\n• Pod Security Standards\n• NetworkPolicy\n• RBAC") as deploy_cluster:
        deploy = Pod("Produkcijski\nworkload")

    # === FAZA 7: OPERATE/MONITOR ===
    with Cluster("7. Monitoring\n• Falco runtime zaštita\n• SIEM integracija\n• Odgovor na incidente"):
        operate = Grafana("Observability")

    # Flow connections
    plan >> Edge(color="darkgreen", style="bold") >> code
    code >> Edge(color="darkgreen", style="bold") >> build
    build >> Edge(color="darkgreen", style="bold") >> test
    test >> Edge(color="darkgreen", style="bold") >> release
    release >> Edge(color="darkgreen", style="bold") >> deploy
    deploy >> Edge(color="darkgreen", style="bold") >> operate

    # Feedback loop
    operate >> Edge(label="Kontinuirano\npoboljšanje", color="blue", fontcolor="blue", style="dashed") >> plan
