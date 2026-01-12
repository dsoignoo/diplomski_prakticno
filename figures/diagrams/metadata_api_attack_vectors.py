#!/usr/bin/env python3
"""
Metadata API Attack Vectors Diagram
Illustrates security risks of cloud metadata API access from compromised pods
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.k8s.compute import Pod
from diagrams.aws.compute import EC2Instance
from diagrams.aws.storage import S3
from diagrams.aws.database import RDS
from diagrams.onprem.client import User
from diagrams.onprem.network import Internet
from diagrams.generic.network import Firewall
from diagrams.onprem.security import Vault
from diagrams.k8s.podconfig import Secret

# Configuration
diagram_attr = {
    "bgcolor": "white",
    "pad": "0.5",
    "nodesep": "1.0",
    "ranksep": "1.5"
}

node_attr = {
    "height": "1.2",
    "width": "1.2"
}

with Diagram(
    "",
    filename="../figures/svg/metadata_api_attack_vectors",
    show=False,
    direction="TB",
    graph_attr=diagram_attr,
    node_attr=node_attr
):

    # Attacker
    attacker = User("Napadač")

    with Cluster("Kubernetes Klaster"):

        with Cluster("Kompromitovani Pod"):
            compromised_pod = Pod("Aplikacijski\nPod")

        with Cluster("Metadata API Endpoint"):
            # Using Vault icon to represent metadata endpoint
            metadata = Vault("Metadata API\n169.254.169.254")

        # Pod accesses metadata
        compromised_pod >> Edge(
            label="HTTP zahtjev\nbez autentifikacije",
            color="red",
            style="bold"
        ) >> metadata

    with Cluster("Rizici i Posljedice"):

        with Cluster("1. Pristup Cloud Kredencijalima"):
            iam_token = Secret("IAM Role\nToken")
            metadata >> Edge(
                label="Vraća privremene\nkredencijale",
                color="orange"
            ) >> iam_token

        with Cluster("2. Lateralno Kretanje"):
            cloud_resources = [
                S3("S3 Bucket"),
                RDS("Baza\nPodataka"),
                EC2Instance("Druge\nInstance")
            ]
            iam_token >> Edge(
                label="Pristup resursima\nizvan klastera",
                color="red",
                style="dashed"
            ) >> cloud_resources

        with Cluster("3. Eskalacija Privilegija"):
            kube_env = Secret("kube-env\npodaci")
            service_token = Secret("Service Account\nToken")

            metadata >> Edge(label="Kubernetes\nkonfiguracija", color="orange") >> kube_env
            metadata >> Edge(label="Automatski\nmontirani token", color="orange") >> service_token

            privileged_pod = Pod("Novi Privilegovani\nPod")
            service_token >> Edge(
                label="Kreira sa višim\nprivilegijama",
                color="red",
                style="dashed"
            ) >> privileged_pod

    with Cluster("Zaštitni Mehanizmi"):
        with Cluster("Preventivne Mjere"):
            workload_id = Firewall("Workload Identity\n(GKE)")
            irsa = Firewall("IRSA\n(EKS)")
            imdsv2 = Firewall("IMDSv2\n(AWS)")
            network_policy = Firewall("Network Policy\nBlokira 169.254.0.0/16")

        # Show that these block the attack
        for protection in [workload_id, irsa, imdsv2, network_policy]:
            protection >> Edge(
                label="blokira",
                color="green",
                style="dotted"
            ) >> metadata

    # Initial compromise
    attacker >> Edge(
        label="kompromituje",
        color="darkred",
        style="bold"
    ) >> compromised_pod