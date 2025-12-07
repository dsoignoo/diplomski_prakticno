#!/bin/bash
# EKS Hardened Cluster Creation Script
# Kreira production-ready EKS cluster sa IRSA i sigurnosnim kontrolama

set -e

# Konfiguracija
CLUSTER_NAME="${CLUSTER_NAME:-semaphore-hardened}"
REGION="${REGION:-eu-central-1}"
VPC_ID="${VPC_ID:-vpc-xxxxxxxx}"
SUBNET_IDS="${SUBNET_IDS:-subnet-xxx,subnet-yyy,subnet-zzz}"
K8S_VERSION="${K8S_VERSION:-1.28}"

echo "=== Kreiranje EKS Hardened Cluster ==="
echo "Cluster: $CLUSTER_NAME"
echo "Region: $REGION"
echo "Version: $K8S_VERSION"

# Kreiranje EKS klastera sa eksctl
cat > /tmp/eks-cluster.yaml << EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: $CLUSTER_NAME
  region: $REGION
  version: "$K8S_VERSION"

# Private cluster
privateCluster:
  enabled: true
  skipEndpointCreation: false

# VPC konfiguracija
vpc:
  id: "$VPC_ID"
  subnets:
    private:
      eu-central-1a:
        id: subnet-xxx
      eu-central-1b:
        id: subnet-yyy
      eu-central-1c:
        id: subnet-zzz
  clusterEndpoints:
    publicAccess: false
    privateAccess: true

# IAM OIDC provider za IRSA
iam:
  withOIDC: true
  serviceAccounts:
    - metadata:
        name: semaphore-sa
        namespace: semaphore
      attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
      wellKnownPolicies:
        awsLoadBalancerController: true
        certManager: true
        externalDNS: true

# Managed Node Groups
managedNodeGroups:
  - name: semaphore-nodes
    instanceType: m5.xlarge
    desiredCapacity: 3
    minSize: 2
    maxSize: 10
    volumeSize: 100
    volumeType: gp3
    volumeEncrypted: true

    # AMI Type
    amiFamily: AmazonLinux2

    # IMDSv2 enforcement (sprječava SSRF napade)
    disableIMDSv1: true

    # SSH pristup onemogućen
    ssh:
      allow: false

    # Security Groups
    securityGroups:
      attachIDs:
        - sg-xxxxxxxxx

    # Labels i Taints
    labels:
      environment: production
      team: platform

    # IAM
    iam:
      withAddonPolicies:
        autoScaler: true
        ebs: true
        efs: true
        albIngress: true
        cloudWatch: true

# Logging
cloudWatch:
  clusterLogging:
    enableTypes:
      - api
      - audit
      - authenticator
      - controllerManager
      - scheduler

# Addons
addons:
  - name: vpc-cni
    version: latest
    attachPolicyARNs:
      - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
  - name: coredns
    version: latest
  - name: kube-proxy
    version: latest
  - name: aws-ebs-csi-driver
    version: latest
    wellKnownPolicies:
      ebsCSIController: true

# Secrets encryption sa KMS
secretsEncryption:
  keyARN: arn:aws:kms:$REGION:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
EOF

echo "Kreiranje EKS klastera..."
eksctl create cluster -f /tmp/eks-cluster.yaml

# Instalacija Calico za Network Policy
echo "Instalacija Calico Network Policy..."
kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/master/calico-operator.yaml
kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/master/calico-crs.yaml

# Konfiguracija IRSA za Semaphore
echo "Konfiguriranje IRSA za Semaphore..."
eksctl create iamserviceaccount \
    --name semaphore-app \
    --namespace semaphore \
    --cluster $CLUSTER_NAME \
    --attach-policy-arn arn:aws:iam::123456789012:policy/SemaphoreAppPolicy \
    --approve \
    --override-existing-serviceaccounts

echo ""
echo "=== EKS Hardened Cluster Setup Complete ==="
echo ""
echo "Sljedeći koraci:"
echo "1. aws eks update-kubeconfig --name $CLUSTER_NAME --region $REGION"
echo "2. kubectl create namespace semaphore"
echo "3. Apply NetworkPolicies"
