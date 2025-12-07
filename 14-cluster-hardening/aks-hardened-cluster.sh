#!/bin/bash
# AKS Hardened Cluster Creation Script
# Kreira production-ready AKS cluster sa Azure AD i sigurnosnim kontrolama

set -e

# Konfiguracija
RESOURCE_GROUP="${RESOURCE_GROUP:-semaphore-prod-rg}"
CLUSTER_NAME="${CLUSTER_NAME:-semaphore-hardened}"
LOCATION="${LOCATION:-westeurope}"
VNET_NAME="${VNET_NAME:-semaphore-vnet}"
SUBNET_NAME="${SUBNET_NAME:-aks-subnet}"
K8S_VERSION="${K8S_VERSION:-1.28.3}"

echo "=== Kreiranje AKS Hardened Cluster ==="
echo "Resource Group: $RESOURCE_GROUP"
echo "Cluster: $CLUSTER_NAME"
echo "Location: $LOCATION"
echo "Version: $K8S_VERSION"

# Kreiranje Resource Group
echo "Kreiranje Resource Group..."
az group create --name $RESOURCE_GROUP --location $LOCATION

# Kreiranje VNet i Subnet
echo "Kreiranje VNet..."
az network vnet create \
    --resource-group $RESOURCE_GROUP \
    --name $VNET_NAME \
    --address-prefixes 10.0.0.0/8 \
    --subnet-name $SUBNET_NAME \
    --subnet-prefix 10.240.0.0/16

SUBNET_ID=$(az network vnet subnet show \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name $SUBNET_NAME \
    --query id -o tsv)

# Kreiranje User Assigned Managed Identity
echo "Kreiranje Managed Identity..."
az identity create \
    --name "${CLUSTER_NAME}-identity" \
    --resource-group $RESOURCE_GROUP

IDENTITY_ID=$(az identity show \
    --name "${CLUSTER_NAME}-identity" \
    --resource-group $RESOURCE_GROUP \
    --query id -o tsv)

# Kreiranje AKS klastera
echo "Kreiranje AKS klastera..."
az aks create \
    --resource-group $RESOURCE_GROUP \
    --name $CLUSTER_NAME \
    --location $LOCATION \
    --kubernetes-version $K8S_VERSION \
    \
    # Private Cluster
    --enable-private-cluster \
    --disable-public-fqdn \
    --private-dns-zone system \
    \
    # Azure AD Integration
    --enable-aad \
    --enable-azure-rbac \
    --aad-admin-group-object-ids "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    \
    # Managed Identity
    --enable-managed-identity \
    --assign-identity $IDENTITY_ID \
    \
    # Network Configuration
    --network-plugin azure \
    --network-policy azure \
    --vnet-subnet-id $SUBNET_ID \
    --service-cidr 10.0.0.0/16 \
    --dns-service-ip 10.0.0.10 \
    \
    # Node Configuration
    --node-count 3 \
    --node-vm-size Standard_D4s_v3 \
    --os-sku AzureLinux \
    --enable-cluster-autoscaler \
    --min-count 2 \
    --max-count 10 \
    --zones 1 2 3 \
    \
    # Security Features
    --enable-defender \
    --enable-secret-rotation \
    --rotation-poll-interval 2m \
    --enable-workload-identity \
    --enable-oidc-issuer \
    \
    # Azure Policy
    --enable-addons azure-policy,monitoring \
    \
    # Encryption
    --enable-encryption-at-host \
    \
    # API Server Access
    --api-server-authorized-ip-ranges "10.0.0.0/8" \
    \
    # Upgrade Configuration
    --auto-upgrade-channel stable \
    --node-os-upgrade-channel NodeImage \
    \
    # Tags
    --tags environment=production team=platform

echo "Cluster kreiran uspješno!"

# Omogućavanje Azure Key Vault integration
echo "Konfiguriranje Azure Key Vault..."
az aks enable-addons \
    --resource-group $RESOURCE_GROUP \
    --name $CLUSTER_NAME \
    --addons azure-keyvault-secrets-provider \
    --enable-secret-rotation

# Kreiranje Key Vault
az keyvault create \
    --name "${CLUSTER_NAME}-kv" \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --enable-rbac-authorization

# Konfiguriranje Workload Identity za semaphore
echo "Konfiguriranje Workload Identity..."
AKS_OIDC_ISSUER=$(az aks show \
    --name $CLUSTER_NAME \
    --resource-group $RESOURCE_GROUP \
    --query oidcIssuerProfile.issuerUrl -o tsv)

az identity create \
    --name "semaphore-identity" \
    --resource-group $RESOURCE_GROUP

IDENTITY_CLIENT_ID=$(az identity show \
    --name "semaphore-identity" \
    --resource-group $RESOURCE_GROUP \
    --query clientId -o tsv)

# Federated credential
az identity federated-credential create \
    --name "semaphore-federated" \
    --identity-name "semaphore-identity" \
    --resource-group $RESOURCE_GROUP \
    --issuer $AKS_OIDC_ISSUER \
    --subject "system:serviceaccount:semaphore:default"

echo ""
echo "=== AKS Hardened Cluster Setup Complete ==="
echo ""
echo "Sljedeći koraci:"
echo "1. az aks get-credentials --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME"
echo "2. kubectl create namespace semaphore"
echo "3. Annotate service account: azure.workload.identity/client-id=$IDENTITY_CLIENT_ID"
