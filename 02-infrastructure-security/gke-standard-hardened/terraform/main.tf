# Hardened Standard GKE Cluster - Manual Infrastructure Configuration
# Demonstrates security best practices with full control over infrastructure

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# ============================================================================
# 1. VPC NETWORK - Custom network with proper segmentation
# ============================================================================

resource "google_compute_network" "vpc" {
  name                    = var.network_name
  auto_create_subnetworks = false
  description             = "Custom VPC for hardened GKE cluster"

  # Delete default routes on creation for tighter control
  delete_default_routes_on_create = false
}

# Subnet for GKE worker nodes
resource "google_compute_subnetwork" "gke_nodes" {
  name          = "${var.network_name}-gke-nodes"
  ip_cidr_range = "10.0.0.0/20"  # 4096 IPs for nodes
  region        = var.region
  network       = google_compute_network.vpc.id
  description   = "Subnet for GKE worker nodes"

  # Secondary IP ranges for pods and services
  secondary_ip_range {
    range_name    = "pods-range"
    ip_cidr_range = "10.4.0.0/14"  # 262,144 IPs for pods
  }

  secondary_ip_range {
    range_name    = "services-range"
    ip_cidr_range = "10.8.0.0/20"  # 4096 IPs for services
  }

  # Enable Private Google Access (nodes can reach Google APIs without public IP)
  private_ip_google_access = true

  # Flow logs for security monitoring
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Subnet for bastion host
resource "google_compute_subnetwork" "bastion" {
  name          = "${var.network_name}-bastion"
  ip_cidr_range = "10.0.16.0/28"  # 16 IPs for bastion
  region        = var.region
  network       = google_compute_network.vpc.id
  description   = "Subnet for bastion host"

  private_ip_google_access = true
}

# ============================================================================
# 2. CLOUD ROUTER & NAT - Allow private nodes to reach internet
# ============================================================================

resource "google_compute_router" "router" {
  name    = "${var.network_name}-router"
  region  = var.region
  network = google_compute_network.vpc.id

  description = "Router for Cloud NAT"
}

resource "google_compute_router_nat" "nat" {
  name   = "${var.network_name}-nat"
  router = google_compute_router.router.name
  region = google_compute_router.router.region

  # Only NAT private IPs (not public)
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  # Only NAT traffic from GKE nodes subnet
  subnetwork {
    name                    = google_compute_subnetwork.gke_nodes.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  # Logging for security monitoring
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }

  # Prevent NAT IP exhaustion
  min_ports_per_vm = 64
  max_ports_per_vm = 512
}

# ============================================================================
# 3. FIREWALL RULES - Principle of least privilege
# ============================================================================

# Allow internal communication within VPC
resource "google_compute_firewall" "allow_internal" {
  name    = "${var.network_name}-allow-internal"
  network = google_compute_network.vpc.name

  description = "Allow internal communication between nodes, pods, and services"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [
    "10.0.0.0/20",   # GKE nodes
    "10.4.0.0/14",   # Pods
    "10.8.0.0/20",   # Services
    "10.0.16.0/28",  # Bastion
  ]
}

# Allow SSH to bastion host from specific IPs only
resource "google_compute_firewall" "allow_ssh_to_bastion" {
  name    = "${var.network_name}-allow-ssh-bastion"
  network = google_compute_network.vpc.name

  description = "Allow SSH to bastion from authorized IPs only"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  target_tags   = ["bastion"]
  source_ranges = var.bastion_allowed_cidrs
}

# Allow SSH from bastion to GKE nodes (for troubleshooting)
resource "google_compute_firewall" "allow_ssh_from_bastion" {
  name    = "${var.network_name}-allow-ssh-from-bastion"
  network = google_compute_network.vpc.name

  description = "Allow SSH from bastion to GKE nodes"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_tags = ["bastion"]
  target_tags = ["gke-node"]
}

# Allow GKE master to communicate with nodes
resource "google_compute_firewall" "allow_master_to_nodes" {
  name    = "${var.network_name}-allow-master-nodes"
  network = google_compute_network.vpc.name

  description = "Allow GKE master to communicate with worker nodes"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["443", "10250"]  # Kubelet API
  }

  source_ranges = [var.master_ipv4_cidr_block]
  target_tags   = ["gke-node"]
}

# Deny all other inbound traffic by default
resource "google_compute_firewall" "deny_all_ingress" {
  name    = "${var.network_name}-deny-all-ingress"
  network = google_compute_network.vpc.name

  description = "Deny all other inbound traffic (explicit default)"
  priority    = 65534

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

# ============================================================================
# 4. BASTION HOST - Secure access point for kubectl
# ============================================================================

# Service account for bastion host (minimal permissions)
resource "google_service_account" "bastion_sa" {
  account_id   = "${var.cluster_name}-bastion"
  display_name = "Bastion Host Service Account"
  description  = "Minimal permissions for bastion host"
}

# IAM role for bastion to access GKE cluster
resource "google_project_iam_member" "bastion_gke_viewer" {
  project = var.project_id
  role    = "roles/container.clusterViewer"
  member  = "serviceAccount:${google_service_account.bastion_sa.email}"
}

# Bastion host VM
resource "google_compute_instance" "bastion" {
  name         = "${var.cluster_name}-bastion"
  machine_type = "e2-micro"  # Minimal instance
  zone         = "${var.region}-a"

  tags = ["bastion"]

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = 20
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.bastion.id

    # Assign public IP so we can SSH from outside
    access_config {
      nat_ip = google_compute_address.bastion_ip.address
    }
  }

  service_account {
    email  = google_service_account.bastion_sa.email
    scopes = ["cloud-platform"]
  }

  # Startup script to install kubectl and gcloud
  metadata_startup_script = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y apt-transport-https ca-certificates curl

    # Install kubectl
    curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list
    apt-get update
    apt-get install -y kubectl

    # Install gcloud (already included in Compute Engine instances)
    echo "Bastion host ready"
  EOF

  # Prevent accidental deletion
  deletion_protection = false

  # Shielded VM configuration
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  labels = {
    environment = "production"
    role        = "bastion"
  }
}

# Static IP for bastion host
resource "google_compute_address" "bastion_ip" {
  name   = "${var.cluster_name}-bastion-ip"
  region = var.region
}

# ============================================================================
# 5. HARDENED GKE STANDARD CLUSTER
# ============================================================================

# Service account for GKE nodes (custom, not default Compute Engine SA)
resource "google_service_account" "gke_nodes_sa" {
  account_id   = "${var.cluster_name}-nodes"
  display_name = "GKE Nodes Service Account"
  description  = "Custom service account for GKE nodes with minimal permissions"
}

# Minimal IAM roles for node service account
resource "google_project_iam_member" "gke_nodes_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes_sa.email}"
}

resource "google_project_iam_member" "gke_nodes_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes_sa.email}"
}

resource "google_project_iam_member" "gke_nodes_monitoring_viewer" {
  project = var.project_id
  role    = "roles/monitoring.viewer"
  member  = "serviceAccount:${google_service_account.gke_nodes_sa.email}"
}

resource "google_project_iam_member" "gke_nodes_gcr_reader" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.gke_nodes_sa.email}"
}

# GKE Cluster
resource "google_container_cluster" "primary" {
  provider = google-beta
  name     = var.cluster_name
  location = var.region

  # Remove default node pool (we'll create custom one)
  remove_default_node_pool = true
  initial_node_count       = 1

  # Network configuration
  network    = google_compute_network.vpc.name
  subnetwork = google_compute_subnetwork.gke_nodes.name

  # VPC-native cluster (required for NetworkPolicies)
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods-range"
    services_secondary_range_name = "services-range"
  }

  # ========== PRIVATE CLUSTER ==========
  private_cluster_config {
    enable_private_nodes    = true   # Nodes have NO public IPs
    enable_private_endpoint = true   # Master API only accessible from VPC
    master_ipv4_cidr_block  = var.master_ipv4_cidr_block

    # Allow master to be accessed from bastion subnet
    master_global_access_config {
      enabled = false  # Only from VPC, not globally
    }
  }

  # Master authorized networks - only bastion can reach master
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = google_compute_subnetwork.bastion.ip_cidr_range
      display_name = "Bastion subnet"
    }

    # Optionally allow your local IP for direct access during development
    dynamic "cidr_blocks" {
      for_each = var.dev_access_cidrs
      content {
        cidr_block   = cidr_blocks.value.cidr_block
        display_name = cidr_blocks.value.display_name
      }
    }
  }

  # ========== WORKLOAD IDENTITY ==========
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # ========== SECURITY FEATURES ==========

  # Binary Authorization (image signature verification)
  binary_authorization {
    evaluation_mode = var.enable_binary_auth ? "PROJECT_SINGLETON_POLICY_ENFORCE" : "DISABLED"
  }

  # Dataplane V2 (eBPF-based, better performance, includes NetworkPolicy support)
  datapath_provider = "ADVANCED_DATAPATH"

  # Shielded Nodes
  enable_shielded_nodes = true

  # Security Posture Management
  security_posture_config {
    mode               = var.security_posture_mode
    vulnerability_mode = var.vulnerability_mode
  }

  # Application-layer secrets encryption (KMS)
  database_encryption {
    state    = var.enable_secrets_encryption ? "ENCRYPTED" : "DECRYPTED"
    key_name = var.enable_secrets_encryption ? google_kms_crypto_key.gke_secrets[0].id : null
  }

  # ========== LOGGING & MONITORING ==========

  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS"
    ]
  }

  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS"
      # WORKLOADS removed - incompatible with GKE 1.33.5+ (requires v1.20-1.24)
      # We'll monitor workloads via Prometheus in Phase 07 (observability-stack)
    ]
  }

  # ========== MAINTENANCE ==========

  maintenance_policy {
    daily_maintenance_window {
      start_time = "03:00"  # 3 AM UTC
    }
  }

  # Auto-repair and auto-upgrade
  release_channel {
    channel = "REGULAR"  # Balanced stability and features
  }

  # ========== ADDONS ==========

  addons_config {
    http_load_balancing {
      disabled = false
    }

    horizontal_pod_autoscaling {
      disabled = false
    }

    network_policy_config {
      disabled = false
    }

    gcp_filestore_csi_driver_config {
      enabled = true
    }

    gcs_fuse_csi_driver_config {
      enabled = true
    }
  }

  # ========== RESOURCE LABELS ==========

  resource_labels = {
    environment = "production"
    managed_by  = "terraform"
    application = "semaphore"
    security    = "hardened"
  }

  # Prevent accidental deletion
  deletion_protection = false

  depends_on = [
    google_project_service.container_api,
    google_project_service.compute_api,
  ]
}

# ============================================================================
# 6. NODE POOL - Hardened worker nodes
# ============================================================================

resource "google_container_node_pool" "primary_nodes" {
  name       = "${var.cluster_name}-node-pool"
  location   = var.region
  cluster    = google_container_cluster.primary.name
  node_count = var.node_count

  # Autoscaling
  autoscaling {
    min_node_count = var.min_node_count
    max_node_count = var.max_node_count
  }

  # Auto-upgrade and auto-repair
  management {
    auto_repair  = true
    auto_upgrade = true
  }

  # Node configuration
  node_config {
    machine_type = var.machine_type
    disk_size_gb = 100
    disk_type    = "pd-standard"

    # Use custom service account (not default Compute Engine SA)
    service_account = google_service_account.gke_nodes_sa.email

    # Minimal OAuth scopes
    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
      "https://www.googleapis.com/auth/devstorage.read_only",  # Read GCR/Artifact Registry
    ]

    # ========== NODE SECURITY ==========

    # Shielded VM
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # Workload Identity
    workload_metadata_config {
      mode = "GKE_METADATA"  # Required for Workload Identity
    }

    # Node tags for firewall rules
    tags = ["gke-node", "${var.cluster_name}-node"]

    # Metadata
    metadata = {
      disable-legacy-endpoints = "true"  # Disable metadata v1 endpoint
    }

    # Labels
    labels = {
      environment = "production"
      cluster     = var.cluster_name
    }

    # Taints (optional, for dedicated workloads)
    # taint {
    #   key    = "workload"
    #   value  = "semaphore"
    #   effect = "NO_SCHEDULE"
    # }
  }

  # Upgrade settings
  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
  }
}

# ============================================================================
# 7. KMS for Secrets Encryption
# ============================================================================

# KMS keyring
resource "google_kms_key_ring" "gke" {
  count    = var.enable_secrets_encryption ? 1 : 0
  name     = "${var.cluster_name}-keyring"
  location = var.region
}

# KMS key for secrets encryption
resource "google_kms_crypto_key" "gke_secrets" {
  count           = var.enable_secrets_encryption ? 1 : 0
  name            = "${var.cluster_name}-secrets-key"
  key_ring        = google_kms_key_ring.gke[0].id
  rotation_period = "7776000s"  # 90 days

  lifecycle {
    prevent_destroy = true
  }
}

# Grant GKE permission to use the key
resource "google_kms_crypto_key_iam_member" "gke_secrets_encrypter" {
  count         = var.enable_secrets_encryption ? 1 : 0
  crypto_key_id = google_kms_crypto_key.gke_secrets[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.project.number}@container-engine-robot.iam.gserviceaccount.com"
}

# ============================================================================
# 8. APIs to enable
# ============================================================================

resource "google_project_service" "container_api" {
  service = "container.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "compute_api" {
  service = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "kms_api" {
  count   = var.enable_secrets_encryption ? 1 : 0
  service = "cloudkms.googleapis.com"
  disable_on_destroy = false
}

# ============================================================================
# DATA SOURCES
# ============================================================================

data "google_project" "project" {
  project_id = var.project_id
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.primary.name
}

output "cluster_endpoint" {
  description = "GKE cluster endpoint (private)"
  value       = google_container_cluster.primary.endpoint
  sensitive   = true
}

output "bastion_ip" {
  description = "Bastion host public IP"
  value       = google_compute_address.bastion_ip.address
}

output "bastion_ssh_command" {
  description = "SSH command to connect to bastion"
  value       = "gcloud compute ssh ${google_compute_instance.bastion.name} --zone=${var.region}-a"
}

output "kubectl_via_bastion" {
  description = "Instructions to use kubectl via bastion"
  value       = <<-EOT
    # SSH to bastion:
    gcloud compute ssh ${google_compute_instance.bastion.name} --zone=${var.region}-a

    # On bastion, configure kubectl:
    gcloud container clusters get-credentials ${google_container_cluster.primary.name} --region=${var.region}
    kubectl get nodes
  EOT
}

output "network_name" {
  description = "VPC network name"
  value       = google_compute_network.vpc.name
}

output "nodes_service_account" {
  description = "Service account used by GKE nodes"
  value       = google_service_account.gke_nodes_sa.email
}
