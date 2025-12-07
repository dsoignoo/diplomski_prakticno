# GKE Autopilot Hardened Cluster za Semaphore CI/CD
# Terraform konfiguracija za security-first Kubernetes deployment

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

# VPC Network
resource "google_compute_network" "vpc" {
  name                    = var.network_name
  auto_create_subnetworks = false
  description             = "VPC network za Semaphore Kubernetes cluster"
}

# Subnet za GKE nodes
resource "google_compute_subnetwork" "gke_subnet" {
  name          = "${var.network_name}-gke-subnet"
  ip_cidr_range = "10.0.0.0/20"  # 4096 IPs
  region        = var.region
  network       = google_compute_network.vpc.id
  description   = "Subnet za GKE nodes"

  # Secondary IP ranges za Pods i Services
  secondary_ip_range {
    range_name    = "pods-range"
    ip_cidr_range = "10.4.0.0/14"  # 262,144 IPs za podove
  }

  secondary_ip_range {
    range_name    = "services-range"
    ip_cidr_range = "10.8.0.0/20"  # 4096 IPs za servise
  }

  # Private Google Access omogućava pristup Google API-jima bez public IP
  private_ip_google_access = true
}

# Cloud Router za Cloud NAT
resource "google_compute_router" "router" {
  name    = "${var.network_name}-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

# Cloud NAT za outbound connectivity (nodes nemaju public IP)
resource "google_compute_router_nat" "nat" {
  name                               = "${var.network_name}-nat"
  router                             = google_compute_router.router.name
  region                             = google_compute_router.router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Firewall rules
resource "google_compute_firewall" "allow_internal" {
  name    = "${var.network_name}-allow-internal"
  network = google_compute_network.vpc.name

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
    "10.0.0.0/20",   # GKE subnet
    "10.4.0.0/14",   # Pods range
    "10.8.0.0/20",   # Services range
  ]

  description = "Allow internal communication between nodes, pods, and services"
}

# GKE Autopilot Cluster
resource "google_container_cluster" "primary" {
  provider = google-beta
  name     = var.cluster_name
  location = var.region

  # Autopilot mode
  enable_autopilot = true

  # Network configuration
  network    = google_compute_network.vpc.name
  subnetwork = google_compute_subnetwork.gke_subnet.name

  # IP allocation policy (VPC-native)
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods-range"
    services_secondary_range_name = "services-range"
  }

  # Private cluster configuration
  private_cluster_config {
    enable_private_nodes    = var.enable_private_nodes
    enable_private_endpoint = var.enable_private_endpoint
    master_ipv4_cidr_block  = var.master_ipv4_cidr_block

    master_global_access_config {
      enabled = true  # Allow kubectl access from anywhere
    }
  }

  # Master authorized networks (kubectl pristup samo iz authorized IPs)
  dynamic "master_authorized_networks_config" {
    for_each = var.authorized_networks != null ? [1] : []
    content {
      dynamic "cidr_blocks" {
        for_each = var.authorized_networks
        content {
          cidr_block   = cidr_blocks.value.cidr_block
          display_name = cidr_blocks.value.display_name
        }
      }
    }
  }

  # Workload Identity
  workload_identity_config {
    workload_pool = var.workload_identity_pool
  }

  # Binary Authorization
  binary_authorization {
    evaluation_mode = var.binary_authorization_evaluation_mode
  }

  # Network Policy (Calico)
  network_policy {
    enabled  = var.enable_network_policy
    provider = "PROVIDER_UNSPECIFIED"  # Autopilot uses Dataplane V2
  }

  # Dataplane V2 (eBPF-based networking i Network Policy)
  datapath_provider = "ADVANCED_DATAPATH"

  # Shielded Nodes
  enable_shielded_nodes = var.enable_shielded_nodes

  # Security posture management
  security_posture_config {
    mode               = var.security_posture_mode
    vulnerability_mode = var.vulnerability_mode
  }

  # Secrets encryption
  database_encryption {
    state    = "ENCRYPTED"
    key_name = var.kms_key_name != "" ? var.kms_key_name : null
  }

  # Maintenance window (da se upgradeovi ne dešavaju nasumično)
  maintenance_policy {
    daily_maintenance_window {
      start_time = "03:00"  # 3 AM UTC
    }
  }

  # Monitoring i logging
  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS"
    ]
  }

  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS"
    ]

    managed_prometheus {
      enabled = true
    }
  }

  # Notification config
  notification_config {
    pubsub {
      enabled = var.enable_notifications
      topic   = var.enable_notifications ? google_pubsub_topic.cluster_notifications[0].id : ""
    }
  }

  # Addons
  addons_config {
    http_load_balancing {
      disabled = false
    }

    horizontal_pod_autoscaling {
      disabled = false
    }

    gcp_filestore_csi_driver_config {
      enabled = true
    }

    gcs_fuse_csi_driver_config {
      enabled = true
    }
  }

  # Cluster autoscaling (Autopilot upravlja ovim automatski)
  cluster_autoscaling {
    auto_provisioning_defaults {
      oauth_scopes = [
        "https://www.googleapis.com/auth/cloud-platform"
      ]

      shielded_instance_config {
        enable_secure_boot          = var.enable_secure_boot
        enable_integrity_monitoring = var.enable_integrity_monitoring
      }
    }
  }

  # Labels
  resource_labels = {
    environment = "production"
    managed_by  = "terraform"
    application = "semaphore"
    security    = "hardened"
  }

  # Lifecycle
  lifecycle {
    ignore_changes = [
      node_pool,  # Autopilot manages this
      initial_node_count,
    ]
  }
}

# Pub/Sub topic za cluster notifications
resource "google_pubsub_topic" "cluster_notifications" {
  count = var.enable_notifications ? 1 : 0
  name  = "${var.cluster_name}-notifications"
}

# Service Account za Workload Identity - Guard service
resource "google_service_account" "guard_sa" {
  account_id   = "semaphore-guard"
  display_name = "Semaphore Guard Service Account"
  description  = "Service Account za Guard authentication servis sa Workload Identity"
}

# IAM binding za Secret Manager pristup (Guard servisu treba database password)
resource "google_project_iam_member" "guard_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.guard_sa.email}"
}

# Workload Identity binding za Guard
resource "google_service_account_iam_member" "guard_workload_identity_binding" {
  service_account_id = google_service_account.guard_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[semaphore/guard]"
}

# GKE Backup Plan (ako je enabled)
resource "google_gke_backup_backup_plan" "semaphore_backup" {
  count    = var.enable_backup ? 1 : 0
  name     = "${var.cluster_name}-backup-plan"
  location = var.region
  cluster  = google_container_cluster.primary.id

  retention_policy {
    backup_delete_lock_days = 7
    backup_retain_days      = var.backup_retention_days
    locked                  = false
  }

  backup_schedule {
    cron_schedule = var.backup_schedule
  }

  backup_config {
    include_volume_data = true
    include_secrets     = true

    selected_namespaces {
      namespaces = ["semaphore"]
    }

    encryption_key {
      gcp_kms_encryption_key = var.backup_kms_key_name != "" ? var.backup_kms_key_name : ""
    }
  }

  description = "Daily backup plan for Semaphore namespace"
}

# Outputs
output "cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.primary.name
}

output "cluster_endpoint" {
  description = "GKE cluster endpoint"
  value       = google_container_cluster.primary.endpoint
  sensitive   = true
}

output "cluster_ca_certificate" {
  description = "Cluster CA certificate"
  value       = google_container_cluster.primary.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

output "region" {
  description = "GKE cluster region"
  value       = var.region
}

output "network_name" {
  description = "VPC network name"
  value       = google_compute_network.vpc.name
}

output "subnet_name" {
  description = "GKE subnet name"
  value       = google_compute_subnetwork.gke_subnet.name
}

output "guard_service_account_email" {
  description = "Guard Service Account email for Workload Identity"
  value       = google_service_account.guard_sa.email
}

output "kubectl_connection_command" {
  description = "Command to configure kubectl"
  value       = "gcloud container clusters get-credentials ${google_container_cluster.primary.name} --region=${var.region} --project=${var.project_id}"
}
