# Terraform Variables za GKE Autopilot Hardened Cluster

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region za cluster"
  type        = string
  default     = "us-central1"
}

variable "cluster_name" {
  description = "Ime GKE klastera"
  type        = string
  default     = "semaphore-prod"
}

variable "network_name" {
  description = "Ime VPC network-a"
  type        = string
  default     = "semaphore-vpc"
}

variable "workload_identity_pool" {
  description = "Workload Identity pool (project_id.svc.id.goog)"
  type        = string
}

variable "binary_authorization_evaluation_mode" {
  description = "Binary Authorization evaluation mode"
  type        = string
  default     = "PROJECT_SINGLETON_POLICY_ENFORCE"

  validation {
    condition     = contains(["DISABLED", "PROJECT_SINGLETON_POLICY_ENFORCE"], var.binary_authorization_evaluation_mode)
    error_message = "Must be DISABLED or PROJECT_SINGLETON_POLICY_ENFORCE."
  }
}

variable "enable_shielded_nodes" {
  description = "Enable Shielded GKE Nodes"
  type        = bool
  default     = true
}

variable "enable_secure_boot" {
  description = "Enable Secure Boot na nodes"
  type        = bool
  default     = true
}

variable "enable_integrity_monitoring" {
  description = "Enable Integrity Monitoring na nodes"
  type        = bool
  default     = true
}

variable "enable_network_policy" {
  description = "Enable Network Policy (Calico/Dataplane V2)"
  type        = bool
  default     = true
}

variable "enable_private_nodes" {
  description = "Nodes without public IP addresses"
  type        = bool
  default     = true
}

variable "enable_private_endpoint" {
  description = "Private GKE API endpoint (zahtijeva bastion host za kubectl)"
  type        = bool
  default     = false  # Keep false za lakši pristup tokom development-a
}

variable "master_ipv4_cidr_block" {
  description = "CIDR block za GKE control plane"
  type        = string
  default     = "172.16.0.0/28"
}

variable "authorized_networks" {
  description = "CIDR blokovi koji mogu pristupiti GKE API serveru"
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = null  # null = allow from anywhere (mijenjati za produkciju)

  # Za produkciju, postaviti na:
  # default = [
  #   {
  #     cidr_block   = "YOUR_OFFICE_IP/32"
  #     display_name = "Office"
  #   }
  # ]
}

variable "security_posture_mode" {
  description = "Security Posture mode (DISABLED, BASIC, ENTERPRISE)"
  type        = string
  default     = "ENTERPRISE"
}

variable "vulnerability_mode" {
  description = "Vulnerability scanning mode"
  type        = string
  default     = "VULNERABILITY_ENTERPRISE"
}

variable "kms_key_name" {
  description = "KMS key za secrets enkripciju (optional, GKE default ako prazno)"
  type        = string
  default     = ""
}

variable "enable_backup" {
  description = "Enable GKE Backup za cluster"
  type        = bool
  default     = true
}

variable "backup_schedule" {
  description = "Cron schedule za backupe (default: daily at 2 AM)"
  type        = string
  default     = "0 2 * * *"
}

variable "backup_retention_days" {
  description = "Broj dana za čuvanje backup-a"
  type        = number
  default     = 30
}

variable "backup_kms_key_name" {
  description = "KMS key za backup enkripciju (optional)"
  type        = string
  default     = ""
}

variable "enable_notifications" {
  description = "Enable cluster notifications via Pub/Sub"
  type        = bool
  default     = false
}

variable "enable_cloud_logging" {
  description = "Enable Cloud Logging"
  type        = bool
  default     = true
}

variable "enable_cloud_monitoring" {
  description = "Enable Cloud Monitoring"
  type        = bool
  default     = true
}
