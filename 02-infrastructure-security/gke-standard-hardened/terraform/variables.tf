# Variables for Hardened Standard GKE Cluster

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "cluster_name" {
  description = "Name of the GKE cluster"
  type        = string
  default     = "semaphore-prod-hardened"
}

variable "network_name" {
  description = "Name of the VPC network"
  type        = string
  default     = "semaphore-vpc"
}

# ============================================================================
# PRIVATE CLUSTER CONFIGURATION
# ============================================================================

variable "master_ipv4_cidr_block" {
  description = "CIDR block for GKE master (must be /28)"
  type        = string
  default     = "172.16.0.0/28"
}

variable "bastion_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH to bastion host"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # WARNING: Change this to your IP!
  # Example: ["1.2.3.4/32"]  # Your office IP
}

variable "dev_access_cidrs" {
  description = "CIDR blocks for direct kubectl access during development (optional)"
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = []
  # Example:
  # default = [
  #   {
  #     cidr_block   = "1.2.3.4/32"
  #     display_name = "My office"
  #   }
  # ]
}

# ============================================================================
# NODE POOL CONFIGURATION
# ============================================================================

variable "machine_type" {
  description = "Machine type for GKE nodes"
  type        = string
  default     = "e2-standard-4"  # 4 vCPU, 16 GB RAM
}

variable "node_count" {
  description = "Initial number of nodes per zone"
  type        = number
  default     = 1
}

variable "min_node_count" {
  description = "Minimum number of nodes per zone (autoscaling)"
  type        = number
  default     = 1
}

variable "max_node_count" {
  description = "Maximum number of nodes per zone (autoscaling)"
  type        = number
  default     = 3
}

# ============================================================================
# SECURITY FEATURES
# ============================================================================

variable "enable_binary_auth" {
  description = "Enable Binary Authorization for image signature verification"
  type        = bool
  default     = false  # Enable in Phase 03 after setting up Cosign
}

variable "enable_secrets_encryption" {
  description = "Enable application-layer secrets encryption with KMS"
  type        = bool
  default     = true
}

variable "security_posture_mode" {
  description = "Security posture mode (DISABLED, BASIC, ENTERPRISE)"
  type        = string
  default     = "BASIC"  # Use BASIC for free tier, ENTERPRISE for paid
  validation {
    condition     = contains(["DISABLED", "BASIC", "ENTERPRISE"], var.security_posture_mode)
    error_message = "security_posture_mode must be DISABLED, BASIC, or ENTERPRISE"
  }
}

variable "vulnerability_mode" {
  description = "Vulnerability scanning mode"
  type        = string
  default     = "VULNERABILITY_BASIC"
  validation {
    condition     = contains(["VULNERABILITY_DISABLED", "VULNERABILITY_BASIC", "VULNERABILITY_ENTERPRISE"], var.vulnerability_mode)
    error_message = "vulnerability_mode must be VULNERABILITY_DISABLED, VULNERABILITY_BASIC, or VULNERABILITY_ENTERPRISE"
  }
}

# ============================================================================
# WORKLOAD IDENTITY
# ============================================================================

# (Automatically enabled, no variable needed)

# ============================================================================
# MONITORING & LOGGING
# ============================================================================

# (Automatically enabled with comprehensive logging)

# ============================================================================
# OUTPUTS
# ============================================================================

# (Defined in main.tf)
