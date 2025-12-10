variable "resource_group_name" {
  type        = string
  description = "Name of the resource group containing the Log Analytics workspace"
}

variable "log_analytics_workspace_name" {
  type        = string
  description = "Name of the Log Analytics workspace with Sentinel enabled"
}

variable "allowed_namespaces" {
  type        = list(string)
  description = "List of Kubernetes namespaces to exclude from detections"
  default = [
    "kube-system",
    "gatekeeper-system",
    "azure-arc",
    "calico-system",
    "tigera-operator"
  ]
}

variable "allowed_service_accounts" {
  type        = list(string)
  description = "List of service accounts to exclude from detections"
  default = [
    "system:kube-controller-manager",
    "system:kube-scheduler",
    "system:serviceaccount:kube-system:replicaset-controller"
  ]
}

variable "trusted_registries" {
  type        = list(string)
  description = "List of trusted container registries"
  default = [
    ".azurecr.io",
    "mcr.microsoft.com",
    "gcr.io/gke-release"
  ]
}

variable "brute_force_threshold" {
  type        = number
  description = "Number of failed authentications to trigger brute force alert"
  default     = 10
}

variable "log_access_threshold" {
  type        = number
  description = "Number of log accesses to trigger exfiltration alert"
  default     = 50
}

variable "data_transfer_threshold_mb" {
  type        = number
  description = "Data transfer threshold in MB to trigger exfiltration alert"
  default     = 500
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to all resources"
  default = {
    ManagedBy = "Terraform"
    Purpose   = "AKS Security Detections"
  }
}
