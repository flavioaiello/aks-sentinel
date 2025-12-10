terraform {
  required_version = ">= 1.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = ">= 1.0.0"
    }
  }
}

provider "azurerm" {
  features {}
}

provider "azapi" {}

# Data source for existing Log Analytics workspace
data "azurerm_log_analytics_workspace" "sentinel" {
  name                = var.log_analytics_workspace_name
  resource_group_name = var.resource_group_name
}

# Data source for existing Sentinel workspace
data "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = data.azurerm_log_analytics_workspace.sentinel.id
}

# Local variables for analytics rules
locals {
  # Container Runtime Rules
  container_runtime_rules = {
    privileged_container = {
      display_name = "AKS Privileged Container Execution"
      description  = "Detects the creation of privileged containers in AKS clusters, which can be used for container escape attacks."
      severity     = "High"
      tactics      = ["PrivilegeEscalation", "Execution"]
      techniques   = ["T1611"]
      query        = <<-QUERY
        AzureDiagnostics
        | where Category == "kube-audit"
        | where TimeGenerated > ago(5m)
        | extend requestObject = parse_json(tostring(parse_json(log_s).requestObject))
        | extend verb = tostring(parse_json(log_s).verb)
        | extend objectRef = parse_json(tostring(parse_json(log_s).objectRef))
        | extend user = parse_json(tostring(parse_json(log_s).user))
        | where verb in ("create", "update", "patch")
        | where objectRef.resource == "pods"
        | extend containers = requestObject.spec.containers
        | mv-expand container = containers
        | extend securityContext = container.securityContext
        | where securityContext.privileged == true
        | extend
            PodName = tostring(objectRef.name),
            Namespace = tostring(objectRef.namespace),
            ContainerName = tostring(container.name),
            ContainerImage = tostring(container.image),
            Username = tostring(user.username),
            ClusterName = Resource
        | where Namespace !in ("kube-system", "gatekeeper-system", "azure-arc")
        | project TimeGenerated, ClusterName, Namespace, PodName, ContainerName, ContainerImage, Username
        | summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Count = count()
            by ClusterName, Namespace, PodName, ContainerName, ContainerImage, Username
      QUERY
    }

    hostpath_mount = {
      display_name = "AKS Container with Sensitive Host Path Mount"
      description  = "Detects when a container mounts sensitive host filesystem paths which can be used for container escape."
      severity     = "High"
      tactics      = ["PrivilegeEscalation", "Persistence"]
      techniques   = ["T1611", "T1078"]
      query        = <<-QUERY
        let SensitivePaths = dynamic(["/", "/etc", "/var/run/docker.sock", "/var/run/crio/crio.sock", "/var/lib/kubelet", "/proc", "/sys"]);
        AzureDiagnostics
        | where Category == "kube-audit"
        | where TimeGenerated > ago(5m)
        | extend log = parse_json(log_s)
        | extend verb = tostring(log.verb)
        | extend objectRef = log.objectRef
        | extend requestObject = log.requestObject
        | extend user = log.user
        | where verb in ("create", "update", "patch")
        | where objectRef.resource == "pods"
        | extend volumes = requestObject.spec.volumes
        | mv-expand volume = volumes
        | extend hostPath = tostring(volume.hostPath.path)
        | where isnotempty(hostPath)
        | where hostPath in (SensitivePaths) or hostPath startswith "/etc" or hostPath startswith "/var/run"
        | extend
            PodName = tostring(objectRef.name),
            Namespace = tostring(objectRef.namespace),
            VolumeName = tostring(volume.name),
            HostPath = hostPath,
            Username = tostring(user.username),
            ClusterName = Resource
        | where Namespace !in ("kube-system", "gatekeeper-system", "azure-arc", "calico-system")
        | project TimeGenerated, ClusterName, Namespace, PodName, VolumeName, HostPath, Username
        | summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Count = count()
            by ClusterName, Namespace, PodName, VolumeName, HostPath, Username
      QUERY
    }

    host_network = {
      display_name = "AKS Pod with Host Network Access"
      description  = "Detects when a pod is created with hostNetwork: true, allowing direct access to the node's network namespace."
      severity     = "High"
      tactics      = ["PrivilegeEscalation", "LateralMovement"]
      techniques   = ["T1611"]
      query        = <<-QUERY
        AzureDiagnostics
        | where Category == "kube-audit"
        | where TimeGenerated > ago(5m)
        | extend log = parse_json(log_s)
        | extend verb = tostring(log.verb)
        | extend objectRef = log.objectRef
        | extend requestObject = log.requestObject
        | extend user = log.user
        | where verb in ("create", "update", "patch")
        | where objectRef.resource == "pods"
        | extend
            HostNetwork = tobool(requestObject.spec.hostNetwork),
            HostPID = tobool(requestObject.spec.hostPID),
            HostIPC = tobool(requestObject.spec.hostIPC)
        | where HostNetwork == true or HostPID == true or HostIPC == true
        | extend
            PodName = tostring(objectRef.name),
            Namespace = tostring(objectRef.namespace),
            Username = tostring(user.username),
            ClusterName = Resource
        | where Namespace !in ("kube-system", "gatekeeper-system", "azure-arc", "calico-system", "tigera-operator")
        | project TimeGenerated, ClusterName, Namespace, PodName, HostNetwork, HostPID, HostIPC, Username
        | summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Count = count()
            by ClusterName, Namespace, PodName, HostNetwork, HostPID, HostIPC, Username
      QUERY
    }
  }

  # Kubernetes API Rules
  kubernetes_api_rules = {
    secrets_access = {
      display_name = "AKS Kubernetes Secrets Access"
      description  = "Detects when Kubernetes secrets are accessed by non-system users."
      severity     = "High"
      tactics      = ["CredentialAccess"]
      techniques   = ["T1552.007"]
      query        = <<-QUERY
        let AllowedSecretAccessors = dynamic(["system:kube-controller-manager", "system:kube-scheduler"]);
        AzureDiagnostics
        | where Category == "kube-audit"
        | where TimeGenerated > ago(5m)
        | extend log = parse_json(log_s)
        | extend verb = tostring(log.verb)
        | extend objectRef = log.objectRef
        | extend user = log.user
        | extend sourceIPs = log.sourceIPs
        | extend responseStatus = log.responseStatus
        | where objectRef.resource == "secrets"
        | where verb in ("get", "list", "watch")
        | where responseStatus.code == 200 or responseStatus.code == 201
        | extend
            SecretName = tostring(objectRef.name),
            Namespace = tostring(objectRef.namespace),
            Username = tostring(user.username),
            SourceIP = tostring(sourceIPs[0]),
            ClusterName = Resource
        | where not(Username has_any (AllowedSecretAccessors))
        | where not(Username startswith "system:serviceaccount:kube-system:")
        | project TimeGenerated, ClusterName, Namespace, SecretName, Username, SourceIP
        | summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), AccessCount = count(),
            SecretsAccessed = make_set(SecretName, 20) by ClusterName, Username, SourceIP
      QUERY
    }

    anonymous_access = {
      display_name = "AKS Anonymous API Access Detected"
      description  = "Detects when the Kubernetes API is accessed using anonymous authentication."
      severity     = "Critical"
      tactics      = ["InitialAccess", "Discovery"]
      techniques   = ["T1190", "T1613"]
      query        = <<-QUERY
        AzureDiagnostics
        | where Category == "kube-audit"
        | where TimeGenerated > ago(5m)
        | extend log = parse_json(log_s)
        | extend user = log.user
        | extend sourceIPs = log.sourceIPs
        | extend responseStatus = log.responseStatus
        | extend objectRef = log.objectRef
        | where user.username == "system:anonymous"
        | where responseStatus.code in (200, 201, 202, 204)
        | extend
            Resource_Type = tostring(objectRef.resource),
            SourceIP = tostring(sourceIPs[0]),
            ClusterName = Resource
        | project TimeGenerated, ClusterName, Resource_Type, SourceIP
        | summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), RequestCount = count(),
            Resources = make_set(Resource_Type, 20) by ClusterName, SourceIP
      QUERY
    }

    exec_into_pod = {
      display_name = "AKS Kubectl Exec into Pod"
      description  = "Detects when kubectl exec is used to execute commands in a running container."
      severity     = "Medium"
      tactics      = ["Execution"]
      techniques   = ["T1609"]
      query        = <<-QUERY
        AzureDiagnostics
        | where Category == "kube-audit"
        | where TimeGenerated > ago(5m)
        | extend log = parse_json(log_s)
        | extend verb = tostring(log.verb)
        | extend objectRef = log.objectRef
        | extend user = log.user
        | extend sourceIPs = log.sourceIPs
        | where objectRef.resource == "pods" and objectRef.subresource == "exec"
        | where verb == "create"
        | extend
            PodName = tostring(objectRef.name),
            Namespace = tostring(objectRef.namespace),
            Username = tostring(user.username),
            SourceIP = tostring(sourceIPs[0]),
            ClusterName = Resource
        | where not(Username startswith "system:")
        | where Namespace !in ("kube-system", "gatekeeper-system", "azure-arc")
        | project TimeGenerated, ClusterName, Namespace, PodName, Username, SourceIP
        | summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), ExecCount = count(),
            PodsTargeted = make_set(PodName, 20) by ClusterName, Username, SourceIP
      QUERY
    }

    cluster_role_creation = {
      display_name = "AKS ClusterRole or ClusterRoleBinding Created"
      description  = "Detects when cluster-wide RBAC roles or bindings are created."
      severity     = "High"
      tactics      = ["PrivilegeEscalation", "Persistence"]
      techniques   = ["T1078", "T1098"]
      query        = <<-QUERY
        AzureDiagnostics
        | where Category == "kube-audit"
        | where TimeGenerated > ago(5m)
        | extend log = parse_json(log_s)
        | extend verb = tostring(log.verb)
        | extend objectRef = log.objectRef
        | extend requestObject = log.requestObject
        | extend user = log.user
        | extend responseStatus = log.responseStatus
        | where objectRef.resource in ("clusterroles", "clusterrolebindings")
        | where verb == "create"
        | where responseStatus.code in (200, 201)
        | extend
            ResourceName = tostring(objectRef.name),
            ResourceType = tostring(objectRef.resource),
            Username = tostring(user.username),
            ClusterName = Resource
        | extend Rules = tostring(requestObject.rules)
        | where not(Username startswith "system:")
        | project TimeGenerated, ClusterName, ResourceType, ResourceName, Username, Rules
        | summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Count = count()
            by ClusterName, ResourceType, ResourceName, Username, Rules
      QUERY
    }
  }

  # Combine all rules
  all_rules = merge(local.container_runtime_rules, local.kubernetes_api_rules)
}

# Create Analytics Rules
resource "azurerm_sentinel_alert_rule_scheduled" "aks_detection" {
  for_each = local.all_rules

  name                       = "aks-${each.key}"
  log_analytics_workspace_id = data.azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = each.value.display_name
  description                = each.value.description
  severity                   = each.value.severity
  query                      = each.value.query
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  tactics                    = each.value.tactics
  techniques                 = each.value.techniques

  incident_configuration {
    create_incident = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = ["Host", "Account"]
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}

# Output the created rules
output "created_rules" {
  description = "List of created analytics rules"
  value = {
    for k, v in azurerm_sentinel_alert_rule_scheduled.aks_detection :
    k => {
      name         = v.name
      display_name = v.display_name
      severity     = v.severity
    }
  }
}
