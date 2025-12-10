output "workspace_id" {
  description = "Log Analytics workspace ID"
  value       = data.azurerm_log_analytics_workspace.sentinel.id
}

output "workspace_name" {
  description = "Log Analytics workspace name"
  value       = data.azurerm_log_analytics_workspace.sentinel.name
}

output "analytics_rules" {
  description = "Details of created analytics rules"
  value = {
    for k, v in azurerm_sentinel_alert_rule_scheduled.aks_detection :
    k => {
      id           = v.id
      name         = v.name
      display_name = v.display_name
      severity     = v.severity
      tactics      = v.tactics
    }
  }
}

output "rule_count" {
  description = "Total number of analytics rules created"
  value       = length(azurerm_sentinel_alert_rule_scheduled.aks_detection)
}
