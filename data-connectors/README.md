# AKS Data Connector Configuration

This document describes how to configure the required data connectors for AKS security monitoring in Microsoft Sentinel.

## Required Data Sources

### 1. Azure Kubernetes Service (AKS) Diagnostics

Configure diagnostic settings on your AKS clusters to send logs to Log Analytics.

#### Required Log Categories

| Category | Description | Required |
|----------|-------------|----------|
| `kube-audit` | Kubernetes API audit logs | **Yes** |
| `kube-audit-admin` | Admin-level audit logs | **Yes** |
| `kube-apiserver` | API server logs | Yes |
| `kube-controller-manager` | Controller manager logs | Yes |
| `kube-scheduler` | Scheduler logs | Optional |
| `cluster-autoscaler` | Autoscaler logs | Optional |
| `guard` | Azure AD Pod Identity logs | Optional |

#### Configuration via Azure CLI

```bash
# Get your AKS cluster resource ID
AKS_RESOURCE_ID=$(az aks show \
    --name <aks-cluster-name> \
    --resource-group <resource-group> \
    --query id -o tsv)

# Get your Log Analytics workspace resource ID
WORKSPACE_ID=$(az monitor log-analytics workspace show \
    --resource-group <resource-group> \
    --workspace-name <workspace-name> \
    --query id -o tsv)

# Create diagnostic setting
az monitor diagnostic-settings create \
    --name "sentinel-aks" \
    --resource "$AKS_RESOURCE_ID" \
    --workspace "$WORKSPACE_ID" \
    --logs '[
        {"category": "kube-apiserver", "enabled": true},
        {"category": "kube-audit", "enabled": true},
        {"category": "kube-audit-admin", "enabled": true},
        {"category": "kube-controller-manager", "enabled": true},
        {"category": "kube-scheduler", "enabled": true},
        {"category": "cluster-autoscaler", "enabled": true},
        {"category": "guard", "enabled": true}
    ]' \
    --metrics '[{"category": "AllMetrics", "enabled": true}]'
```

#### Configuration via Terraform

```hcl
resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                       = "sentinel-aks"
  target_resource_id         = azurerm_kubernetes_cluster.aks.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel.id

  enabled_log {
    category = "kube-apiserver"
  }

  enabled_log {
    category = "kube-audit"
  }

  enabled_log {
    category = "kube-audit-admin"
  }

  enabled_log {
    category = "kube-controller-manager"
  }

  enabled_log {
    category = "kube-scheduler"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
```

### 2. Container Insights

Enable Container Insights for additional container-level visibility.

#### Enable via Azure CLI

```bash
az aks enable-addons \
    --resource-group <resource-group> \
    --name <aks-cluster-name> \
    --addons monitoring \
    --workspace-resource-id "$WORKSPACE_ID"
```

#### Required Tables

After enabling Container Insights, verify these tables are populated:

- `ContainerLog` / `ContainerLogV2`
- `KubePodInventory`
- `KubeNodeInventory`
- `ContainerInventory`
- `KubeEvents`
- `Perf`

### 3. Microsoft Defender for Containers (Recommended)

For enhanced threat detection, enable Microsoft Defender for Containers:

```bash
# Enable Defender for Containers on subscription
az security pricing create \
    --name Containers \
    --tier Standard

# Enable Defender profile on AKS cluster
az aks update \
    --resource-group <resource-group> \
    --name <aks-cluster-name> \
    --enable-defender
```

### 4. Network Flow Logs (Optional)

For network-based detections, configure NSG Flow Logs:

```bash
# Enable NSG flow logs
az network watcher flow-log create \
    --resource-group <resource-group> \
    --name <flow-log-name> \
    --nsg <nsg-name> \
    --storage-account <storage-account-id> \
    --workspace "$WORKSPACE_ID" \
    --enabled true \
    --format JSON \
    --log-version 2
```

## Verification

After configuration, run these queries to verify data ingestion:

```kql
// Verify AKS audit logs
AzureDiagnostics
| where Category == "kube-audit"
| take 10

// Verify Container Insights
ContainerLog
| take 10

// Verify Pod Inventory
KubePodInventory
| take 10
```

## Estimated Data Volumes

| Data Source | Estimated Volume |
|-------------|------------------|
| kube-audit | 5-50 GB/day per cluster |
| kube-audit-admin | 1-10 GB/day per cluster |
| Container Insights | 1-20 GB/day per cluster |
| NSG Flow Logs | 2-10 GB/day |

**Note:** Actual volumes depend on cluster size, workload, and API activity.

## Cost Optimization

To reduce costs while maintaining security visibility:

1. **Filter audit logs:** Use Azure Policy to filter unnecessary audit events
2. **Retention policies:** Set appropriate data retention periods
3. **Basic tier:** Consider Log Analytics basic tier for historical data
4. **Sampling:** Enable sampling for high-volume tables

```kql
// Example: Check data ingestion by table
Usage
| where TimeGenerated > ago(30d)
| where DataType has_any ("AzureDiagnostics", "ContainerLog", "KubePod")
| summarize TotalGB = sum(Quantity) / 1024 by DataType, bin(TimeGenerated, 1d)
| render timechart
```
