# AKS Hunting Queries for Microsoft Sentinel

This directory contains proactive hunting queries for investigating AKS security incidents.

## Query Categories

| Query | Description | Tactic |
|-------|-------------|--------|
| `privileged-pods-inventory.kql` | Inventory all privileged pods in the cluster | Discovery |
| `failed-api-requests.kql` | Investigate failed API requests | CredentialAccess |
| `container-image-analysis.kql` | Analyze container images for anomalies | InitialAccess |
| `user-activity-timeline.kql` | Build timeline of user activities | Discovery |
| `network-traffic-analysis.kql` | Analyze network traffic patterns | Exfiltration |
| `rbac-escalation-paths.kql` | Identify RBAC privilege escalation paths | PrivilegeEscalation |

## Usage

1. Open Microsoft Sentinel in the Azure Portal
2. Navigate to **Hunting** > **Queries**
3. Create a new custom query
4. Paste the query content
5. Set appropriate parameters and run

## Best Practices

- Run queries during incident investigation
- Adjust time ranges based on investigation scope
- Correlate findings across multiple queries
- Document findings and update detection rules as needed
