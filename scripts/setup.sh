#!/bin/bash
# AKS Security Detections Setup Script
# This script configures AKS diagnostic settings and deploys Sentinel analytics rules

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
RESOURCE_GROUP=""
WORKSPACE_NAME=""
AKS_CLUSTERS=()
SUBSCRIPTION_ID=""

print_usage() {
    echo "Usage: $0 -g <resource-group> -w <workspace-name> [-c <aks-cluster-name>] [-s <subscription-id>]"
    echo ""
    echo "Options:"
    echo "  -g    Resource group name containing the Log Analytics workspace"
    echo "  -w    Log Analytics workspace name with Sentinel enabled"
    echo "  -c    AKS cluster name (can be specified multiple times)"
    echo "  -s    Subscription ID (optional, uses current subscription if not specified)"
    echo ""
    echo "Examples:"
    echo "  $0 -g rg-sentinel -w law-sentinel -c aks-prod -c aks-dev"
    echo "  $0 -g rg-sentinel -w law-sentinel -s 12345678-1234-1234-1234-123456789012"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse arguments
while getopts "g:w:c:s:h" opt; do
    case $opt in
        g) RESOURCE_GROUP="$OPTARG" ;;
        w) WORKSPACE_NAME="$OPTARG" ;;
        c) AKS_CLUSTERS+=("$OPTARG") ;;
        s) SUBSCRIPTION_ID="$OPTARG" ;;
        h) print_usage; exit 0 ;;
        *) print_usage; exit 1 ;;
    esac
done

# Validate required parameters
if [[ -z "$RESOURCE_GROUP" || -z "$WORKSPACE_NAME" ]]; then
    log_error "Resource group and workspace name are required"
    print_usage
    exit 1
fi

# Set subscription if provided
if [[ -n "$SUBSCRIPTION_ID" ]]; then
    log_info "Setting subscription to: $SUBSCRIPTION_ID"
    az account set --subscription "$SUBSCRIPTION_ID"
fi

# Get workspace ID
log_info "Getting Log Analytics workspace ID..."
WORKSPACE_ID=$(az monitor log-analytics workspace show \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --query id -o tsv 2>/dev/null)

if [[ -z "$WORKSPACE_ID" ]]; then
    log_error "Could not find workspace: $WORKSPACE_NAME in resource group: $RESOURCE_GROUP"
    exit 1
fi

log_info "Workspace ID: $WORKSPACE_ID"

# Configure AKS diagnostic settings if clusters are specified
if [[ ${#AKS_CLUSTERS[@]} -gt 0 ]]; then
    log_info "Configuring AKS diagnostic settings..."
    
    for cluster in "${AKS_CLUSTERS[@]}"; do
        log_info "Configuring diagnostics for cluster: $cluster"
        
        # Get AKS cluster resource ID
        CLUSTER_ID=$(az aks show \
            --name "$cluster" \
            --resource-group "$RESOURCE_GROUP" \
            --query id -o tsv 2>/dev/null)
        
        if [[ -z "$CLUSTER_ID" ]]; then
            log_warn "Could not find AKS cluster: $cluster in resource group: $RESOURCE_GROUP"
            continue
        fi
        
        # Create diagnostic setting
        az monitor diagnostic-settings create \
            --name "sentinel-aks-diagnostics" \
            --resource "$CLUSTER_ID" \
            --workspace "$WORKSPACE_ID" \
            --logs '[
                {"category": "kube-apiserver", "enabled": true},
                {"category": "kube-audit", "enabled": true},
                {"category": "kube-audit-admin", "enabled": true},
                {"category": "kube-controller-manager", "enabled": true},
                {"category": "kube-scheduler", "enabled": true},
                {"category": "cluster-autoscaler", "enabled": true},
                {"category": "cloud-controller-manager", "enabled": true},
                {"category": "guard", "enabled": true},
                {"category": "csi-azuredisk-controller", "enabled": true},
                {"category": "csi-azurefile-controller", "enabled": true},
                {"category": "csi-snapshot-controller", "enabled": true}
            ]' \
            --metrics '[{"category": "AllMetrics", "enabled": true}]' \
            2>/dev/null || log_warn "Diagnostic setting may already exist for $cluster"
        
        log_info "Diagnostic settings configured for: $cluster"
    done
fi

# Deploy ARM template
log_info "Deploying Sentinel analytics rules..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARM_TEMPLATE="$SCRIPT_DIR/../arm/azuredeploy.json"

if [[ -f "$ARM_TEMPLATE" ]]; then
    az deployment group create \
        --resource-group "$RESOURCE_GROUP" \
        --template-file "$ARM_TEMPLATE" \
        --parameters workspaceName="$WORKSPACE_NAME" \
        --parameters workspaceResourceGroup="$RESOURCE_GROUP" \
        --name "aks-security-detections-$(date +%Y%m%d%H%M%S)"
    
    log_info "Analytics rules deployed successfully"
else
    log_warn "ARM template not found at: $ARM_TEMPLATE"
    log_info "You can deploy manually using Terraform or Azure CLI"
fi

# Verify deployment
log_info "Verifying deployment..."
RULE_COUNT=$(az sentinel alert-rule list \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --query "[?contains(displayName, 'AKS')] | length(@)" \
    -o tsv 2>/dev/null || echo "0")

log_info "Total AKS security rules deployed: $RULE_COUNT"

# Print next steps
echo ""
echo "=========================================="
echo "         Deployment Complete"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Verify analytics rules in Azure Portal > Sentinel > Analytics"
echo "2. Review and tune detection thresholds based on your environment"
echo "3. Configure allowed namespaces and service accounts"
echo "4. Set up playbooks for automated response"
echo "5. Import the workbook for visualization"
echo ""
echo "For more information, see the README.md file"
