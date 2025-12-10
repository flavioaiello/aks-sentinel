# AKS Security Detections for Microsoft Sentinel

This recipe provides a comprehensive set of security detection rules for Azure Kubernetes Service (AKS) ingestion into Microsoft Sentinel.

> **Experimental Disclaimer**
>
> This repository is a **experimental project** exploring AKS / Kubernetes detections.  
> It is provided **as-is**, with **no guarantees** of correctness, completeness, performance, or security.
>
> - Not production-ready and not officially supported.
> - May contain bugs, blind spots, and false positives/negatives.
> - Detection logic and examples are opinionated and may change at any time.
> - Use at your own risk and always validate in a safe, non-production environment first.
>
> Feedback, issues, and PRs are very welcome, this repo is meant as a **living experiment**, not a finished product.
> 
> All views, assumptions, and mistakes in this repository are my own and **do not represent any employer or vendor.**


## Overview

This detection package covers:
- **Container Runtime Security**: Detection of suspicious container activities
- **Kubernetes API Abuse**: Detection of malicious API operations
- **Network Security**: Detection of anomalous network patterns
- **Identity & Access**: Detection of privilege escalation and unauthorized access
- **Configuration Security**: Detection of insecure configurations
- **Data Exfiltration**: Detection of potential data theft attempts
- **Supply Chain Security**: Detection of npm supply chain attacks (Shai-Hulud)
- **Workload Security**: Detection of application-layer exploits and runtime abuse (Java, Node.js, Web Shells)

## Detection Coverage

| Category | Rule Count | Severity Range | MITRE ATT&CK Coverage |
|----------|------------|----------------|----------------------|
| Container Runtime | 5 | Medium - High | T1611, T1204, T1059, T1082 |
| Kubernetes API | 6 | Medium - Critical | T1552, T1078, T1609, T1190, T1613, T1110 |
| Network Security | 4 | Medium - High | T1071, T1041, T1611 |
| Identity & Access | 3 | Medium - Critical | T1134, T1136, T1565 |
| Data Exfiltration | 3 | High - Critical | T1530, T1041, T1552 |
| Configuration | 1 | Low | T1046 |
| **Supply Chain (Shai-Hulud)** | **3** | **Critical** | **T1195, T1059, T1567** |
| **Workload Security** | **5** | **High** | **T1190, T1505, T1203, T1211** |

**Total: 30 detection rules** covering 25+ MITRE ATT&CK techniques.

## Quick Start

### Deployment Options

| Method | Command | Best For |
|--------|---------|----------|
| **Terraform** (recommended) | `terraform apply` | Production, IaC workflows |
| **ARM Template** | `az deployment group create` | Azure-native deployments |
| **Setup Script** | `./scripts/setup.sh` | Quick testing, demos |

### 1-Minute Deploy

```bash
# Clone and deploy
git clone <repo-url>
cd recipes/aks-security-detections/terraform
terraform init && terraform apply -var-file="variables.tfvars"
```

## Prerequisites

1. **Azure Subscription** with:
   - Microsoft Sentinel workspace enabled
   - AKS cluster(s) with diagnostic settings configured

2. **Data Connectors** configured:
   - Azure Kubernetes Service (AKS) diagnostics
   - Microsoft Defender for Containers (recommended)
   - Azure Activity Logs

3. **Required Tables**:
   - `AzureDiagnostics` (Category: kube-apiserver, kube-audit, kube-controller-manager)
   - `ContainerLog` / `ContainerLogV2`
   - `KubeEvents`
   - `KubePodInventory`
   - `KubeNodeInventory`
   - `ContainerInventory`
   - `AzureActivity`

## Deployment

### Option 1: Terraform (Recommended)

```bash
cd terraform
terraform init
terraform plan -var-file="variables.tfvars"
terraform apply -var-file="variables.tfvars"
```

### Option 2: Azure CLI

```bash
# Deploy all analytics rules
for file in analytics-rules/*.json; do
  az sentinel alert-rule create \
    --resource-group <rg-name> \
    --workspace-name <workspace-name> \
    --alert-rule "$file"
done
```

### Option 3: ARM Template

```bash
az deployment group create \
  --resource-group <rg-name> \
  --template-file arm/azuredeploy.json \
  --parameters arm/azuredeploy.parameters.json
```

### Option 4: Setup Script

```bash
# Interactive setup with validation
./scripts/setup.sh
```

## Detection Categories

| Category | Rule Count | Severity Range | MITRE ATT&CK |
|----------|------------|----------------|--------------|
| Container Runtime | 5 | Medium - High | T1611, T1204, T1059, T1082 |
| Kubernetes API | 6 | Medium - Critical | T1552, T1078, T1609, T1190, T1613, T1110 |
| Network Security | 4 | Medium - High | T1071, T1041, T1611 |
| Identity & Access | 3 | High - Critical | T1134, T1136, T1565 |
| Configuration | 1 | Low - Medium | T1046 |
| Data Exfiltration | 3 | High - Critical | T1530, T1041, T1552 |
| **Supply Chain (Shai-Hulud)** | **3** | **Critical** | **T1195, T1059, T1567** |
| **Workload Security** | **5** | **High** | **T1190, T1505, T1203, T1211** |

## Supply Chain Attack Detection (NEW)

This recipe includes specialized detections for the **Shai-Hulud NPM supply chain attacks** that compromised 1000+ packages in September-November 2025.

### What is Shai-Hulud?

A series of sophisticated npm supply chain attacks that:
- Compromised 1000+ npm packages including @posthog/*, @zapier/*, @crowdstrike/*, @asyncapi/*
- Exfiltrated credentials via TruffleHog to webhook.site
- Abused GitHub Actions with malicious SHA1HULUD runners
- Used fake Bun runtime installation as attack vector

### Included Supply Chain Rules

| Rule | Description | IoCs Detected |
|------|-------------|---------------|
| `shai-hulud-exfiltration.json` | Detects connections to known exfil endpoints | webhook.site, bb8ca5f6-... |
| `shai-hulud-trufflehog.json` | Detects TruffleHog credential harvesting | trufflehog filesystem, credential env vars |
| `shai-hulud-malicious-files.json` | Detects known malicious files | setup_bun.js, actionsSecrets.json, SHA1HULUD |

### Gap Analysis

**Important:** When CI/CD runners (GitLab runners, GitHub Actions self-hosted runners) run **on Kubernetes**, these AKS rules provide **substantial protection (80-90%)** against Shai-Hulud:

| Attack Phase | Detection |
|--------------|-----------|
| postinstall hook (curl/wget) | DETECTED |
| TruffleHog download/execution | DETECTED |
| Exfiltration to webhook.site | DETECTED |
| SHA1HULUD runner references | DETECTED |
| JavaScript-based exfiltration | PARTIAL (network) |

**Remaining gaps:** Developer workstation attacks, pure JS exfiltration, browser-based crypto theft.

See `docs/SHAI-HULUD-GAP-ANALYSIS.md` for complete coverage analysis.

### Reference

- [Shai-Hulud Detector](https://github.com/Cobenian/shai-hulud-detect)
- [StepSecurity Analysis](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [Semgrep Advisory](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)

## Files Structure

```
aks-security-detections/
├── README.md
├── analytics-rules/
│   ├── container-runtime/
│   ├── kubernetes-api/
│   ├── network-security/
│   ├── identity-access/
│   ├── configuration/
│   ├── data-exfiltration/
│   ├── supply-chain/           # NEW: Shai-Hulud detections
│   └── workload-security/      # NEW: App-layer exploits (Java, Node, Web Shells)
├── hunting-queries/
│   └── shai-hulud-comprehensive-hunt.kql  # NEW
├── workbooks/
├── terraform/
├── arm/
└── docs/
    └── SHAI-HULUD-GAP-ANALYSIS.md  # NEW: Coverage analysis
```

## Tuning Recommendations

1. **Allowlisting**: Update the `allowed_namespaces` and `allowed_service_accounts` parameters
2. **Thresholds**: Adjust detection thresholds based on your baseline
3. **Severity**: Modify severity levels based on your risk tolerance

## License

MIT License - See LICENSE file for details.
