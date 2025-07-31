# Azure Public IP Reputation Checker

This solution creates an Azure public IP address using Bicep and then verifies its reputation using multiple threat intelligence services.

## Overview

The solution consists of:
1. **Bicep Template** (`main.bicep`) - Creates Azure infrastructure including public IP and storage account
2. **PowerShell Reputation Checker** (`Check-IPReputation.ps1`) - Verifies IP reputation against multiple services
3. **Deployment Script** (`Deploy-And-Check.ps1`) - Automates the entire process

## Features

### Infrastructure (Bicep)
- ✅ Creates a public IP address with customizable settings
- ✅ Configures DNS settings and domain name labels
- ✅ Includes DDoS protection settings
- ✅ Creates storage account for logging
- ✅ Applies consistent tagging for resource management
- ✅ Uses latest Azure API versions (2024-05-01)

### Reputation Checking (PowerShell)
- ✅ Checks multiple reputation services:
  - AbuseIPDB (requires API key)
  - VirusTotal (requires API key)
  - Spamhaus DNS blocklist
  - IP geolocation and ISP information
- ✅ Multiple output formats (Console, JSON, CSV)
- ✅ Azure Storage logging integration
- ✅ Colored console output for easy reading
- ✅ Comprehensive error handling

## Prerequisites

1. **Azure CLI** - Install from [here](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
2. **PowerShell 7+** - Install from [here](https://github.com/PowerShell/PowerShell)
3. **Azure Subscription** - With contributor access
4. **API Keys** (Optional for enhanced checking):
   - [AbuseIPDB API Key](https://www.abuseipdb.com/api)
   - [VirusTotal API Key](https://www.virustotal.com/gui/join-us)

## Quick Start

### 1. Clone and Setup
```powershell
# Navigate to the repository
cd "c:\Users\cobeyerrett\repos\cobey-msft\Azure\ReputableIP"

# Login to Azure
az login

# Set your subscription (optional)
az account set --subscription "your-subscription-id"
```

### 2. Deploy Everything
```powershell
# Deploy infrastructure and check reputation
.\Deploy-And-Check.ps1 -ResourceGroupName "rg-reputable-ip-test"
```

### 3. Manual Deployment (Alternative)
```powershell
# Create resource group
az group create --name "rg-reputable-ip" --location "East US"

# Deploy Bicep template
az deployment group create \
  --resource-group "rg-reputable-ip" \
  --template-file "main.bicep" \
  --parameters "@main.parameters.json"

# Get the public IP address
$ip = az network public-ip show --resource-group "rg-reputable-ip" --name "pip-reputable-dev" --query "ipAddress" -o tsv

# Check reputation
.\Check-IPReputation.ps1 -IpAddress $ip
```

## Configuration

### Bicep Parameters (`main.parameters.json`)
```json
{
  "location": "East US",           // Azure region
  "environment": "dev",            // Environment suffix
  "publicIpSku": "Standard",       // Basic or Standard
  "publicIpAllocationMethod": "Static"  // Static or Dynamic
}
```

### Environment Variables (for API keys)
```powershell
# Set API keys for enhanced reputation checking
$env:ABUSEIPDB_API_KEY = "your-abuseipdb-key"
$env:VIRUSTOTAL_API_KEY = "your-virustotal-key"
```

## Usage Examples

### Basic Reputation Check
```powershell
.\Check-IPReputation.ps1 -IpAddress "8.8.8.8"
```

### Save Results to JSON
```powershell
.\Check-IPReputation.ps1 -IpAddress "8.8.8.8" -OutputFormat JSON -SaveToFile
```

### Log to Azure Storage
```powershell
.\Check-IPReputation.ps1 -IpAddress "8.8.8.8" -LogToStorage -StorageAccountName "mystorageaccount"
```

### Custom Deployment
```powershell
.\Deploy-And-Check.ps1 -ResourceGroupName "my-rg" -Location "West US 2" -Environment "prod"
```

## Output Examples

### Console Output
```
=== IP Reputation Check Report ===
IP Address: 20.123.45.67
Check Date: 2025-01-31 10:30:45 UTC
Check ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
==================================================

IP Information:
  Country: United States
  City: Seattle
  ISP: Microsoft Corporation
  ASN: AS8075

Reputation Checks:
  AbuseIPDB: Clean
    Details: No abuse reports found
  VirusTotal: Clean
    Details: No malicious activity detected
  Spamhaus: Clean
    Details: IP not found in Spamhaus blocklist

Overall Assessment:
  REPUTATION: GOOD - IP is clean across all services
  Services Checked: 3/3
```

### JSON Output
```json
{
  "CheckId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "CheckDate": "2025-01-31 10:30:45 UTC",
  "IpAddress": "20.123.45.67",
  "IPInfo": {
    "Service": "IPInfo",
    "Country": "United States",
    "City": "Seattle",
    "ISP": "Microsoft Corporation"
  },
  "Summary": {
    "OverallReputation": "GOOD",
    "TotalServices": 3,
    "ServicesChecked": 3,
    "CleanServices": 3,
    "ListedServices": 0
  }
}
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Bicep Template│    │  Public IP      │    │ Reputation      │
│   Deployment    │───▶│  Address        │───▶│ Checker         │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       ▼
         ▼                       ▼              ┌─────────────────┐
┌─────────────────┐    ┌─────────────────┐    │ Multiple        │
│ Storage Account │    │ DNS Settings    │    │ Reputation      │
│ (Logging)       │    │ & Tags          │    │ Services        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Security Considerations

1. **API Keys**: Store API keys in environment variables or Azure Key Vault
2. **Network Security**: Consider IP restrictions if deploying in production
3. **Storage Security**: Enable storage account security features in production
4. **Access Control**: Use Azure RBAC for resource access management

## Monitoring and Alerts

You can set up monitoring for:
- IP reputation changes over time
- Failed reputation checks
- Storage account access logs
- Resource deployment status

## Troubleshooting

### Common Issues

1. **Azure CLI not logged in**
   ```powershell
   az login
   ```

2. **Insufficient permissions**
   - Ensure you have Contributor role on the subscription/resource group

3. **API rate limits**
   - Some reputation services have rate limits
   - Consider implementing retry logic for production use

4. **PowerShell execution policy**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Debug Mode
```powershell
# Enable verbose output
.\Check-IPReputation.ps1 -IpAddress "8.8.8.8" -Verbose
```

## Cleanup

To remove all resources:
```powershell
az group delete --name "rg-reputable-ip" --yes --no-wait
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is provided as-is for educational and testing purposes.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review Azure documentation
3. Open an issue in the repository

---

**Note**: This solution is designed for testing and educational purposes. For production use, consider additional security measures, error handling, and monitoring capabilities.
