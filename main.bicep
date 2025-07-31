@description('Location for all resources')
param location string = resourceGroup().location

@description('Name prefix for the public IP address')
param publicIpNamePrefix string = 'pip-reputable'

@description('Environment suffix (e.g., dev, test, prod)')
param environment string = 'dev'

@description('Public IP allocation method')
@allowed([
  'Static'
  'Dynamic'
])
param publicIpAllocationMethod string = 'Static'

@description('Public IP SKU')
@allowed([
  'Basic'
  'Standard'
])
param publicIpSku string = 'Standard'

@description('Public IP SKU tier')
@allowed([
  'Regional'
  'Global'
])
param publicIpSkuTier string = 'Regional'

@description('Domain name label for the public IP')
param domainNameLabel string = '${publicIpNamePrefix}-${environment}-${uniqueString(resourceGroup().id)}'

@description('DNS domain name label scope')
@allowed([
  'TenantReuse'
  'SubscriptionReuse'
  'ResourceGroupReuse'
  'NoReuse'
])
param domainNameLabelScope string = 'ResourceGroupReuse'

var publicIpName = '${publicIpNamePrefix}-${environment}'

// Public IP Address resource
resource publicIpAddress 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: publicIpName
  location: location
  sku: {
    name: publicIpSku
    tier: publicIpSkuTier
  }
  properties: {
    publicIPAllocationMethod: publicIpAllocationMethod
    dnsSettings: {
      domainNameLabel: domainNameLabel
      domainNameLabelScope: domainNameLabelScope
    }
    ddosSettings: {
      protectionMode: 'VirtualNetworkInherited'
    }
    idleTimeoutInMinutes: 4
    ipTags: [
      {
        ipTagType: 'FirstPartyUsage'
        tag: 'Reputation-Check'
      }
    ]
  }
  tags: {
    Purpose: 'IP-Reputation-Testing'
    Environment: environment
    CreatedBy: 'Bicep-Template'
  }
}

// Storage Account for logs (optional)
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'st${uniqueString(resourceGroup().id)}rep'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
  tags: {
    Purpose: 'IP-Reputation-Logs'
    Environment: environment
  }
}

// Output values
output publicIpAddress string = publicIpAddress.properties.ipAddress
output publicIpId string = publicIpAddress.id
output publicIpName string = publicIpAddress.name
output publicIpFqdn string = publicIpAddress.properties.dnsSettings.fqdn
output storageAccountName string = storageAccount.name
output resourceGroupName string = resourceGroup().name
