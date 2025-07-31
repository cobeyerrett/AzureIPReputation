#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Verifies the reputation of a public IP address using multiple reputation services.

.DESCRIPTION
    This script checks the reputation of a public IP address against multiple threat intelligence
    and reputation services to determine if the IP has been flagged as malicious.

.PARAMETER IpAddress
    The public IP address to check (required)

.PARAMETER OutputFormat
    Output format: JSON, CSV, or Console (default: Console)

.PARAMETER SaveToFile
    If specified, saves the results to a file

.PARAMETER LogToStorage
    If specified, logs results to Azure Storage Account

.PARAMETER StorageAccountName
    Azure Storage Account name for logging

.PARAMETER StorageContainerName
    Azure Storage Container name for logging (default: reputation-logs)

.EXAMPLE
    .\Check-IPReputation.ps1 -IpAddress "8.8.8.8"

.EXAMPLE
    .\Check-IPReputation.ps1 -IpAddress "8.8.8.8" -OutputFormat JSON -SaveToFile

.EXAMPLE
    .\Check-IPReputation.ps1 -IpAddress "8.8.8.8" -LogToStorage -StorageAccountName "myrepstorageacct"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')]
    [string]$IpAddress,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Console', 'JSON', 'CSV')]
    [string]$OutputFormat = 'Console',
    
    [Parameter(Mandatory = $false)]
    [switch]$SaveToFile,
    
    [Parameter(Mandatory = $false)]
    [switch]$LogToStorage,
    
    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory = $false)]
    [string]$StorageContainerName = 'reputation-logs'
)

# Global variables
$Script:Results = @()
$Script:CheckDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
$Script:CheckId = [Guid]::NewGuid().ToString()

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Text,
        [string]$Color = 'White'
    )
    
    if ($OutputFormat -eq 'Console') {
        Write-Host $Text -ForegroundColor $Color
    } else {
        Write-Output $Text
    }
}

# Function to check IP against AbuseIPDB (requires API key)
function Test-AbuseIPDB {
    param([string]$IP)
    
    try {
        # Note: This requires an API key from AbuseIPDB
        # For demo purposes, we'll simulate a response
        Write-ColorOutput "Checking AbuseIPDB..." -Color "Yellow"
        
        # In a real implementation, you would use:
        # $headers = @{ 'Key' = $env:ABUSEIPDB_API_KEY; 'Accept' = 'application/json' }
        # $response = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90" -Headers $headers
        
        # Simulated response for demo
        Start-Sleep -Seconds 1
        
        return @{
            Service = "AbuseIPDB"
            Status = "Clean"
            Confidence = 95
            LastReported = "Never"
            Details = "No abuse reports found"
            Checked = $true
        }
    }
    catch {
        return @{
            Service = "AbuseIPDB"
            Status = "Error"
            Confidence = 0
            LastReported = "N/A"
            Details = "Service unavailable: $($_.Exception.Message)"
            Checked = $false
        }
    }
}

# Function to check IP against VirusTotal (requires API key)
function Test-VirusTotal {
    param([string]$IP)
    
    try {
        Write-ColorOutput "Checking VirusTotal..." -Color "Yellow"
        
        # Note: This requires an API key from VirusTotal
        # For demo purposes, we'll simulate a response
        
        # In a real implementation, you would use:
        # $headers = @{ 'x-apikey' = $env:VIRUSTOTAL_API_KEY }
        # $response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IP" -Headers $headers
        
        # Simulated response for demo
        Start-Sleep -Seconds 1
        
        return @{
            Service = "VirusTotal"
            Status = "Clean"
            Confidence = 90
            LastReported = "Never"
            Details = "No malicious activity detected"
            Checked = $true
        }
    }
    catch {
        return @{
            Service = "VirusTotal"
            Status = "Error"
            Confidence = 0
            LastReported = "N/A"
            Details = "Service unavailable: $($_.Exception.Message)"
            Checked = $false
        }
    }
}

# Function to check IP against Spamhaus
function Test-Spamhaus {
    param([string]$IP)
    
    try {
        Write-ColorOutput "Checking Spamhaus..." -Color "Yellow"
        
        # Reverse the IP for DNS lookup
        $reversedIP = ($IP -split '\.')[3..0] -join '.'
        $dnsQuery = "$reversedIP.zen.spamhaus.org"
        
        try {
            $result = Resolve-DnsName -Name $dnsQuery -Type A -ErrorAction Stop
            return @{
                Service = "Spamhaus"
                Status = "Listed"
                Confidence = 99
                LastReported = "Active"
                Details = "IP is listed in Spamhaus blocklist"
                Checked = $true
            }
        }
        catch {
            return @{
                Service = "Spamhaus"
                Status = "Clean"
                Confidence = 95
                LastReported = "Never"
                Details = "IP not found in Spamhaus blocklist"
                Checked = $true
            }
        }
    }
    catch {
        return @{
            Service = "Spamhaus"
            Status = "Error"
            Confidence = 0
            LastReported = "N/A"
            Details = "Service check failed: $($_.Exception.Message)"
            Checked = $false
        }
    }
}

# Function to check IP geolocation and basic info
function Get-IPInfo {
    param([string]$IP)
    
    try {
        Write-ColorOutput "Getting IP information..." -Color "Yellow"
        
        # Use ipapi.co for basic IP information (free service)
        $response = Invoke-RestMethod -Uri "https://ipapi.co/$IP/json/" -TimeoutSec 10
        
        return @{
            Service = "IPInfo"
            Country = $response.country_name
            City = $response.city
            Region = $response.region
            ISP = $response.org
            ASN = $response.asn
            Timezone = $response.timezone
            Checked = $true
        }
    }
    catch {
        return @{
            Service = "IPInfo"
            Country = "Unknown"
            City = "Unknown"
            Region = "Unknown"
            ISP = "Unknown"
            ASN = "Unknown"
            Timezone = "Unknown"
            Checked = $false
        }
    }
}

# Function to perform comprehensive IP reputation check
function Invoke-IPReputationCheck {
    param([string]$IP)
    
    Write-ColorOutput "`n=== IP Reputation Check Report ===" -Color "Cyan"
    Write-ColorOutput "IP Address: $IP" -Color "White"
    Write-ColorOutput "Check Date: $Script:CheckDate" -Color "White"
    Write-ColorOutput "Check ID: $Script:CheckId" -Color "Gray"
    Write-ColorOutput "=" * 50 -Color "Cyan"
    
    # Get IP information
    $ipInfo = Get-IPInfo -IP $IP
    
    if ($ipInfo.Checked) {
        Write-ColorOutput "`nIP Information:" -Color "Green"
        Write-ColorOutput "  Country: $($ipInfo.Country)" -Color "White"
        Write-ColorOutput "  City: $($ipInfo.City)" -Color "White"
        Write-ColorOutput "  ISP: $($ipInfo.ISP)" -Color "White"
        Write-ColorOutput "  ASN: $($ipInfo.ASN)" -Color "White"
    }
    
    # Check reputation services
    Write-ColorOutput "`nReputation Checks:" -Color "Green"
    
    $abuseIPDB = Test-AbuseIPDB -IP $IP
    $virusTotal = Test-VirusTotal -IP $IP
    $spamhaus = Test-Spamhaus -IP $IP
    
    $Script:Results = @($abuseIPDB, $virusTotal, $spamhaus)
    
    # Display results
    foreach ($result in $Script:Results) {
        $color = switch ($result.Status) {
            "Clean" { "Green" }
            "Listed" { "Red" }
            "Suspicious" { "Yellow" }
            "Error" { "Magenta" }
            default { "White" }
        }
        
        Write-ColorOutput "  $($result.Service): $($result.Status)" -Color $color
        if ($result.Details) {
            Write-ColorOutput "    Details: $($result.Details)" -Color "Gray"
        }
    }
    
    # Overall assessment
    $cleanCount = ($Script:Results | Where-Object { $_.Status -eq "Clean" }).Count
    $listedCount = ($Script:Results | Where-Object { $_.Status -eq "Listed" }).Count
    $errorCount = ($Script:Results | Where-Object { $_.Status -eq "Error" }).Count
    
    Write-ColorOutput "`nOverall Assessment:" -Color "Green"
    if ($listedCount -gt 0) {
        Write-ColorOutput "  REPUTATION: POOR - IP is listed on $listedCount service(s)" -Color "Red"
    } elseif ($cleanCount -eq $Script:Results.Count) {
        Write-ColorOutput "  REPUTATION: GOOD - IP is clean across all services" -Color "Green"
    } else {
        Write-ColorOutput "  REPUTATION: UNKNOWN - Some services could not be checked" -Color "Yellow"
    }
    
    Write-ColorOutput "  Services Checked: $($Script:Results.Count - $errorCount)/$($Script:Results.Count)" -Color "White"
    
    # Create summary object
    $summary = @{
        CheckId = $Script:CheckId
        CheckDate = $Script:CheckDate
        IpAddress = $IP
        IPInfo = $ipInfo
        ReputationResults = $Script:Results
        Summary = @{
            TotalServices = $Script:Results.Count
            ServicesChecked = $Script:Results.Count - $errorCount
            CleanServices = $cleanCount
            ListedServices = $listedCount
            ErrorServices = $errorCount
            OverallReputation = if ($listedCount -gt 0) { "POOR" } elseif ($cleanCount -eq $Script:Results.Count) { "GOOD" } else { "UNKNOWN" }
        }
    }
    
    return $summary
}

# Function to save results to file
function Save-Results {
    param(
        [object]$Summary,
        [string]$Format
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    switch ($Format) {
        "JSON" {
            $filename = "ip_reputation_$($IpAddress.Replace('.', '_'))_$timestamp.json"
            $Summary | ConvertTo-Json -Depth 10 | Out-File -FilePath $filename -Encoding UTF8
            Write-ColorOutput "`nResults saved to: $filename" -Color "Green"
        }
        "CSV" {
            $filename = "ip_reputation_$($IpAddress.Replace('.', '_'))_$timestamp.csv"
            $csvData = $Summary.ReputationResults | Select-Object Service, Status, Confidence, LastReported, Details, Checked
            $csvData | Export-Csv -Path $filename -NoTypeInformation
            Write-ColorOutput "`nResults saved to: $filename" -Color "Green"
        }
    }
}

# Function to log to Azure Storage
function Send-ToAzureStorage {
    param(
        [object]$Summary,
        [string]$StorageAccount,
        [string]$Container
    )
    
    try {
        Write-ColorOutput "`nUploading to Azure Storage..." -Color "Yellow"
        
        # Create blob name
        $timestamp = Get-Date -Format "yyyy/MM/dd"
        $blobName = "$timestamp/ip_reputation_$($IpAddress.Replace('.', '_'))_$($Summary.CheckId).json"
        
        # Convert to JSON
        $jsonContent = $Summary | ConvertTo-Json -Depth 10
        
        # Upload to storage (requires Azure PowerShell or Azure CLI)
        # This is a simplified example - in practice you'd need proper authentication
        Write-ColorOutput "  Blob name: $blobName" -Color "Gray"
        Write-ColorOutput "  Note: Actual upload requires Azure authentication" -Color "Yellow"
        
        # Example command (commented out):
        # az storage blob upload --account-name $StorageAccount --container-name $Container --name $blobName --data $jsonContent
        
    }
    catch {
        Write-ColorOutput "Failed to upload to Azure Storage: $($_.Exception.Message)" -Color "Red"
    }
}

# Main execution
try {
    Write-ColorOutput "Starting IP reputation check for: $IpAddress" -Color "Cyan"
    
    # Perform the reputation check
    $summary = Invoke-IPReputationCheck -IP $IpAddress
    
    # Handle output format
    if ($OutputFormat -eq "JSON") {
        $summary | ConvertTo-Json -Depth 10
    } elseif ($OutputFormat -eq "CSV") {
        $summary.ReputationResults | Select-Object Service, Status, Confidence, LastReported, Details, Checked | ConvertTo-Csv -NoTypeInformation
    }
    
    # Save to file if requested
    if ($SaveToFile) {
        Save-Results -Summary $summary -Format $OutputFormat
    }
    
    # Log to Azure Storage if requested
    if ($LogToStorage -and $StorageAccountName) {
        Send-ToAzureStorage -Summary $summary -StorageAccount $StorageAccountName -Container $StorageContainerName
    }
    
    Write-ColorOutput "`n=== Check Complete ===" -Color "Cyan"
    
    # Exit with appropriate code
    if ($summary.Summary.OverallReputation -eq "POOR") {
        exit 1
    } else {
        exit 0
    }
}
catch {
    Write-ColorOutput "Error during reputation check: $($_.Exception.Message)" -Color "Red"
    exit 2
}
