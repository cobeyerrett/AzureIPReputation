#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Complete example script demonstrating Azure Public IP reputation checking.

.DESCRIPTION
    This example script shows how to use all components together:
    1. Deploy Azure infrastructure
    2. Get the public IP address
    3. Check its reputation
    4. Clean up resources (optional)

.PARAMETER ResourceGroupName
    Name of the resource group (default: rg-reputable-ip-demo)

.PARAMETER SkipCleanup
    Skip the cleanup step at the end

.EXAMPLE
    .\Example-Complete-Workflow.ps1

.EXAMPLE
    .\Example-Complete-Workflow.ps1 -ResourceGroupName "my-test-rg" -SkipCleanup
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "rg-reputable-ip-demo",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipCleanup
)

function Write-ColorOutput {
    param([string]$Text, [string]$Color = 'White')
    Write-Host $Text -ForegroundColor $Color
}

function Show-Header {
    param([string]$Title)
    Write-ColorOutput "`n$('=' * 60)" -Color "Cyan"
    Write-ColorOutput $Title -Color "Cyan"
    Write-ColorOutput "$('=' * 60)" -Color "Cyan"
}

function Show-Step {
    param([string]$Step)
    Write-ColorOutput "`n>>> $Step" -Color "Magenta"
}

try {
    Show-Header "Azure Public IP Reputation Check - Complete Demo"
    
    Write-ColorOutput "This demo will:" -Color "Yellow"
    Write-ColorOutput "1. Deploy Azure infrastructure (Public IP + Storage)" -Color "White"
    Write-ColorOutput "2. Verify the IP address allocation" -Color "White"
    Write-ColorOutput "3. Check the IP reputation using multiple services" -Color "White"
    Write-ColorOutput "4. Show results and cleanup options" -Color "White"
    
    Write-ColorOutput "`nResource Group: $ResourceGroupName" -Color "Green"
    
    # Confirmation
    $response = Read-Host "`nProceed with demo? (y/N)"
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-ColorOutput "Demo cancelled." -Color "Yellow"
        exit 0
    }
    
    Show-Step "Step 1: Running complete deployment and check..."
    
    # Run the main deployment script
    if (Test-Path ".\Deploy-And-Check.ps1") {
        & ".\Deploy-And-Check.ps1" -ResourceGroupName $ResourceGroupName -Location "East US" -Environment "demo"
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "`nDeployment and reputation check completed successfully!" -Color "Green"
        } else {
            Write-ColorOutput "`nDeployment or reputation check encountered issues." -Color "Yellow"
        }
    } else {
        Write-ColorOutput "Deploy-And-Check.ps1 not found!" -Color "Red"
        exit 1
    }
    
    Show-Step "Step 2: Getting deployment information..."
    
    try {
        # Get public IP information
        $publicIps = az network public-ip list --resource-group $ResourceGroupName --output json | ConvertFrom-Json
        
        if ($publicIps -and $publicIps.Count -gt 0) {
            foreach ($pip in $publicIps) {
                Write-ColorOutput "`nPublic IP Details:" -Color "Green"
                Write-ColorOutput "  Name: $($pip.name)" -Color "White"
                Write-ColorOutput "  IP Address: $($pip.ipAddress)" -Color "White"
                Write-ColorOutput "  FQDN: $($pip.dnsSettings.fqdn)" -Color "White"
                Write-ColorOutput "  Location: $($pip.location)" -Color "White"
                Write-ColorOutput "  SKU: $($pip.sku.name)" -Color "White"
            }
        }
        
        # Get storage account information
        $storageAccounts = az storage account list --resource-group $ResourceGroupName --output json | ConvertFrom-Json
        
        if ($storageAccounts -and $storageAccounts.Count -gt 0) {
            Write-ColorOutput "`nStorage Account Details:" -Color "Green"
            foreach ($sa in $storageAccounts) {
                Write-ColorOutput "  Name: $($sa.name)" -Color "White"
                Write-ColorOutput "  Location: $($sa.location)" -Color "White"
                Write-ColorOutput "  SKU: $($sa.sku.name)" -Color "White"
            }
        }
    }
    catch {
        Write-ColorOutput "Could not retrieve resource information: $($_.Exception.Message)" -Color "Yellow"
    }
    
    Show-Step "Step 3: Demonstrating additional reputation check options..."
    
    if ($publicIps -and $publicIps.Count -gt 0 -and $publicIps[0].ipAddress) {
        $ipAddress = $publicIps[0].ipAddress
        
        Write-ColorOutput "`nRunning additional reputation checks with different output formats..." -Color "Yellow"
        
        # JSON format
        Write-ColorOutput "`n--- JSON Output Format ---" -Color "Cyan"
        if (Test-Path ".\Check-IPReputation.ps1") {
            & ".\Check-IPReputation.ps1" -IpAddress $ipAddress -OutputFormat JSON
        }
        
        # Save to file example
        Write-ColorOutput "`n--- Saving Results to File ---" -Color "Cyan"
        if (Test-Path ".\Check-IPReputation.ps1") {
            & ".\Check-IPReputation.ps1" -IpAddress $ipAddress -OutputFormat JSON -SaveToFile
            Write-ColorOutput "Results saved to files in current directory." -Color "Green"
        }
    }
    
    Show-Step "Step 4: Demo Summary"
    
    Write-ColorOutput "`nDemo completed successfully! Here's what was accomplished:" -Color "Green"
    Write-ColorOutput "✓ Created Azure resource group: $ResourceGroupName" -Color "Green"
    Write-ColorOutput "✓ Deployed public IP address with DNS settings" -Color "Green"
    Write-ColorOutput "✓ Created storage account for logging" -Color "Green"
    Write-ColorOutput "✓ Checked IP reputation against multiple services" -Color "Green"
    Write-ColorOutput "✓ Demonstrated different output formats" -Color "Green"
    Write-ColorOutput "✓ Showed file saving capabilities" -Color "Green"
    
    Write-ColorOutput "`nNext steps you could take:" -Color "Yellow"
    Write-ColorOutput "1. Set up API keys for enhanced reputation checking:" -Color "White"
    Write-ColorOutput "   - Get AbuseIPDB API key from: https://www.abuseipdb.com/api" -Color "Gray"
    Write-ColorOutput "   - Get VirusTotal API key from: https://www.virustotal.com/gui/join-us" -Color "Gray"
    Write-ColorOutput "2. Schedule regular reputation checks" -Color "White"
    Write-ColorOutput "3. Set up monitoring and alerting" -Color "White"
    Write-ColorOutput "4. Integrate with your existing security workflow" -Color "White"
    
    # Cleanup option
    if (-not $SkipCleanup) {
        Write-ColorOutput "`nCleanup:" -Color "Yellow"
        $cleanup = Read-Host "Delete the created resources? (y/N)"
        
        if ($cleanup -eq 'y' -or $cleanup -eq 'Y') {
            Show-Step "Step 5: Cleaning up resources..."
            
            Write-ColorOutput "Deleting resource group: $ResourceGroupName" -Color "Yellow"
            az group delete --name $ResourceGroupName --yes --no-wait
            
            Write-ColorOutput "Resource group deletion initiated (running in background)." -Color "Green"
            Write-ColorOutput "You can check the status with: az group show --name $ResourceGroupName" -Color "Gray"
        } else {
            Write-ColorOutput "`nResources preserved. To clean up later, run:" -Color "Yellow"
            Write-ColorOutput "az group delete --name $ResourceGroupName --yes" -Color "Gray"
        }
    } else {
        Write-ColorOutput "`nSkipping cleanup as requested." -Color "Yellow"
        Write-ColorOutput "To clean up later, run: az group delete --name $ResourceGroupName --yes" -Color "Gray"
    }
    
    Show-Header "Demo Complete!"
    Write-ColorOutput "Thank you for trying the Azure Public IP Reputation Checker!" -Color "Green"
    
}
catch {
    Write-ColorOutput "`nDemo failed: $($_.Exception.Message)" -Color "Red"
    Write-ColorOutput "`nYou may need to clean up manually:" -Color "Yellow"
    Write-ColorOutput "az group delete --name $ResourceGroupName --yes" -Color "Gray"
    exit 1
}
