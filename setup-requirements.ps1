# Azure Entra Security Assessment - Module Setup Script
# This script installs all required PowerShell modules

Write-Host "Azure Entra Security Assessment - Module Setup" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# Required modules
$requiredModules = @(
    @{ Name = 'Az.Accounts'; Description = 'Azure Account management' },
    @{ Name = 'Az.Resources'; Description = 'Azure Resource management' },
    @{ Name = 'Microsoft.Graph.Authentication'; Description = 'Microsoft Graph authentication' },
    @{ Name = 'Microsoft.Graph.Identity.SignIns'; Description = 'Identity and sign-in policies' },
    @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; Description = 'Directory management' },
    @{ Name = 'Microsoft.Graph.Users'; Description = 'User management' },
    @{ Name = 'Microsoft.Graph.Groups'; Description = 'Group management' },
    @{ Name = 'Microsoft.Graph.DeviceManagement'; Description = 'Device management' }
)

Write-Host "`nChecking PowerShell execution policy..." -ForegroundColor Yellow
$executionPolicy = Get-ExecutionPolicy
if ($executionPolicy -eq 'Restricted') {
    Write-Host "Warning: PowerShell execution policy is set to 'Restricted'" -ForegroundColor Red
    Write-Host "Setting execution policy to RemoteSigned for CurrentUser..." -ForegroundColor Yellow
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Write-Host "Success: Execution policy updated successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Failed to update execution policy. You may need to run as Administrator." -ForegroundColor Red
        Write-Host "Manual command: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Gray
    }
}

Write-Host "`nInstalling required modules..." -ForegroundColor Yellow
Write-Host "This may take several minutes..." -ForegroundColor Gray

foreach ($module in $requiredModules) {
    Write-Host "`nProcessing: $($module.Name)" -ForegroundColor Cyan
    Write-Host "Purpose: $($module.Description)" -ForegroundColor Gray
    
    if (Get-Module -ListAvailable -Name $module.Name) {
        Write-Host "Success: Already installed: $($module.Name)" -ForegroundColor Green
        
        # Check for updates
        $installed = Get-Module -ListAvailable -Name $module.Name | Sort-Object Version -Descending | Select-Object -First 1
        try {
            $online = Find-Module -Name $module.Name -ErrorAction SilentlyContinue
            if ($online -and ($online.Version -gt $installed.Version)) {
                Write-Host "Update available: $($installed.Version) -> $($online.Version)" -ForegroundColor Yellow
                Write-Host "   Run: Update-Module -Name $($module.Name)" -ForegroundColor Gray
            }
        }
        catch {
            # Ignore errors when checking for updates
        }
    }
    else {
        try {
            Write-Host "Installing: $($module.Name)..." -ForegroundColor Yellow
            Install-Module -Name $module.Name -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
            Write-Host "Success: Successfully installed: $($module.Name)" -ForegroundColor Green
        }
        catch {
            Write-Host "Error: Failed to install: $($module.Name)" -ForegroundColor Red
            Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "`n" + "="*60 -ForegroundColor Green
Write-Host "SETUP COMPLETE" -ForegroundColor Green
Write-Host "="*60 -ForegroundColor Green

Write-Host "`nNext steps:" -ForegroundColor White
Write-Host "1. Run the security assessment: .\Azure-Entra-Security-Assessment.ps1"
Write-Host "2. Follow the interactive authentication prompts"
Write-Host "3. Review the generated HTML report"

Write-Host "`nTroubleshooting:" 
Write-Host "* If you get execution policy errors, run as Administrator:" 
Write-Host "  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine" 
Write-Host "* If modules fail to install, try running PowerShell as Administrator" 
Write-Host "* For corporate networks, you may need to configure proxy settings"