<#
.SYNOPSIS
    Azure Entra Tenant Security Assessment Script (Modular Version)

.DESCRIPTION
    This script performs a comprehensive security assessment of an Azure Entra tenant,
    analyzing various security settings, policies, and configurations to provide
    a detailed health report. It will automatically install required modules if missing.

    This modular version organizes code into separate modules for better maintainability:
    - Security-Assessment-Utils.ps1: Connection functions and utilities
    - Core-Security-Assessments.ps1: Standard Azure Entra security checks
    - Essential8-Assessments.ps1: Essential 8 framework compliance checks
    - Report-Generation.ps1: Scoring, recommendations, and HTML generation

.NOTES
    Author: Security Assessment Tool
    Version: 2.0 (Modular)
    Requires: Az PowerShell modules and Microsoft Graph PowerShell modules
#>

param(
    [string]$OutputPath = "",
    [switch]$DetailedOutput
)

# Import modules
Write-Host "🔧 Loading Security Assessment Modules..." -ForegroundColor Cyan

try {
    # Import utility functions
    Import-Module ".\modules\Security-Assessment-Utils.psm1" -Force -ErrorAction Stop
    Write-Host "✅ Utilities module loaded" -ForegroundColor Green
    
    # Import core assessments
    Import-Module ".\modules\Core-Security-Assessments.psm1" -Force -ErrorAction Stop
    Write-Host "✅ Core assessments module loaded" -ForegroundColor Green
    
    # Import Essential 8 assessments
    Import-Module ".\modules\Essential8-Assessments.psm1" -Force -ErrorAction Stop
    Write-Host "✅ Essential 8 assessments module loaded" -ForegroundColor Green
    
    # Import reporting functions
    Import-Module ".\modules\Report-Generation.psm1" -Force -ErrorAction Stop
    Write-Host "✅ Report generation module loaded" -ForegroundColor Green
    
    Write-Host "✅ All modules loaded successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Failed to load required modules: $_"
    Write-Host "Please ensure all module files exist in the 'modules' directory:" -ForegroundColor Red
    Write-Host "  - modules\Security-Assessment-Utils.psm1" -ForegroundColor Gray
    Write-Host "  - modules\Core-Security-Assessments.psm1" -ForegroundColor Gray
    Write-Host "  - modules\Essential8-Assessments.psm1" -ForegroundColor Gray
    Write-Host "  - modules\Report-Generation.psm1" -ForegroundColor Gray
    exit 1
}

# Main execution function
function Start-SecurityAssessment {
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "AZURE ENTRA TENANT SECURITY ASSESSMENT TOOL (MODULAR v2.0)" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    # Check required modules and auto-install if missing
    if (!(Test-RequiredModules)) {
        Write-Error "Required modules are not available. Exiting."
        Write-Host "`nTo manually install modules, run: .\setup-requirements.ps1" -ForegroundColor Yellow
        return
    }
    
    # Connect to Azure services
    if (!(Connect-ToAzureServices)) {
        Write-Error "Failed to connect to Azure services. Exiting."
        return
    }
    
    # Generate dynamic output path after we have tenant information
    $Global:FinalOutputPath = Get-DynamicOutputPath -CustomPath $OutputPath
    Write-Host "`nReport will be saved as: $Global:FinalOutputPath" -ForegroundColor Gray
    
    # Run standard security assessments
    Write-Host "`n" + "="*60 -ForegroundColor Green
    Write-Host "STANDARD AZURE ENTRA SECURITY ASSESSMENTS" -ForegroundColor Green
    Write-Host "="*60 -ForegroundColor Green
    
    Test-SecurityDefaults
    Test-ConditionalAccessPolicies
    Test-PasswordPolicy
    Test-PrivilegedRoles
    Test-GuestUserSettings
    Test-MFAConfiguration
    Test-IdentityProtection
    Test-ApplicationRegistrations
    Test-DeviceCompliance
    Test-NamedLocations
    Test-SignInLogs
    
    # Run Enhanced Essential 8 assessments with maturity levels
    Write-Host "`n" + "="*60 -ForegroundColor Magenta
    Write-Host "ENHANCED ESSENTIAL 8 SECURITY FRAMEWORK ASSESSMENT" -ForegroundColor Magenta
    Write-Host "="*60 -ForegroundColor Magenta
    Write-Host "Assessing maturity levels (1-3) for each Essential 8 strategy..." -ForegroundColor Gray
    
    # Try to import enhanced modules
    try {
        Import-Module ".\modules\Enhanced-Essential8-Assessments.psm1" -Force -ErrorAction Stop
        Import-Module ".\modules\Enhanced-Essential8-Part2.psm1" -Force -ErrorAction Stop
        Write-Host "✅ Enhanced Essential 8 modules loaded" -ForegroundColor Green
        
        # Run enhanced assessments with maturity levels
        Write-Host "Running Enhanced Essential 8 assessments..." -ForegroundColor Gray
        Test-Essential8-ApplicationControl-Enhanced
        Test-Essential8-PatchApplications-Enhanced
        Test-Essential8-OfficeMacroSettings-Enhanced
        Test-Essential8-UserApplicationHardening-Enhanced
        Test-Essential8-RestrictAdminPrivileges-Enhanced
        Test-Essential8-PatchOperatingSystems-Enhanced
        Test-Essential8-MultiFactor-Enhanced
        Test-Essential8-RegularBackups-Enhanced
        
        # Debug: Check if Global scope has been populated
        Write-Host "Debug: Checking Global Essential8Results after enhanced assessments..." -ForegroundColor Yellow
        if ($Global:Essential8Results) {
            foreach ($strategy in $Global:Essential8Results.Keys) {
                $maturity = if ($Global:Essential8Results[$strategy].ContainsKey('MaturityLevel')) {
                    $Global:Essential8Results[$strategy].MaturityLevel
                } else {
                    "Unknown"
                }
                Write-Host "  $strategy : Maturity Level $maturity" -ForegroundColor Gray
            }
        } else {
            Write-Host "  No Global Essential8Results found!" -ForegroundColor Red
        }
        
        # Calculate Enhanced Essential 8 compliance score
        try {
            $essential8Score = Calculate-Essential8Score-Enhanced
        }
        catch {
            Write-Warning "Enhanced scoring failed. Using basic calculation."
            $essential8Score = Calculate-Essential8Score
        }
    }
    catch {
        Write-Warning "Enhanced Essential 8 modules not found. Using basic assessments."
        Test-Essential8-ApplicationControl
        Test-Essential8-PatchApplications
        Test-Essential8-OfficeMacroSettings
        Test-Essential8-UserApplicationHardening
        Test-Essential8-RestrictAdminPrivileges
        Test-Essential8-PatchOperatingSystems
        Test-Essential8-MultiFactor
        Test-Essential8-RegularBackups
        
        # Calculate basic Essential 8 compliance score
        $essential8Score = Calculate-Essential8Score
    }
    
    # Generate reports
    Write-Host "`n" + "="*60 -ForegroundColor Yellow
    Write-Host "REPORT GENERATION" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Yellow
    
    Generate-HtmlReport -OutputPath $Global:FinalOutputPath
    
    # Show summary with Essential 8 integration
    Show-Summary
    
    Write-Host "`nEssential 8 Compliance Summary:" -ForegroundColor White
    if ($essential8Score) {
        Write-Host "  Compliance Level: $($essential8Score.CompliancePercentage)% ($($essential8Score.CompliantCategories)/$($essential8Score.TotalCategories) categories)" -ForegroundColor $(
            if ($essential8Score.CompliancePercentage -ge 75) { "Green" }
            elseif ($essential8Score.CompliancePercentage -ge 50) { "Yellow" }  
            else { "Red" }
        )
        if ($essential8Score.PartiallyCompliant -gt 0) {
            Write-Host "  Partially Compliant: $($essential8Score.PartiallyCompliant) categories need improvement" -ForegroundColor Yellow
        }
    }

    Write-Host "`nNext Steps:" -ForegroundColor White
    Write-Host "  1. Review the detailed HTML report: $script:FinalOutputPath" -ForegroundColor Gray
    Write-Host "  2. Address critical and high priority findings first" -ForegroundColor Gray
    Write-Host "  3. Focus on Essential 8 gaps for comprehensive security" -ForegroundColor Gray
    Write-Host "  4. Implement recommended security improvements" -ForegroundColor Gray
    Write-Host "  5. Schedule regular security assessments" -ForegroundColor Gray
    
    Write-Host "`n🎉 Security assessment completed successfully!" -ForegroundColor Green
    Write-Host "📁 Modular architecture makes this tool easy to maintain and extend" -ForegroundColor Gray
}

# Execute the assessment
Start-SecurityAssessment 