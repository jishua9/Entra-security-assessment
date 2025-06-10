<#
.SYNOPSIS
    Azure Entra Tenant Security Assessment Script

.DESCRIPTION
    This script performs a comprehensive security assessment of an Azure Entra tenant,
    analyzing various security settings, policies, and configurations to provide
    a detailed health report. It will automatically install required modules if missing.

.NOTES
    Author: Security Assessment Tool
    Version: 1.0
    Requires: Az PowerShell modules and Microsoft Graph PowerShell modules
#>

param(
    [string]$OutputPath = ".\Azure-Entra-Security-Report.html",
    [switch]$DetailedOutput
)

# Required modules for the assessment
$script:RequiredModules = @(
    'Az.Accounts',
    'Az.Resources', 
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.DeviceManagement'
)

function Test-RequiredModules {
    Write-Host "Checking required modules..." -ForegroundColor Cyan
    
    $missingModules = @()
    foreach ($module in $script:RequiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Host "Missing modules detected: $($missingModules -join ', ')" -ForegroundColor Yellow
        Write-Host "Running setup script to install missing modules..." -ForegroundColor Yellow
        
        # Check if setup script exists
        $setupScript = ".\setup-requirements.ps1"
        if (!(Test-Path $setupScript)) {
            Write-Error "Setup script not found: $setupScript"
            Write-Host "Please ensure setup-requirements.ps1 is in the same directory as this script." -ForegroundColor Red
            return $false
        }
        
        # Run setup script
        try {
            Write-Host "Executing: $setupScript" -ForegroundColor Gray
            & $setupScript
            
            # Verify modules are now installed
            $stillMissing = @()
            foreach ($module in $missingModules) {
                if (!(Get-Module -ListAvailable -Name $module)) {
                    $stillMissing += $module
                }
            }
            
            if ($stillMissing.Count -gt 0) {
                Write-Error "Failed to install modules: $($stillMissing -join ', ')"
                Write-Host "Please run setup-requirements.ps1 manually or install modules with:" -ForegroundColor Red
                Write-Host "Install-Module -Name $($stillMissing -join ', ') -Scope CurrentUser" -ForegroundColor Gray
                return $false
            }
            
            Write-Host "All required modules are now installed!" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to run setup script: $_"
            return $false
        }
    } else {
        Write-Host "All required modules are available!" -ForegroundColor Green
    }
    
    return $true
}

# Color coding for console output
$script:Colors = @{
    'Critical' = 'Red'
    'High' = 'Magenta' 
    'Medium' = 'Yellow'
    'Low' = 'Cyan'
    'Good' = 'Green'
    'Info' = 'White'
}

# Assessment results storage
$script:AssessmentResults = @{
    'Critical' = @()
    'High' = @()
    'Medium' = @()
    'Low' = @()
    'Good' = @()
    'Info' = @()
}

function Write-AssessmentResult {
    param(
        [string]$Category,
        [string]$Finding,
        [string]$Severity,
        [string]$Recommendation = "",
        [string]$Details = ""
    )
    
    $result = @{
        Category = $Category
        Finding = $Finding
        Severity = $Severity
        Recommendation = $Recommendation
        Details = $Details
        Timestamp = Get-Date
    }
    
    $script:AssessmentResults[$Severity] += $result
    
    $color = $script:Colors[$Severity]
    Write-Host "[$Severity] ${Category}: $Finding" -ForegroundColor $color
    if ($Recommendation) {
        Write-Host "  -> Recommendation: $Recommendation" -ForegroundColor Gray
    }
    if ($DetailedOutput -and $Details) {
        Write-Host "  -> Details: $Details" -ForegroundColor Gray
    }
}

function Connect-ToAzureServices {
    Write-Host "`n=== Connecting to Azure Services ===" -ForegroundColor Cyan
    
    # Check for conflicting modules
    Write-Host "Checking for module conflicts..." -ForegroundColor Yellow
    $azureRMModules = Get-Module -ListAvailable -Name AzureRM*
    if ($azureRMModules.Count -gt 0) {
        Write-Host "WARNING: AzureRM modules detected. These can conflict with Az modules." -ForegroundColor Red
        Write-Host "Consider removing AzureRM modules: Uninstall-AzureRm" -ForegroundColor Yellow
    }
    
    # Disconnect any existing sessions to ensure clean connection
    try {
        Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Ignore errors when disconnecting
    }
    
    # Import required modules explicitly
    try {
        Write-Host "Importing Az.Accounts module..." -ForegroundColor Yellow
        Import-Module Az.Accounts -Force -ErrorAction Stop
        
        Write-Host "Importing Microsoft.Graph.Authentication module..." -ForegroundColor Yellow
        Import-Module Microsoft.Graph.Authentication -Force -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to import required modules: $_"
        return $false
    }
    
    # Connect to Azure with interactive browser authentication
    try {
        Write-Host "Connecting to Azure..." -ForegroundColor Yellow
        Write-Host "A browser window will open for authentication..." -ForegroundColor Gray
        
        # Use browser authentication instead of device code for better reliability
        $azContext = Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to Azure as $($azContext.Context.Account.Id)" -ForegroundColor Green
        
        # Get tenant information
        $tenantInfo = Get-AzTenant | Select-Object -First 1
        if ($tenantInfo) {
            Write-Host "Tenant: $($tenantInfo.Name) ($($tenantInfo.Id))" -ForegroundColor Green
        }
        
    }
    catch {
        Write-Error "Failed to connect to Azure: $_"
        Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
        Write-Host "1. Ensure you have the latest Az modules: Update-Module Az" -ForegroundColor Gray
        Write-Host "2. Clear any cached credentials: Clear-AzContext -Force" -ForegroundColor Gray
        Write-Host "3. Remove conflicting modules: Uninstall-AzureRm" -ForegroundColor Gray
        return $false
    }
    
    # Connect to Microsoft Graph
    try {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        $graphScopes = @(
            'Directory.Read.All',
            'Policy.Read.All', 
            'UserAuthenticationMethod.Read.All',
            'IdentityRiskEvent.Read.All',
            'IdentityRiskyUser.Read.All',
            'RoleManagement.Read.All',
            'DeviceManagementConfiguration.Read.All',
            'User.Read.All',
            'Group.Read.All'
        )
        
        # Use browser authentication for Graph as well
        Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop
        Write-Host "Connected to Microsoft Graph" -ForegroundColor Green
        
        # Verify Graph connection
        $context = Get-MgContext
        if ($context) {
            Write-Host "Graph Context: $($context.Account) in $($context.TenantId)" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        Write-Host "Graph connection failed. Some assessments may not work." -ForegroundColor Yellow
        Write-Host "Ensure you have admin permissions and the required licenses." -ForegroundColor Gray
        return $false
    }
    
    return $true
}

function Test-SecurityDefaults {
    Write-Host "`n=== Checking Security Defaults ===" -ForegroundColor Cyan
    
    try {
        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        
        if ($securityDefaults.IsEnabled) {
            Write-AssessmentResult -Category "Security Defaults" -Finding "Security Defaults are enabled" -Severity "Good" -Details "Provides baseline security for the tenant"
        } else {
            Write-AssessmentResult -Category "Security Defaults" -Finding "Security Defaults are disabled" -Severity "Medium" -Recommendation "Consider enabling Security Defaults if not using Conditional Access policies"
        }
    }
    catch {
        Write-AssessmentResult -Category "Security Defaults" -Finding "Unable to retrieve Security Defaults status" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-ConditionalAccessPolicies {
    Write-Host "`n=== Analyzing Conditional Access Policies ===" -ForegroundColor Cyan
    
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy
        
        if ($caPolicies.Count -eq 0) {
            Write-AssessmentResult -Category "Conditional Access" -Finding "No Conditional Access policies found" -Severity "High" -Recommendation "Implement Conditional Access policies for enhanced security"
        } else {
            Write-AssessmentResult -Category "Conditional Access" -Finding "$($caPolicies.Count) Conditional Access policies found" -Severity "Info"
            
            $enabledPolicies = $caPolicies | Where-Object { $_.State -eq 'enabled' }
            $disabledPolicies = $caPolicies | Where-Object { $_.State -eq 'disabled' }
            
            Write-AssessmentResult -Category "Conditional Access" -Finding "$($enabledPolicies.Count) policies enabled, $($disabledPolicies.Count) policies disabled" -Severity "Info"
            
            # Check for MFA enforcement
            $mfaPolicies = $caPolicies | Where-Object { 
                $_.GrantControls.BuiltInControls -contains 'mfa' -and $_.State -eq 'enabled'
            }
            
            if ($mfaPolicies.Count -gt 0) {
                Write-AssessmentResult -Category "Conditional Access" -Finding "$($mfaPolicies.Count) policies enforce MFA" -Severity "Good"
            } else {
                Write-AssessmentResult -Category "Conditional Access" -Finding "No policies found that enforce MFA" -Severity "High" -Recommendation "Create Conditional Access policies that require MFA for users"
            }
            
            # Check for device compliance requirements
            $devicePolicies = $caPolicies | Where-Object { 
                $_.GrantControls.BuiltInControls -contains 'compliantDevice' -and $_.State -eq 'enabled'
            }
            
            if ($devicePolicies.Count -gt 0) {
                Write-AssessmentResult -Category "Conditional Access" -Finding "$($devicePolicies.Count) policies require device compliance" -Severity "Good"
            } else {
                Write-AssessmentResult -Category "Conditional Access" -Finding "No policies require device compliance" -Severity "Medium" -Recommendation "Consider requiring device compliance for accessing corporate resources"
            }
        }
    }
    catch {
        Write-AssessmentResult -Category "Conditional Access" -Finding "Unable to retrieve Conditional Access policies" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-PasswordPolicy {
    Write-Host "`n=== Analyzing Password Policies ===" -ForegroundColor Cyan
    
    try {
        $domainPasswordPolicy = Get-MgDomain | Select-Object -First 1 | Get-MgDomainPasswordValidationPolicy -ErrorAction SilentlyContinue
        
        # Check password protection settings
        $org = Get-MgOrganization
        $authMethods = Get-MgPolicyAuthenticationMethodPolicy
        
        if ($authMethods.PolicyVersion -eq 'v2') {
            Write-AssessmentResult -Category "Password Policy" -Finding "Authentication methods policy v2 is enabled" -Severity "Good"
        } else {
            Write-AssessmentResult -Category "Password Policy" -Finding "Authentication methods policy v1 is in use" -Severity "Medium" -Recommendation "Consider upgrading to v2 authentication methods policy"
        }
        
        # Check for password protection
        $passwordProtection = Get-MgDirectoryOnPremisesSynchronization -ErrorAction SilentlyContinue
        if ($passwordProtection) {
            Write-AssessmentResult -Category "Password Policy" -Finding "On-premises password protection may be configured" -Severity "Info"
        }
    }
    catch {
        Write-AssessmentResult -Category "Password Policy" -Finding "Unable to fully analyze password policies" -Severity "Low" -Details $_.Exception.Message
    }
}

function Test-PrivilegedRoles {
    Write-Host "`n=== Analyzing Privileged Role Assignments ===" -ForegroundColor Cyan
    
    try {
        # Get directory roles
        $directoryRoles = Get-MgDirectoryRole
        $privilegedRoles = @(
            'Global Administrator',
            'Privileged Role Administrator', 
            'User Administrator',
            'Security Administrator',
            'Conditional Access Administrator',
            'Exchange Administrator',
            'SharePoint Administrator',
            'Application Administrator'
        )
        
        foreach ($role in $directoryRoles) {
            if ($privilegedRoles -contains $role.DisplayName) {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
                
                if ($members.Count -gt 5) {
                    Write-AssessmentResult -Category "Privileged Roles" -Finding "$($role.DisplayName) has $($members.Count) members" -Severity "Medium" -Recommendation "Review and minimize privileged role assignments"
                } elseif ($members.Count -eq 0) {
                    Write-AssessmentResult -Category "Privileged Roles" -Finding "$($role.DisplayName) has no members" -Severity "High" -Recommendation "Ensure at least one break-glass admin account is assigned"
                } else {
                    Write-AssessmentResult -Category "Privileged Roles" -Finding "$($role.DisplayName) has $($members.Count) members" -Severity "Good"
                }
            }
        }
    }
    catch {
        Write-AssessmentResult -Category "Privileged Roles" -Finding "Unable to analyze privileged role assignments" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-GuestUserSettings {
    Write-Host "`n=== Analyzing Guest User Settings ===" -ForegroundColor Cyan
    
    try {
        $org = Get-MgOrganization
        $authorizationPolicy = Get-MgPolicyAuthorizationPolicy
        
        if ($authorizationPolicy.AllowedToCreateApps -eq $false) {
            Write-AssessmentResult -Category "Guest Users" -Finding "Guest users cannot create applications" -Severity "Good"
        } else {
            Write-AssessmentResult -Category "Guest Users" -Finding "Guest users can create applications" -Severity "Medium" -Recommendation "Consider restricting guest users from creating applications"
        }
        
        if ($authorizationPolicy.AllowedToCreateSecurityGroups -eq $false) {
            Write-AssessmentResult -Category "Guest Users" -Finding "Guest users cannot create security groups" -Severity "Good"
        } else {
            Write-AssessmentResult -Category "Guest Users" -Finding "Guest users can create security groups" -Severity "Medium" -Recommendation "Consider restricting guest users from creating security groups"
        }
        
        # Check guest invite settings
        if ($authorizationPolicy.AllowInvitesFrom -eq 'adminsAndGuestInvitors') {
            Write-AssessmentResult -Category "Guest Users" -Finding "Only admins and guest inviters can invite guests" -Severity "Good"
        } elseif ($authorizationPolicy.AllowInvitesFrom -eq 'everyone') {
            Write-AssessmentResult -Category "Guest Users" -Finding "All users can invite guests" -Severity "Medium" -Recommendation "Consider restricting guest invitations to admins only"
        }
    }
    catch {
        Write-AssessmentResult -Category "Guest Users" -Finding "Unable to analyze guest user settings" -Severity "Low" -Details $_.Exception.Message
    }
}

function Test-MFAConfiguration {
    Write-Host "`n=== Analyzing Multi-Factor Authentication ===" -ForegroundColor Cyan
    
    try {
        # Get users and their MFA status
        $users = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,AccountEnabled" | Where-Object { $_.AccountEnabled -eq $true }
        $totalUsers = $users.Count
        $mfaEnabledUsers = 0
        
        # This is a simplified check - in practice, you might want to check authentication methods
        foreach ($user in $users | Select-Object -First 100) { # Limit for performance
            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
                if ($authMethods.Count -gt 1) { # More than just password
                    $mfaEnabledUsers++
                }
            }
            catch {
                # User might not have MFA configured
            }
        }
        
        $mfaPercentage = if ($totalUsers -gt 0) { [math]::Round(($mfaEnabledUsers / [math]::Min($totalUsers, 100)) * 100, 2) } else { 0 }
        
        if ($mfaPercentage -ge 90) {
            Write-AssessmentResult -Category "MFA" -Finding "$mfaPercentage% of sampled users have MFA configured" -Severity "Good"
        } elseif ($mfaPercentage -ge 70) {
            Write-AssessmentResult -Category "MFA" -Finding "$mfaPercentage% of sampled users have MFA configured" -Severity "Medium" -Recommendation "Increase MFA adoption across the organization"
        } else {
            Write-AssessmentResult -Category "MFA" -Finding "$mfaPercentage% of sampled users have MFA configured" -Severity "High" -Recommendation "Implement mandatory MFA for all users"
        }
        
        Write-AssessmentResult -Category "MFA" -Finding "Total active users in tenant: $totalUsers" -Severity "Info"
    }
    catch {
        Write-AssessmentResult -Category "MFA" -Finding "Unable to analyze MFA configuration" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-IdentityProtection {
    Write-Host "`n=== Checking Identity Protection ===" -ForegroundColor Cyan
    
    try {
        # Check for risky users
        $riskyUsers = Get-MgIdentityProtectionRiskyUser -Top 10
        
        if ($riskyUsers.Count -gt 0) {
            $highRiskUsers = $riskyUsers | Where-Object { $_.RiskLevel -eq 'high' }
            if ($highRiskUsers.Count -gt 0) {
                Write-AssessmentResult -Category "Identity Protection" -Finding "$($highRiskUsers.Count) high-risk users detected" -Severity "High" -Recommendation "Review and remediate high-risk users immediately"
            }
            
            Write-AssessmentResult -Category "Identity Protection" -Finding "$($riskyUsers.Count) risky users found in recent activity" -Severity "Medium" -Recommendation "Review risky users and consider remediation actions"
        } else {
            Write-AssessmentResult -Category "Identity Protection" -Finding "No risky users detected in recent activity" -Severity "Good"
        }
        
        # Check for risk events
        $riskEvents = Get-MgIdentityProtectionRiskDetection -Top 10
        if ($riskEvents.Count -gt 0) {
            Write-AssessmentResult -Category "Identity Protection" -Finding "$($riskEvents.Count) recent risk detections found" -Severity "Info" -Details "Recent risk events detected in the tenant"
        }
    }
    catch {
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Premium*") {
            Write-AssessmentResult -Category "Identity Protection" -Finding "Identity Protection features not available" -Severity "Medium" -Recommendation "Consider upgrading to Azure AD Premium P2 for Identity Protection features"
        } else {
            Write-AssessmentResult -Category "Identity Protection" -Finding "Unable to check Identity Protection status" -Severity "Low" -Details $_.Exception.Message
        }
    }
}

function Generate-HtmlReport {
    param([string]$OutputPath)
    
    Write-Host "`n=== Generating HTML Report ===" -ForegroundColor Cyan
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Entra Security Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { background-color: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .finding { margin: 15px 0; padding: 15px; border-radius: 5px; border-left: 4px solid; }
        .critical { background-color: #fadbd8; border-color: #e74c3c; }
        .high { background-color: #fdeaea; border-color: #e91e63; }
        .medium { background-color: #fef9e7; border-color: #f39c12; }
        .low { background-color: #eaf2f8; border-color: #3498db; }
        .good { background-color: #eafaf1; border-color: #27ae60; }
        .info { background-color: #f8f9fa; border-color: #6c757d; }
        .severity { font-weight: bold; text-transform: uppercase; }
        .recommendation { font-style: italic; color: #555; margin-top: 8px; }
        .details { font-size: 0.9em; color: #666; margin-top: 5px; }
        .stats { display: flex; justify-content: space-around; flex-wrap: wrap; }
        .stat-box { text-align: center; padding: 15px; margin: 10px; border-radius: 5px; min-width: 120px; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Entra Security Assessment Report</h1>
        <div class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="stats">
                <div class="stat-box critical">
                    <h3>$($script:AssessmentResults.Critical.Count)</h3>
                    <p>Critical Issues</p>
                </div>
                <div class="stat-box high">
                    <h3>$($script:AssessmentResults.High.Count)</h3>
                    <p>High Priority</p>
                </div>
                <div class="stat-box medium">
                    <h3>$($script:AssessmentResults.Medium.Count)</h3>
                    <p>Medium Priority</p>
                </div>
                <div class="stat-box low">
                    <h3>$($script:AssessmentResults.Low.Count)</h3>
                    <p>Low Priority</p>
                </div>
                <div class="stat-box good">
                    <h3>$($script:AssessmentResults.Good.Count)</h3>
                    <p>Good Practices</p>
                </div>
            </div>
        </div>
"@

    # Add findings by severity
    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Good', 'Info')) {
        if ($script:AssessmentResults[$severity].Count -gt 0) {
            $html += "<h2>$severity Priority Findings</h2>`n"
            
            foreach ($finding in $script:AssessmentResults[$severity]) {
                $html += "<div class='finding $($severity.ToLower())'>`n"
                $html += "<div class='severity'>[$severity]</div>`n"
                $html += "<strong>$($finding.Category):</strong> $($finding.Finding)`n"
                
                if ($finding.Recommendation) {
                    $html += "<div class='recommendation'>Recommendation: $($finding.Recommendation)</div>`n"
                }
                
                if ($finding.Details) {
                    $html += "<div class='details'>Details: $($finding.Details)</div>`n"
                }
                
                $html += "</div>`n"
            }
        }
    }

    $html += @"
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "HTML report generated: $OutputPath" -ForegroundColor Green
}

function Show-Summary {
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "AZURE ENTRA SECURITY ASSESSMENT SUMMARY" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    $totalFindings = $script:AssessmentResults.Critical.Count + $script:AssessmentResults.High.Count + $script:AssessmentResults.Medium.Count + $script:AssessmentResults.Low.Count
    
    Write-Host "`nFindings Summary:" -ForegroundColor White
    Write-Host "  Critical Issues: $($script:AssessmentResults.Critical.Count)" -ForegroundColor Red
    Write-Host "  High Priority:   $($script:AssessmentResults.High.Count)" -ForegroundColor Magenta
    Write-Host "  Medium Priority: $($script:AssessmentResults.Medium.Count)" -ForegroundColor Yellow
    Write-Host "  Low Priority:    $($script:AssessmentResults.Low.Count)" -ForegroundColor Cyan
    Write-Host "  Good Practices:  $($script:AssessmentResults.Good.Count)" -ForegroundColor Green
    Write-Host "  Total Issues:    $totalFindings" -ForegroundColor White
    
    if ($script:AssessmentResults.Critical.Count -gt 0) {
        Write-Host "`nIMMEDIATE ACTION REQUIRED - Critical security issues found!" -ForegroundColor Red
    } elseif ($script:AssessmentResults.High.Count -gt 0) {
        Write-Host "`nHigh priority security issues require attention" -ForegroundColor Magenta
    } elseif ($totalFindings -eq 0) {
        Write-Host "`nNo security issues identified in this assessment" -ForegroundColor Green
    } else {
        Write-Host "`nNo critical issues found, but some improvements recommended" -ForegroundColor Green
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor White
    Write-Host "  1. Review the detailed HTML report: $OutputPath" -ForegroundColor Gray
    Write-Host "  2. Address critical and high priority findings first" -ForegroundColor Gray
    Write-Host "  3. Implement recommended security improvements" -ForegroundColor Gray
    Write-Host "  4. Schedule regular security assessments" -ForegroundColor Gray
}

# Main execution
function Start-SecurityAssessment {
    Write-Host "Azure Entra Tenant Security Assessment Tool" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
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
    
    # Run security assessments
    Test-SecurityDefaults
    Test-ConditionalAccessPolicies
    Test-PasswordPolicy
    Test-PrivilegedRoles
    Test-GuestUserSettings
    Test-MFAConfiguration
    Test-IdentityProtection
    
    # Generate reports
    Generate-HtmlReport -OutputPath $OutputPath
    Show-Summary
    
    Write-Host "`nSecurity assessment completed successfully!" -ForegroundColor Green
}

# Execute the assessment
Start-SecurityAssessment