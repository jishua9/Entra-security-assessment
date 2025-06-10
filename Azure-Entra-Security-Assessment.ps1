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
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Reports'
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
            'Group.Read.All',
            'Application.Read.All',
            'AuditLog.Read.All',
            'Device.Read.All'
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

function Test-ApplicationRegistrations {
    Write-Host "`n=== Analyzing Application Registrations ===" -ForegroundColor Cyan
    
    try {
        $applications = Get-MgApplication -All
        Write-AssessmentResult -Category "Applications" -Finding "$($applications.Count) application registrations found" -Severity "Info"
        
        # Check for applications with expiring secrets/certificates
        $expiringSecrets = @()
        $expiredSecrets = @()
        $expiringCerts = @()
        $expiredCerts = @()
        $orphanedApps = @()
        
        $currentDate = Get-Date
        
        foreach ($app in $applications) {
            # Check owners
            try {
                $owners = Get-MgApplicationOwner -ApplicationId $app.Id -ErrorAction SilentlyContinue
                if ($owners.Count -eq 0) {
                    $orphanedApps += $app
                }
            }
            catch {
                # Assume orphaned if we can't check owners
                $orphanedApps += $app
            }
            
            # Check password credentials (secrets)
            if ($app.PasswordCredentials) {
                foreach ($cred in $app.PasswordCredentials) {
                    if ($cred.EndDateTime) {
                        $daysUntilExpiry = ($cred.EndDateTime - $currentDate).Days
                        if ($daysUntilExpiry -lt 0) {
                            $expiredSecrets += @{ App = $app.DisplayName; DaysOverdue = [Math]::Abs($daysUntilExpiry) }
                        } elseif ($daysUntilExpiry -le 30) {
                            $expiringSecrets += @{ App = $app.DisplayName; DaysLeft = $daysUntilExpiry }
                        }
                    }
                }
            }
            
            # Check key credentials (certificates)
            if ($app.KeyCredentials) {
                foreach ($cred in $app.KeyCredentials) {
                    if ($cred.EndDateTime) {
                        $daysUntilExpiry = ($cred.EndDateTime - $currentDate).Days
                        if ($daysUntilExpiry -lt 0) {
                            $expiredCerts += @{ App = $app.DisplayName; DaysOverdue = [Math]::Abs($daysUntilExpiry) }
                        } elseif ($daysUntilExpiry -le 30) {
                            $expiringCerts += @{ App = $app.DisplayName; DaysLeft = $daysUntilExpiry }
                        }
                    }
                }
            }
        }
        
        # Report findings
        if ($expiredSecrets.Count -gt 0) {
            Write-AssessmentResult -Category "Applications" -Finding "$($expiredSecrets.Count) applications have expired secrets" -Severity "High" -Recommendation "Renew expired application secrets immediately to prevent service disruption"
        }
        
        if ($expiredCerts.Count -gt 0) {
            Write-AssessmentResult -Category "Applications" -Finding "$($expiredCerts.Count) applications have expired certificates" -Severity "High" -Recommendation "Renew expired application certificates immediately"
        }
        
        if ($expiringSecrets.Count -gt 0) {
            Write-AssessmentResult -Category "Applications" -Finding "$($expiringSecrets.Count) applications have secrets expiring within 30 days" -Severity "Medium" -Recommendation "Plan renewal of application secrets before expiration"
        }
        
        if ($expiringCerts.Count -gt 0) {
            Write-AssessmentResult -Category "Applications" -Finding "$($expiringCerts.Count) applications have certificates expiring within 30 days" -Severity "Medium" -Recommendation "Plan renewal of application certificates before expiration"
        }
        
        if ($orphanedApps.Count -gt 0) {
            Write-AssessmentResult -Category "Applications" -Finding "$($orphanedApps.Count) applications have no assigned owners" -Severity "Medium" -Recommendation "Assign owners to applications for proper lifecycle management"
        }
        
        if ($expiredSecrets.Count -eq 0 -and $expiredCerts.Count -eq 0 -and $expiringSecrets.Count -eq 0 -and $expiringCerts.Count -eq 0) {
            Write-AssessmentResult -Category "Applications" -Finding "No application credentials expiring within 30 days" -Severity "Good"
        }
        
    }
    catch {
        Write-AssessmentResult -Category "Applications" -Finding "Unable to analyze application registrations" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-DeviceCompliance {
    Write-Host "`n=== Analyzing Device Compliance ===" -ForegroundColor Cyan
    
    try {
        $devices = Get-MgDevice -All
        Write-AssessmentResult -Category "Devices" -Finding "$($devices.Count) devices registered in the directory" -Severity "Info"
        
        if ($devices.Count -eq 0) {
            Write-AssessmentResult -Category "Devices" -Finding "No devices registered" -Severity "Medium" -Recommendation "Consider implementing device registration for enhanced security"
            return
        }
        
        $currentDate = Get-Date
        $staleDevices = @()
        $enabledDevices = @()
        $managedDevices = @()
        
        foreach ($device in $devices) {
            # Check if device is enabled
            if ($device.AccountEnabled) {
                $enabledDevices += $device
            }
            
            # Check for stale devices (no activity in 90 days)
            if ($device.ApproximateLastSignInDateTime) {
                $daysSinceLastSignIn = ($currentDate - $device.ApproximateLastSignInDateTime).Days
                if ($daysSinceLastSignIn -gt 90) {
                    $staleDevices += $device
                }
            }
            
            # Check if device is managed (has management type)
            if ($device.ManagementType -or $device.IsCompliant) {
                $managedDevices += $device
            }
        }
        
        # Calculate percentages
        $enabledPercentage = if ($devices.Count -gt 0) { [math]::Round(($enabledDevices.Count / $devices.Count) * 100, 2) } else { 0 }
        $managedPercentage = if ($devices.Count -gt 0) { [math]::Round(($managedDevices.Count / $devices.Count) * 100, 2) } else { 0 }
        
        # Report findings
        Write-AssessmentResult -Category "Devices" -Finding "$($enabledDevices.Count) devices are enabled ($enabledPercentage%)" -Severity "Info"
        
        if ($staleDevices.Count -gt 0) {
            $stalePercentage = [math]::Round(($staleDevices.Count / $devices.Count) * 100, 2)
            if ($stalePercentage -gt 20) {
                Write-AssessmentResult -Category "Devices" -Finding "$($staleDevices.Count) devices are stale (>90 days inactive, $stalePercentage%)" -Severity "Medium" -Recommendation "Clean up stale device objects to maintain directory hygiene"
            } else {
                Write-AssessmentResult -Category "Devices" -Finding "$($staleDevices.Count) devices are stale (>90 days inactive, $stalePercentage%)" -Severity "Low" -Recommendation "Consider periodic cleanup of inactive devices"
            }
        } else {
            Write-AssessmentResult -Category "Devices" -Finding "No stale devices detected" -Severity "Good"
        }
        
        if ($managedPercentage -ge 80) {
            Write-AssessmentResult -Category "Devices" -Finding "$($managedDevices.Count) devices are managed ($managedPercentage%)" -Severity "Good"
        } elseif ($managedPercentage -ge 50) {
            Write-AssessmentResult -Category "Devices" -Finding "$($managedDevices.Count) devices are managed ($managedPercentage%)" -Severity "Medium" -Recommendation "Increase device management coverage for better security"
        } else {
            Write-AssessmentResult -Category "Devices" -Finding "$($managedDevices.Count) devices are managed ($managedPercentage%)" -Severity "High" -Recommendation "Implement device management solution to ensure compliance"
        }
        
    }
    catch {
        Write-AssessmentResult -Category "Devices" -Finding "Unable to analyze device compliance" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-NamedLocations {
    Write-Host "`n=== Analyzing Named Locations ===" -ForegroundColor Cyan
    
    try {
        $namedLocations = Get-MgIdentityConditionalAccessNamedLocation
        
        if ($namedLocations.Count -eq 0) {
            Write-AssessmentResult -Category "Named Locations" -Finding "No named locations configured" -Severity "Medium" -Recommendation "Configure named locations to enhance Conditional Access policies with location-based controls"
        } else {
            Write-AssessmentResult -Category "Named Locations" -Finding "$($namedLocations.Count) named locations configured" -Severity "Info"
            
            $trustedLocations = $namedLocations | Where-Object { $_.IsTrusted -eq $true }
            $ipBasedLocations = $namedLocations | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.ipNamedLocation' }
            $countryLocations = $namedLocations | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.countryNamedLocation' }
            
            if ($trustedLocations.Count -gt 0) {
                Write-AssessmentResult -Category "Named Locations" -Finding "$($trustedLocations.Count) trusted locations defined" -Severity "Info" -Details "Trusted locations can skip MFA requirements"
            }
            
            if ($ipBasedLocations.Count -gt 0) {
                Write-AssessmentResult -Category "Named Locations" -Finding "$($ipBasedLocations.Count) IP-based locations configured" -Severity "Good"
            }
            
            if ($countryLocations.Count -gt 0) {
                Write-AssessmentResult -Category "Named Locations" -Finding "$($countryLocations.Count) country-based locations configured" -Severity "Good"
            }
            
            # Check if named locations are being used in CA policies
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
            $policiesUsingLocations = $caPolicies | Where-Object { 
                $_.Conditions.Locations.IncludeLocations.Count -gt 0 -or $_.Conditions.Locations.ExcludeLocations.Count -gt 0 
            }
            
            if ($policiesUsingLocations.Count -gt 0) {
                Write-AssessmentResult -Category "Named Locations" -Finding "$($policiesUsingLocations.Count) Conditional Access policies use location conditions" -Severity "Good"
            } else {
                Write-AssessmentResult -Category "Named Locations" -Finding "Named locations exist but are not used in Conditional Access policies" -Severity "Medium" -Recommendation "Leverage named locations in Conditional Access policies for location-based security"
            }
        }
        
    }
    catch {
        Write-AssessmentResult -Category "Named Locations" -Finding "Unable to analyze named locations" -Severity "Low" -Details $_.Exception.Message
    }
}

function Test-SignInLogs {
    Write-Host "`n=== Analyzing Sign-in Patterns (Last 7 Days) ===" -ForegroundColor Cyan
    
    try {
        # Get sign-ins from last 7 days
        $startDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $startDate" -Top 1000
        
        if ($signIns.Count -eq 0) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "No sign-in logs available for analysis" -Severity "Low" -Details "May require Azure AD Premium license or recent activity"
            return
        }
        
        Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($signIns.Count) sign-in events analyzed (last 7 days)" -Severity "Info"
        
        # Analyze failed sign-ins
        $failedSignIns = $signIns | Where-Object { $_.Status.ErrorCode -ne 0 }
        $failedPercentage = if ($signIns.Count -gt 0) { [math]::Round(($failedSignIns.Count / $signIns.Count) * 100, 2) } else { 0 }
        
        if ($failedPercentage -gt 20) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($failedSignIns.Count) failed sign-ins ($failedPercentage%)" -Severity "High" -Recommendation "Investigate high failure rate - possible attack or configuration issues"
        } elseif ($failedPercentage -gt 10) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($failedSignIns.Count) failed sign-ins ($failedPercentage%)" -Severity "Medium" -Recommendation "Monitor failed sign-in patterns for potential security issues"
        } else {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($failedSignIns.Count) failed sign-ins ($failedPercentage%)" -Severity "Good"
        }
        
        # Check for legacy authentication
        $legacyAuth = $signIns | Where-Object { 
            $_.ClientAppUsed -in @('Exchange ActiveSync', 'Other clients', 'IMAP', 'MAPI', 'POP', 'SMTP') -or
            $_.ClientAppUsed -like '*Legacy*'
        }
        
        if ($legacyAuth.Count -gt 0) {
            $legacyPercentage = [math]::Round(($legacyAuth.Count / $signIns.Count) * 100, 2)
            if ($legacyPercentage -gt 5) {
                Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($legacyAuth.Count) legacy authentication attempts ($legacyPercentage%)" -Severity "High" -Recommendation "Block legacy authentication protocols - they bypass MFA and modern security controls"
            } else {
                Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($legacyAuth.Count) legacy authentication attempts ($legacyPercentage%)" -Severity "Medium" -Recommendation "Consider blocking remaining legacy authentication usage"
            }
        } else {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "No legacy authentication detected" -Severity "Good"
        }
        
        # Check for impossible travel (basic analysis)
        $uniqueUsers = $signIns | Group-Object -Property UserId
        $suspiciousTravel = 0
        
        foreach ($userGroup in $uniqueUsers) {
            $userSignIns = $userGroup.Group | Sort-Object CreatedDateTime
            for ($i = 1; $i -lt $userSignIns.Count; $i++) {
                $prevSignIn = $userSignIns[$i-1]
                $currentSignIn = $userSignIns[$i]
                
                if ($prevSignIn.Location.CountryOrRegion -and $currentSignIn.Location.CountryOrRegion) {
                    if ($prevSignIn.Location.CountryOrRegion -ne $currentSignIn.Location.CountryOrRegion) {
                        $timeDiff = $currentSignIn.CreatedDateTime - $prevSignIn.CreatedDateTime
                        if ($timeDiff.TotalHours -lt 2) {
                            $suspiciousTravel++
                        }
                    }
                }
            }
        }
        
        if ($suspiciousTravel -gt 0) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$suspiciousTravel potential impossible travel events detected" -Severity "Medium" -Recommendation "Review sign-ins with rapid geographic changes - may indicate compromised accounts"
        }
        
        # Check geographic distribution
        $countries = $signIns | Where-Object { $_.Location.CountryOrRegion } | Group-Object -Property { $_.Location.CountryOrRegion } | Sort-Object Count -Descending
        if ($countries.Count -gt 10) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "Sign-ins from $($countries.Count) different countries" -Severity "Medium" -Recommendation "Monitor geographic sign-in patterns for unusual activity"
        } elseif ($countries.Count -gt 0) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "Sign-ins from $($countries.Count) countries" -Severity "Info" -Details "Top countries: $($countries[0..2].Name -join ', ')"
        }
        
    }
    catch {
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Premium*") {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "Sign-in logs not accessible" -Severity "Low" -Recommendation "Azure AD Premium license may be required for detailed sign-in analytics"
        } else {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "Unable to analyze sign-in logs" -Severity "Low" -Details $_.Exception.Message
        }
    }
}

function Calculate-RiskScore {
    $totalFindings = $script:AssessmentResults.Critical.Count + $script:AssessmentResults.High.Count + 
                    $script:AssessmentResults.Medium.Count + $script:AssessmentResults.Low.Count
    
    if ($totalFindings -eq 0) {
        return @{ Score = 100; Level = "EXCELLENT" }
    }
    
    # Weighted scoring: Critical = 25 points, High = 15, Medium = 8, Low = 3
    $totalDeductions = ($script:AssessmentResults.Critical.Count * 25) + 
                      ($script:AssessmentResults.High.Count * 15) + 
                      ($script:AssessmentResults.Medium.Count * 8) + 
                      ($script:AssessmentResults.Low.Count * 3)
    
    $score = [Math]::Max(0, 100 - $totalDeductions)
    
    $level = if ($score -ge 90) { "EXCELLENT" }
            elseif ($score -ge 75) { "GOOD" }
            elseif ($score -ge 60) { "FAIR" }
            elseif ($score -ge 40) { "POOR" }
            else { "CRITICAL" }
    
    return @{ Score = $score; Level = $level }
}

function Generate-KeyInsights {
    $insights = @()
    $totalUsers = ($script:AssessmentResults.Info | Where-Object { $_.Category -eq "MFA" -and $_.Finding -like "*Total active users*" }).Finding
    $totalApps = ($script:AssessmentResults.Info | Where-Object { $_.Category -eq "Applications" -and $_.Finding -like "*application registrations found*" }).Finding
    $totalDevices = ($script:AssessmentResults.Info | Where-Object { $_.Category -eq "Devices" -and $_.Finding -like "*devices registered*" }).Finding
    $totalPolicies = ($script:AssessmentResults.Info | Where-Object { $_.Category -eq "Conditional Access" -and $_.Finding -like "*Conditional Access policies found*" }).Finding
    
    if ($totalUsers) {
        $userCount = ($totalUsers -split ': ')[1]
        $insights += "<div class='insight-item'><div class='insight-value'>$userCount</div><div class='insight-label'>Active Users</div></div>"
    }
    
    if ($totalApps) {
        $appCount = ($totalApps -split ' ')[0]
        $insights += "<div class='insight-item'><div class='insight-value'>$appCount</div><div class='insight-label'>Applications</div></div>"
    }
    
    if ($totalDevices) {
        $deviceCount = ($totalDevices -split ' ')[0]
        $insights += "<div class='insight-item'><div class='insight-value'>$deviceCount</div><div class='insight-label'>Registered Devices</div></div>"
    }
    
    if ($totalPolicies) {
        $policyCount = ($totalPolicies -split ' ')[0]
        $insights += "<div class='insight-item'><div class='insight-value'>$policyCount</div><div class='insight-label'>CA Policies</div></div>"
    }
    
    return $insights -join "`n"
}

function Generate-RemediationActions {
    param($Finding)
    
    $actions = @()
    
    # Add specific PowerShell commands based on finding type
    switch -Wildcard ($Finding.Finding) {
        "*Security Defaults are disabled*" {
            $actions += "# Enable Security Defaults`nUpdate-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled `$true"
        }
        "*No Conditional Access policies*" {
            $actions += "# Create a basic MFA policy via Azure Portal`n# Navigate to: Azure AD > Security > Conditional Access > New Policy"
        }
        "*expired secrets*" {
            $actions += "# Find applications with expired secrets`nGet-MgApplication | Where-Object { `$_.PasswordCredentials.EndDateTime -lt (Get-Date) }"
        }
        "*stale devices*" {
            $actions += "# Remove stale devices (>90 days inactive)`nGet-MgDevice | Where-Object { `$_.ApproximateLastSignInDateTime -lt (Get-Date).AddDays(-90) } | Remove-MgDevice"
        }
        "*legacy authentication*" {
            $actions += "# Block legacy authentication via Conditional Access`n# Create CA policy targeting legacy authentication protocols"
        }
    }
    
    return $actions -join "`n"
}

function Generate-HtmlReport {
    param([string]$OutputPath)
    
    Write-Host "`n=== Generating Enhanced HTML Report ===" -ForegroundColor Cyan
    
    # Check if template exists
    $templatePath = ".\report-template.html"
    if (!(Test-Path $templatePath)) {
        Write-Warning "Template file not found at $templatePath. Using basic template."
        Generate-BasicHtmlReport -OutputPath $OutputPath
        return
    }
    
    # Read template
    $template = Get-Content $templatePath -Raw
    
    # Calculate risk score
    $riskData = Calculate-RiskScore
    
    # Generate insights
    $insights = Generate-KeyInsights
    
    # Generate findings content
    $findingsContent = ""
    
    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Good', 'Info')) {
        if ($script:AssessmentResults[$severity].Count -gt 0) {
            $sectionId = "section-$($severity.ToLower())"
            $findingsContent += @"
            <div class="findings-section">
                <div class="section-header" data-section="$sectionId" data-severity="$severity" onclick="toggleSection('$sectionId')">
                    <div>
                        <span class="section-title">$severity Priority Findings</span>
                    </div>
                    <div>
                        <span class="section-count">$($script:AssessmentResults[$severity].Count)</span>
                        <span class="expand-icon">▶</span>
                    </div>
                </div>
                <div class="section-content" id="$sectionId">
"@
            
            foreach ($finding in $script:AssessmentResults[$severity]) {
                $remediationActions = Generate-RemediationActions -Finding $finding
                
                $findingsContent += @"
                <div class="finding $($severity.ToLower())" style="border-left-color: $(
                    switch ($severity) {
                        'Critical' { '#e74c3c' }
                        'High' { '#e91e63' }
                        'Medium' { '#f39c12' }
                        'Low' { '#3498db' }
                        'Good' { '#27ae60' }
                        'Info' { '#6c757d' }
                    }
                );">
                    <div class="finding-header">
                        <span class="severity-badge $($severity.ToLower())">$severity</span>
                    </div>
                    <div class="finding-title">$($finding.Category): $($finding.Finding)</div>
"@
                
                if ($finding.Recommendation) {
                    $findingsContent += @"
                    <div class="recommendation">
                        <div class="recommendation-title">💡 Recommendation</div>
                        $($finding.Recommendation)
                    </div>
"@
                }
                
                if ($finding.Details) {
                    $findingsContent += "<div class='details'>ℹ️ $($finding.Details)</div>"
                }
                
                if ($remediationActions) {
                    $findingsContent += @"
                    <div class="remediation-actions">
                        <div class="remediation-title">🔧 Remediation Actions</div>
                        <div class="powershell-command">$remediationActions</div>
                    </div>
"@
                }
                
                $findingsContent += "</div>"
            }
            
            $findingsContent += "</div></div>"
        }
    }
    
    # Replace template placeholders
    $html = $template -replace '{{TIMESTAMP}}', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $html = $html -replace '{{RISK_SCORE}}', $riskData.Score
    $html = $html -replace '{{RISK_LEVEL}}', $riskData.Level
    $html = $html -replace '{{CRITICAL_COUNT}}', $script:AssessmentResults.Critical.Count
    $html = $html -replace '{{HIGH_COUNT}}', $script:AssessmentResults.High.Count
    $html = $html -replace '{{MEDIUM_COUNT}}', $script:AssessmentResults.Medium.Count
    $html = $html -replace '{{LOW_COUNT}}', $script:AssessmentResults.Low.Count
    $html = $html -replace '{{GOOD_COUNT}}', $script:AssessmentResults.Good.Count
    $html = $html -replace '{{INSIGHTS_CONTENT}}', $insights
    $html = $html -replace '{{FINDINGS_CONTENT}}', $findingsContent
    
    # Write to file
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Enhanced HTML report generated: $OutputPath" -ForegroundColor Green
    Write-Host "Features: Interactive charts, risk scoring, remediation actions, export options" -ForegroundColor Gray
}

function Generate-BasicHtmlReport {
    param([string]$OutputPath)
    
    # Fallback basic HTML if template is missing
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Entra Security Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        .finding { margin: 15px 0; padding: 15px; border-radius: 5px; border-left: 4px solid; }
        .critical { background-color: #f77468; border-color: #e74c3c; }
        .high { background-color: #f8a0a0; border-color: #e91e63; }
        .medium { background-color: #ebd481; border-color: #f39c12; }
        .low { background-color: #b8e0ff; border-color: #3498db; }
        .good { background-color: #7bdda5; border-color: #27ae60; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Entra Security Assessment Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
"@

    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Good', 'Info')) {
        if ($script:AssessmentResults[$severity].Count -gt 0) {
            $html += "<h2>$severity Priority Findings ($($script:AssessmentResults[$severity].Count))</h2>"
            foreach ($finding in $script:AssessmentResults[$severity]) {
                $html += "<div class='finding $($severity.ToLower())'><strong>$($finding.Category):</strong> $($finding.Finding)</div>"
            }
        }
    }

    $html += "</div></body></html>"
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
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
    Test-ApplicationRegistrations
    Test-DeviceCompliance
    Test-NamedLocations
    Test-SignInLogs
    
    # Generate reports
    Generate-HtmlReport -OutputPath $OutputPath
    Show-Summary
    
    Write-Host "`nSecurity assessment completed successfully!" -ForegroundColor Green
}

# Execute the assessment
Start-SecurityAssessment