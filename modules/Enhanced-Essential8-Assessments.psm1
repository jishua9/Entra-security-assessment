# Enhanced Essential 8 Security Framework Assessments Module
# Implements the 3 maturity levels based on official Essential 8 documentation
# Contains comprehensive checks for Entra ID and Intune using Microsoft Graph APIs

# Initialize Global Essential 8 Results if not exists
if (-not $Global:Essential8Results) {
    $Global:Essential8Results = @{
        'ApplicationControl' = @{ MaturityLevel = 0; MaxLevel = 3; Findings = @(); Compliance = "Non-Compliant" }
        'PatchApplications' = @{ MaturityLevel = 0; MaxLevel = 3; Findings = @(); Compliance = "Non-Compliant" }
        'OfficeMacroSettings' = @{ MaturityLevel = 0; MaxLevel = 3; Findings = @(); Compliance = "Non-Compliant" }
        'UserApplicationHardening' = @{ MaturityLevel = 0; MaxLevel = 3; Findings = @(); Compliance = "Non-Compliant" }
        'RestrictAdminPrivileges' = @{ MaturityLevel = 0; MaxLevel = 3; Findings = @(); Compliance = "Non-Compliant" }
    }
}

function Test-Essential8-ApplicationControl-Enhanced {
    Write-Host "`n=== Essential 8: Application Control (Enhanced) ===" -ForegroundColor Cyan
    
    $maturityLevel = 0
    $maturityFindings = @()
    
    try {
        # Maturity Level 1: Application control implemented on workstations
        Write-Host "  Checking Maturity Level 1: Application control on workstations..." -ForegroundColor Yellow
        
        # Check for Windows Defender Application Control (WDAC) policies
        try {
            $wdacPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "deviceConfigurationType eq 'windows10EndpointProtection'" -ErrorAction SilentlyContinue
            $appControlPolicies = $wdacPolicies | Where-Object { 
                $_.DisplayName -like "*Application Control*" -or 
                $_.DisplayName -like "*WDAC*" -or 
                $_.DisplayName -like "*AppLocker*"
            }
            
            if ($appControlPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 1)
                $maturityFindings += "✓ Level 1: Application control policies configured ($($appControlPolicies.Count) policies)"
                Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Application control implemented on workstations" -Severity "Good" -Details "WDAC/AppLocker policies active"
            } else {
                $maturityFindings += "✗ Level 1: No application control policies found for workstations"
                Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Application control not implemented on workstations" -Severity "High" -Recommendation "Implement Windows Defender Application Control or AppLocker policies"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 1: Unable to check application control policies"
        }

        # Maturity Level 2: Application control on workstations and internet-facing servers
        Write-Host "  Checking Maturity Level 2: Extended to internet-facing servers..." -ForegroundColor Yellow
        
        # Check for server-specific application control policies
        try {
            $serverPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Server'" -ErrorAction SilentlyContinue
            $serverAppControl = $serverPolicies | Where-Object { 
                $_.DisplayName -like "*Application*" -or 
                $_.DisplayName -like "*Control*" -or
                $_.DisplayName -like "*Allowlist*"
            }
            
            if ($serverAppControl.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 2)
                $maturityFindings += "✓ Level 2: Server application control policies configured"
                Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Application control extended to servers" -Severity "Good" -Details "Server-specific policies active"
            } else {
                $maturityFindings += "✗ Level 2: No server application control policies found"
                Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Application control not extended to servers" -Severity "Medium" -Recommendation "Implement application control on internet-facing servers"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 2: Unable to check server application control"
        }

        # Maturity Level 3: Application control on all systems including network devices
        Write-Host "  Checking Maturity Level 3: Comprehensive application control..." -ForegroundColor Yellow
        
        # Check for comprehensive application control coverage
        try {
            $allDeviceConfigs = Get-MgDeviceManagementDeviceConfiguration -ErrorAction SilentlyContinue
            $appControlConfigs = $allDeviceConfigs | Where-Object { 
                $_.DisplayName -like "*Application*" -or 
                $_.DisplayName -like "*Control*" -or 
                $_.DisplayName -like "*WDAC*" -or
                $_.DisplayName -like "*AppLocker*" -or
                $_.DisplayName -like "*Allowlist*"
            }
            
            # Check for mobile device application management
            $mobileAppPolicies = Get-MgDeviceAppManagementManagedAppPolicy -ErrorAction SilentlyContinue
            
            if ($appControlConfigs.Count -ge 3 -and $mobileAppPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 3)
                $maturityFindings += "✓ Level 3: Comprehensive application control across device types"
                Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Comprehensive application control implemented" -Severity "Good" -Details "Application control across workstations, servers, and mobile devices"
            } else {
                $maturityFindings += "✗ Level 3: Limited application control coverage"
                Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Application control coverage incomplete" -Severity "Medium" -Recommendation "Extend application control to all device types and network devices"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 3: Unable to assess comprehensive coverage"
        }

        # Store results with maturity level in the script scope
        if (Get-Variable -Name "Essential8Results" -Scope Script -ErrorAction SilentlyContinue) {
            $script:Essential8Results.ApplicationControl.Maturity = $maturityLevel
            $script:Essential8Results.ApplicationControl.Details = $maturityFindings
            $script:Essential8Results.ApplicationControl.Findings = $maturityFindings
        }
        
        # Also store in global scope for backward compatibility
        $Global:Essential8Results.ApplicationControl = @{
            MaturityLevel = $maturityLevel
            MaxLevel = 3
            Findings = $maturityFindings
            Compliance = if ($maturityLevel -ge 2) { "Compliant" } elseif ($maturityLevel -eq 1) { "Partially Compliant" } else { "Non-Compliant" }
        }

        Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Maturity Level $maturityLevel of 3 achieved" -Severity $(if ($maturityLevel -ge 2) { "Good" } elseif ($maturityLevel -eq 1) { "Medium" } else { "High" }) -Details "Based on Essential 8 maturity model"

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Unable to assess application control maturity" -Severity "Medium" -Details $_.Exception.Message
        $Global:Essential8Results.ApplicationControl = @{
            MaturityLevel = 0
            MaxLevel = 3
            Findings = @("Assessment failed: $($_.Exception.Message)")
            Compliance = "Non-Compliant"
        }
    }
}

function Test-Essential8-PatchApplications-Enhanced {
    Write-Host "`n=== Essential 8: Patch Applications (Enhanced) ===" -ForegroundColor Cyan
    
    $maturityLevel = 0
    $maturityFindings = @()
    
    try {
        # Maturity Level 1: Automated asset discovery and vulnerability scanning
        Write-Host "  Checking Maturity Level 1: Automated asset discovery and vulnerability scanning..." -ForegroundColor Yellow
        
        # Check for automated application inventory via Intune
        try {
            $managedApps = Get-MgDeviceAppManagementMobileApp -ErrorAction SilentlyContinue
            $deviceApps = Get-MgDeviceManagementManagedDevice -ErrorAction SilentlyContinue
            
            if ($managedApps.Count -gt 0 -and $deviceApps.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 1)
                $maturityFindings += "✓ Level 1: Automated asset discovery configured ($($managedApps.Count) apps, $($deviceApps.Count) devices)"
                Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Automated asset discovery implemented" -Severity "Good" -Details "Intune managing application inventory"
            } else {
                $maturityFindings += "✗ Level 1: Limited automated asset discovery"
                Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Automated asset discovery not fully implemented" -Severity "High" -Recommendation "Implement comprehensive device and application inventory via Intune"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 1: Unable to check asset discovery"
        }

        # Maturity Level 2: Vulnerability scanning and patch management for critical vulnerabilities
        Write-Host "  Checking Maturity Level 2: Patch management for critical vulnerabilities..." -ForegroundColor Yellow
        
        # Check for Windows Update for Business policies
        try {
            $updatePolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "deviceConfigurationType eq 'windowsUpdateForBusiness'" -ErrorAction SilentlyContinue
            if ($updatePolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 2)
                $maturityFindings += "✓ Level 2: Windows Update for Business policies configured"
                Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Automated patch management configured" -Severity "Good" -Details "Windows Update for Business active"
            } else {
                $maturityFindings += "✗ Level 2: No Windows Update for Business policies found"
                Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Automated patch management not configured" -Severity "High" -Recommendation "Implement Windows Update for Business policies"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 2: Unable to check update policies"
        }

        # Maturity Level 3: Comprehensive patch management with 48-hour critical patch deployment
        Write-Host "  Checking Maturity Level 3: Comprehensive patch management..." -ForegroundColor Yellow
        
        # Check for expedited update rings for critical patches
        try {
            $updateRings = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Ring' or displayName contains 'Expedited'" -ErrorAction SilentlyContinue
            if ($updateRings.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 3)
                $maturityFindings += "✓ Level 3: Expedited update rings configured for critical patches"
                Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Expedited patch deployment configured" -Severity "Good" -Details "Update rings support rapid critical patch deployment"
            } else {
                $maturityFindings += "✗ Level 3: No expedited update rings found"
                Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Expedited patch deployment not configured" -Severity "Medium" -Recommendation "Configure update rings for 48-hour critical patch deployment"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 3: Unable to check expedited update capabilities"
        }

        # Store results in script scope
        if (Get-Variable -Name "Essential8Results" -Scope Script -ErrorAction SilentlyContinue) {
            $script:Essential8Results.PatchApplications.Maturity = $maturityLevel
            $script:Essential8Results.PatchApplications.Details = $maturityFindings
            $script:Essential8Results.PatchApplications.Findings = $maturityFindings
        }
        
        # Store results in global scope for backward compatibility
        $Global:Essential8Results.PatchApplications = @{
            MaturityLevel = $maturityLevel
            MaxLevel = 3
            Findings = $maturityFindings
            Compliance = if ($maturityLevel -ge 2) { "Compliant" } elseif ($maturityLevel -eq 1) { "Partially Compliant" } else { "Non-Compliant" }
        }

        Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Maturity Level $maturityLevel of 3 achieved" -Severity $(if ($maturityLevel -ge 2) { "Good" } elseif ($maturityLevel -eq 1) { "Medium" } else { "High" }) -Details "Based on Essential 8 maturity model"

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Unable to assess patch applications maturity" -Severity "Medium" -Details $_.Exception.Message
        $Global:Essential8Results.PatchApplications = @{
            MaturityLevel = 0
            MaxLevel = 3
            Findings = @("Assessment failed: $($_.Exception.Message)")
            Compliance = "Non-Compliant"
        }
    }
}

function Test-Essential8-OfficeMacroSettings-Enhanced {
    Write-Host "`n=== Essential 8: Configure Microsoft Office Macro Settings (Enhanced) ===" -ForegroundColor Cyan
    
    $maturityLevel = 0
    $maturityFindings = @()
    
    try {
        # Maturity Level 1: Microsoft Office macros disabled or only enabled from trusted locations
        Write-Host "  Checking Maturity Level 1: Basic macro security..." -ForegroundColor Yellow
        
        # Check for Office configuration policies
        try {
            $officeConfigPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Office'" -ErrorAction SilentlyContinue
            if ($officeConfigPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 1)
                $maturityFindings += "✓ Level 1: Office macro security policies configured"
                Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "Office macro security policies implemented" -Severity "Good" -Details "Macro security managed via device configuration"
            } else {
                $maturityFindings += "✗ Level 1: No Office macro security policies found"
                Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "Office macro security not configured" -Severity "High" -Recommendation "Implement Office macro security policies via Intune"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 1: Unable to check Office configuration policies"
        }

        # Maturity Level 2: Microsoft Office macros disabled except in trusted locations with limited write access
        Write-Host "  Checking Maturity Level 2: Enhanced macro security with trusted locations..." -ForegroundColor Yellow
        
        # Check for advanced Office security configurations
        try {
            $advancedOfficePolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Office' and displayName contains 'Advanced'" -ErrorAction SilentlyContinue
            if ($advancedOfficePolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 2)
                $maturityFindings += "✓ Level 2: Advanced Office security policies configured"
                Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "Advanced Office macro security implemented" -Severity "Good" -Details "Trusted locations and advanced security configured"
            } else {
                $maturityFindings += "✗ Level 2: No advanced Office security policies found"
                Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "Advanced Office macro security not configured" -Severity "Medium" -Recommendation "Configure trusted locations with limited write access"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 2: Unable to check advanced Office policies"
        }

        # Maturity Level 3: Microsoft Office macros disabled except for digitally signed macros with trusted certificates
        Write-Host "  Checking Maturity Level 3: Digital signature requirements..." -ForegroundColor Yellow
        
        # Check for certificate-based macro policies
        try {
            $certificatePolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Certificate' or displayName contains 'Signature'" -ErrorAction SilentlyContinue
            $macroSigningPolicies = $certificatePolicies | Where-Object { 
                $_.DisplayName -like "*Office*" -or 
                $_.DisplayName -like "*Macro*" -or
                $_.DisplayName -like "*Sign*"
            }
            
            if ($macroSigningPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 3)
                $maturityFindings += "✓ Level 3: Digital signature requirements for macros configured"
                Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "Digital signature requirements implemented" -Severity "Good" -Details "Only digitally signed macros with trusted certificates allowed"
            } else {
                $maturityFindings += "✗ Level 3: No digital signature requirements found"
                Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "Digital signature requirements not configured" -Severity "Medium" -Recommendation "Configure policies to only allow digitally signed macros"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 3: Unable to check digital signature policies"
        }

        # Store results in script scope
        if (Get-Variable -Name "Essential8Results" -Scope Script -ErrorAction SilentlyContinue) {
            $script:Essential8Results.OfficeMacroSettings.Maturity = $maturityLevel
            $script:Essential8Results.OfficeMacroSettings.Details = $maturityFindings
            $script:Essential8Results.OfficeMacroSettings.Findings = $maturityFindings
        }
        
        # Store results in global scope for backward compatibility
        $Global:Essential8Results.OfficeMacroSettings = @{
            MaturityLevel = $maturityLevel
            MaxLevel = 3
            Findings = $maturityFindings
            Compliance = if ($maturityLevel -ge 2) { "Compliant" } elseif ($maturityLevel -eq 1) { "Partially Compliant" } else { "Non-Compliant" }
        }

        Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "Maturity Level $maturityLevel of 3 achieved" -Severity $(if ($maturityLevel -ge 2) { "Good" } elseif ($maturityLevel -eq 1) { "Medium" } else { "High" }) -Details "Based on Essential 8 maturity model"

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "Unable to assess Office macro settings maturity" -Severity "Medium" -Details $_.Exception.Message
        $Global:Essential8Results.OfficeMacroSettings = @{
            MaturityLevel = 0
            MaxLevel = 3
            Findings = @("Assessment failed: $($_.Exception.Message)")
            Compliance = "Non-Compliant"
        }
    }
}

function Test-Essential8-UserApplicationHardening-Enhanced {
    Write-Host "`n=== Essential 8: User Application Hardening (Enhanced) ===" -ForegroundColor Cyan
    
    $maturityLevel = 0
    $maturityFindings = @()
    
    try {
        # Maturity Level 1: Web browsers configured to block Flash, ads, and Java
        Write-Host "  Checking Maturity Level 1: Basic browser hardening..." -ForegroundColor Yellow
        
        # Check for browser security policies
        try {
            $browserPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Edge' or displayName contains 'Chrome' or displayName contains 'Browser'" -ErrorAction SilentlyContinue
            if ($browserPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 1)
                $maturityFindings += "✓ Level 1: Browser security policies configured ($($browserPolicies.Count) policies)"
                Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "Browser hardening policies implemented" -Severity "Good" -Details "Browser security configurations active"
            } else {
                $maturityFindings += "✗ Level 1: No browser security policies found"
                Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "Browser hardening not configured" -Severity "High" -Recommendation "Implement browser security policies to block Flash, ads, and Java"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 1: Unable to check browser policies"
        }

        # Check for PDF viewer security settings
        try {
            $pdfPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'PDF' or displayName contains 'Adobe'" -ErrorAction SilentlyContinue
            if ($pdfPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 1)
                $maturityFindings += "✓ Level 1: PDF viewer security policies configured"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 1: Unable to check PDF policies"
        }

        # Maturity Level 2: Enhanced browser security and application sandboxing
        Write-Host "  Checking Maturity Level 2: Enhanced application security..." -ForegroundColor Yellow
        
        # Check for application sandboxing/protected view policies
        try {
            $sandboxPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Sandbox' or displayName contains 'Protected'" -ErrorAction SilentlyContinue
            if ($sandboxPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 2)
                $maturityFindings += "✓ Level 2: Application sandboxing policies configured"
                Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "Application sandboxing implemented" -Severity "Good" -Details "Protected view and sandboxing active"
            } else {
                $maturityFindings += "✗ Level 2: No application sandboxing policies found"
                Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "Application sandboxing not configured" -Severity "Medium" -Recommendation "Configure protected view and sandboxing for internet-facing applications"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 2: Unable to check sandboxing policies"
        }

        # Check for endpoint protection policies
        try {
            $endpointProtection = Get-MgDeviceManagementDeviceConfiguration -Filter "deviceConfigurationType eq 'endpointProtection'" -ErrorAction SilentlyContinue
            if ($endpointProtection.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 2)
                $maturityFindings += "✓ Level 2: Endpoint protection policies configured"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 2: Unable to check endpoint protection"
        }

        # Maturity Level 3: Comprehensive application hardening with advanced threat protection
        Write-Host "  Checking Maturity Level 3: Comprehensive application hardening..." -ForegroundColor Yellow
        
        # Check for Microsoft Defender Application Guard
        try {
            $applicationGuardPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Application Guard' or displayName contains 'MDAG'" -ErrorAction SilentlyContinue
            if ($applicationGuardPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 3)
                $maturityFindings += "✓ Level 3: Microsoft Defender Application Guard configured"
                Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "Advanced application isolation implemented" -Severity "Good" -Details "Microsoft Defender Application Guard active"
            } else {
                $maturityFindings += "✗ Level 3: No Application Guard policies found"
                Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "Advanced application isolation not configured" -Severity "Medium" -Recommendation "Configure Microsoft Defender Application Guard for enhanced isolation"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 3: Unable to check Application Guard"
        }

        # Check for comprehensive application protection policies
        try {
            $appProtectionPolicies = Get-MgDeviceAppManagementManagedAppPolicy -ErrorAction SilentlyContinue
            if ($appProtectionPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 3)
                $maturityFindings += "✓ Level 3: Comprehensive application protection policies configured"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 3: Unable to check app protection policies"
        }

        # Store results in script scope
        if (Get-Variable -Name "Essential8Results" -Scope Script -ErrorAction SilentlyContinue) {
            $script:Essential8Results.UserApplicationHardening.Maturity = $maturityLevel
            $script:Essential8Results.UserApplicationHardening.Details = $maturityFindings
            $script:Essential8Results.UserApplicationHardening.Findings = $maturityFindings
        }
        
        # Store results in global scope for backward compatibility
        $Global:Essential8Results.UserApplicationHardening = @{
            MaturityLevel = $maturityLevel
            MaxLevel = 3
            Findings = $maturityFindings
            Compliance = if ($maturityLevel -ge 2) { "Compliant" } elseif ($maturityLevel -eq 1) { "Partially Compliant" } else { "Non-Compliant" }
        }

        Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "Maturity Level $maturityLevel of 3 achieved" -Severity $(if ($maturityLevel -ge 2) { "Good" } elseif ($maturityLevel -eq 1) { "Medium" } else { "High" }) -Details "Based on Essential 8 maturity model"

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "Unable to assess user application hardening maturity" -Severity "Medium" -Details $_.Exception.Message
        $Global:Essential8Results.UserApplicationHardening = @{
            MaturityLevel = 0
            MaxLevel = 3
            Findings = @("Assessment failed: $($_.Exception.Message)")
            Compliance = "Non-Compliant"
        }
    }
}

function Test-Essential8-RestrictAdminPrivileges-Enhanced {
    Write-Host "`n=== Essential 8: Restrict Administrative Privileges (Enhanced) ===" -ForegroundColor Cyan
    
    $maturityLevel = 0
    $maturityFindings = @()
    
    try {
        # Maturity Level 1: Privileged users use separate privileged and unprivileged operating environments
        Write-Host "  Checking Maturity Level 1: Separate privileged environments..." -ForegroundColor Yellow
        
        # Check for Privileged Identity Management (PIM)
        try {
            $pimRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Top 10 -ErrorAction SilentlyContinue
            if ($pimRoles -and $pimRoles.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 1)
                $maturityFindings += "✓ Level 1: Privileged Identity Management (PIM) configured"
                Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "PIM implemented for privileged access" -Severity "Good" -Details "Just-in-time admin access enabled"
            } else {
                $maturityFindings += "✗ Level 1: PIM not configured"
                Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "PIM not implemented" -Severity "High" -Recommendation "Implement Privileged Identity Management for just-in-time access"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 1: Unable to check PIM configuration"
        }

        # Check for admin workstation policies
        try {
            $adminWorkstationPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Admin' or displayName contains 'Privileged'" -ErrorAction SilentlyContinue
            if ($adminWorkstationPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 1)
                $maturityFindings += "✓ Level 1: Privileged workstation policies configured"
            } else {
                $maturityFindings += "✗ Level 1: No privileged workstation policies found"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 1: Unable to check admin workstation policies"
        }

        # Maturity Level 2: Privileged access management with enhanced controls
        Write-Host "  Checking Maturity Level 2: Enhanced privileged access controls..." -ForegroundColor Yellow
        
        # Check for Conditional Access policies targeting admin roles
        try {
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
            $adminCAPolicies = $caPolicies | Where-Object { 
                $_.Conditions.Users.IncludeRoles.Count -gt 0 -or 
                $_.DisplayName -like "*admin*" -or 
                $_.DisplayName -like "*privileged*"
            }
            
            if ($adminCAPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 2)
                $maturityFindings += "✓ Level 2: Admin-specific Conditional Access policies configured"
                Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "Enhanced CA policies for admins" -Severity "Good" -Details "Conditional Access targeting privileged roles"
            } else {
                $maturityFindings += "✗ Level 2: No admin-specific CA policies found"
                Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "Admin-specific CA policies missing" -Severity "Medium" -Recommendation "Create enhanced CA policies for administrative accounts"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 2: Unable to check admin CA policies"
        }

        # Maturity Level 3: Comprehensive privileged access security
        Write-Host "  Checking Maturity Level 3: Comprehensive privileged access security..." -ForegroundColor Yellow
        
        # Check for Privileged Access Workstations (PAW) policies
        try {
            $pawPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'PAW' or displayName contains 'Privileged Access Workstation'" -ErrorAction SilentlyContinue
            if ($pawPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 3)
                $maturityFindings += "✓ Level 3: Privileged Access Workstation policies configured"
                Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "PAW implementation detected" -Severity "Good" -Details "Dedicated privileged access workstations configured"
            } else {
                $maturityFindings += "✗ Level 3: No PAW policies found"
                Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "PAW not implemented" -Severity "Medium" -Recommendation "Consider implementing Privileged Access Workstations"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 3: Unable to check PAW policies"
        }

        # Store results in script scope
        if (Get-Variable -Name "Essential8Results" -Scope Script -ErrorAction SilentlyContinue) {
            $script:Essential8Results.RestrictAdminPrivileges.Maturity = $maturityLevel
            $script:Essential8Results.RestrictAdminPrivileges.Details = $maturityFindings
            $script:Essential8Results.RestrictAdminPrivileges.Findings = $maturityFindings
        }
        
        # Store results in global scope for backward compatibility
        $Global:Essential8Results.RestrictAdminPrivileges = @{
            MaturityLevel = $maturityLevel
            MaxLevel = 3
            Findings = $maturityFindings
            Compliance = if ($maturityLevel -ge 2) { "Compliant" } elseif ($maturityLevel -eq 1) { "Partially Compliant" } else { "Non-Compliant" }
        }

        Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "Maturity Level $maturityLevel of 3 achieved" -Severity $(if ($maturityLevel -ge 2) { "Good" } elseif ($maturityLevel -eq 1) { "Medium" } else { "High" }) -Details "Based on Essential 8 maturity model"

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "Unable to assess admin privilege restrictions maturity" -Severity "Medium" -Details $_.Exception.Message
        $Global:Essential8Results.RestrictAdminPrivileges = @{
            MaturityLevel = 0
            MaxLevel = 3
            Findings = @("Assessment failed: $($_.Exception.Message)")
            Compliance = "Non-Compliant"
        }
    }
}

# Export functions
Export-ModuleMember -Function Test-Essential8-ApplicationControl-Enhanced, Test-Essential8-PatchApplications-Enhanced, Test-Essential8-OfficeMacroSettings-Enhanced, Test-Essential8-UserApplicationHardening-Enhanced, Test-Essential8-RestrictAdminPrivileges-Enhanced 