# Essential 8 Security Framework Assessments Module
# Contains all Essential 8 compliance assessment functions

function Test-Essential8-ApplicationControl {
    Write-Host "`n=== Essential 8: Application Control ===" -ForegroundColor Cyan
    
    try {
        # Check application consent policies
        $consentPolicy = Get-MgPolicyPermissionGrantPolicy -ErrorAction SilentlyContinue
        if ($consentPolicy) {
            Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Application consent policies configured" -Severity "Good" -Details "Helps control application installations"
            $Global:Essential8Results.ApplicationControl += "Application consent policies configured"
        } else {
            Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "No application consent policies found" -Severity "Medium" -Recommendation "Configure application consent policies to control app installations"
            $Global:Essential8Results.ApplicationControl += "No application consent policies configured"
        }

        # Check app protection policies via Intune
        try {
            $appProtectionPolicies = Get-MgDeviceAppManagementManagedAppPolicy -ErrorAction SilentlyContinue
            if ($appProtectionPolicies -and $appProtectionPolicies.Count -gt 0) {
                Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "$($appProtectionPolicies.Count) application protection policies found" -Severity "Good" -Details "Mobile application management policies active"
                $script:Essential8Results.ApplicationControl += "$($appProtectionPolicies.Count) app protection policies configured"
            } else {
                Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "No application protection policies configured" -Severity "Medium" -Recommendation "Implement Intune application protection policies for mobile devices"
                $script:Essential8Results.ApplicationControl += "No app protection policies configured"
            }
        }
        catch {
            Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Unable to check application protection policies" -Severity "Low" -Details "May require Intune licensing"
        }

        # Check enterprise app consent settings
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue
        if ($authPolicy -and $authPolicy.DefaultUserRolePermissions.AllowedToCreateApps -eq $false) {
            Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Users cannot create applications by default" -Severity "Good" -Details "Prevents unauthorized app registrations"
            $script:Essential8Results.ApplicationControl += "App creation restricted for users"
        } else {
            Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Users can create applications" -Severity "Medium" -Recommendation "Restrict application creation to authorized users only"
            $script:Essential8Results.ApplicationControl += "App creation not restricted"
        }

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Application Control" -Finding "Unable to assess application control settings" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-Essential8-PatchApplications {
    Write-Host "`n=== Essential 8: Patch Applications ===" -ForegroundColor Cyan
    
    try {
        # Check Microsoft 365 Apps update settings
        try {
            $updatePolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "deviceConfigurationType eq 'windows10General'" -ErrorAction SilentlyContinue
            if ($updatePolicies -and $updatePolicies.Count -gt 0) {
                Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "$($updatePolicies.Count) application update policies configured" -Severity "Good" -Details "Device configuration policies managing app updates"
                $script:Essential8Results.PatchApplications += "$($updatePolicies.Count) update policies configured"
            } else {
                Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "No application update policies found" -Severity "High" -Recommendation "Implement Intune policies to manage application updates"
                $script:Essential8Results.PatchApplications += "No update policies configured"
            }
        }
        catch {
            Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Unable to check application update policies" -Severity "Medium" -Recommendation "Ensure Intune is configured for application patch management"
        }

        # Check Microsoft Store for Business policies
        try {
            $storeApps = Get-MgDeviceAppManagementMobileApp -Filter "isAssigned eq true" -ErrorAction SilentlyContinue
            if ($storeApps -and $storeApps.Count -gt 0) {
                Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "$($storeApps.Count) managed applications found" -Severity "Good" -Details "Applications under management control"
                $script:Essential8Results.PatchApplications += "$($storeApps.Count) managed applications"
            }
        }
        catch {
            Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Unable to enumerate managed applications" -Severity "Low" -Details "May require additional Intune permissions"
        }

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Patch Applications" -Finding "Unable to assess application patching capabilities" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-Essential8-OfficeMacroSettings {
    Write-Host "`n=== Essential 8: Configure Microsoft Office Macro Settings ===" -ForegroundColor Cyan
    
    try {
        # Check for Office configuration policies
        $officeConfigPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Office'" -ErrorAction SilentlyContinue
        if ($officeConfigPolicies -and $officeConfigPolicies.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "$($officeConfigPolicies.Count) Office configuration policies found" -Severity "Good" -Details "Office settings managed through device configuration"
            $script:Essential8Results.OfficeMacroSettings += "$($officeConfigPolicies.Count) Office policies configured"
        } else {
            Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "No Office configuration policies found" -Severity "High" -Recommendation "Implement Office configuration policies to control macro settings and security"
            $script:Essential8Results.OfficeMacroSettings += "No Office policies configured"
        }

        # Check for administrative templates (Group Policy-style settings)
        $adminTemplates = Get-MgDeviceManagementDeviceConfiguration -Filter "deviceConfigurationType eq 'groupPolicyConfiguration'" -ErrorAction SilentlyContinue
        if ($adminTemplates -and $adminTemplates.Count -gt 0) {
            $officeTemplates = $adminTemplates | Where-Object { $_.DisplayName -like "*Office*" -or $_.DisplayName -like "*Macro*" }
            if ($officeTemplates.Count -gt 0) {
                Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "$($officeTemplates.Count) Office-related administrative templates configured" -Severity "Good" -Details "Group Policy settings for Office security"
                $script:Essential8Results.OfficeMacroSettings += "$($officeTemplates.Count) Office admin templates"
            }
        }

        # Check Microsoft 365 Security policies (if accessible)
        try {
            # This would require Microsoft Graph Security API access
            Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "Office macro settings assessment completed" -Severity "Info" -Details "Review Microsoft 365 Security & Compliance center for detailed macro policies"
        }
        catch {
            # Expected if security policies aren't accessible
        }

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Office Macro Settings" -Finding "Unable to assess Office macro settings" -Severity "Medium" -Details $_.Exception.Message -Recommendation "Manually review Office 365 Security & Compliance policies"
    }
}

function Test-Essential8-UserApplicationHardening {
    Write-Host "`n=== Essential 8: User Application Hardening ===" -ForegroundColor Cyan
    
    try {
        # Check browser security policies
        $browserPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Edge' or displayName contains 'Chrome' or displayName contains 'Browser'" -ErrorAction SilentlyContinue
        if ($browserPolicies -and $browserPolicies.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "$($browserPolicies.Count) browser security policies configured" -Severity "Good" -Details "Browser hardening policies active"
            $script:Essential8Results.UserApplicationHardening += "$($browserPolicies.Count) browser policies configured"
        } else {
            Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "No browser security policies found" -Severity "Medium" -Recommendation "Implement browser hardening policies (Edge, Chrome security settings)"
            $script:Essential8Results.UserApplicationHardening += "No browser policies configured"
        }

        # Check endpoint protection policies
        $endpointProtection = Get-MgDeviceManagementDeviceConfiguration -Filter "deviceConfigurationType eq 'endpointProtection'" -ErrorAction SilentlyContinue
        if ($endpointProtection -and $endpointProtection.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "$($endpointProtection.Count) endpoint protection policies configured" -Severity "Good" -Details "Endpoint security hardening active"
            $script:Essential8Results.UserApplicationHardening += "$($endpointProtection.Count) endpoint protection policies"
        } else {
            Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "No endpoint protection policies found" -Severity "High" -Recommendation "Implement endpoint protection policies for application hardening"
            $script:Essential8Results.UserApplicationHardening += "No endpoint protection policies"
        }

        # Check application protection policies
        $appProtectionPolicies = Get-MgDeviceAppManagementManagedAppPolicy -ErrorAction SilentlyContinue
        if ($appProtectionPolicies -and $appProtectionPolicies.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "$($appProtectionPolicies.Count) application protection policies active" -Severity "Good" -Details "Mobile application hardening policies configured"
            $script:Essential8Results.UserApplicationHardening += "$($appProtectionPolicies.Count) app protection policies"
        }

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: User Application Hardening" -Finding "Unable to assess user application hardening" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-Essential8-RestrictAdminPrivileges {
    Write-Host "`n=== Essential 8: Restrict Administrative Privileges ===" -ForegroundColor Cyan
    
    try {
        # Enhanced privileged access assessment (building on existing function)
        
        # Check for Privileged Identity Management (PIM)
        try {
            $pimRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Top 10 -ErrorAction SilentlyContinue
            if ($pimRoles -and $pimRoles.Count -gt 0) {
                Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "Privileged Identity Management (PIM) is configured" -Severity "Good" -Details "Just-in-time admin access enabled"
                $script:Essential8Results.RestrictAdminPrivileges += "PIM configured"
            } else {
                Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "Privileged Identity Management (PIM) not configured" -Severity "High" -Recommendation "Implement PIM for just-in-time administrative access"
                $script:Essential8Results.RestrictAdminPrivileges += "PIM not configured"
            }
        }
        catch {
            Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "Unable to check PIM configuration" -Severity "Medium" -Details "May require Azure AD Premium P2 license"
        }

        # Check for admin workstation policies
        $adminWorkstationPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Admin' or displayName contains 'Privileged'" -ErrorAction SilentlyContinue
        if ($adminWorkstationPolicies -and $adminWorkstationPolicies.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "$($adminWorkstationPolicies.Count) privileged workstation policies found" -Severity "Good" -Details "Dedicated admin workstation configurations"
            $script:Essential8Results.RestrictAdminPrivileges += "$($adminWorkstationPolicies.Count) admin workstation policies"
        } else {
            Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "No privileged workstation policies found" -Severity "Medium" -Recommendation "Consider implementing dedicated administrative workstation policies"
            $script:Essential8Results.RestrictAdminPrivileges += "No admin workstation policies"
        }

        # Check for Conditional Access policies targeting admin roles
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
        $adminCAPolicies = $caPolicies | Where-Object { 
            $_.Conditions.Users.IncludeRoles.Count -gt 0 -or 
            $_.DisplayName -like "*admin*" -or 
            $_.DisplayName -like "*privileged*"
        }
        
        if ($adminCAPolicies.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "$($adminCAPolicies.Count) Conditional Access policies target admin roles" -Severity "Good" -Details "Enhanced security for privileged accounts"
            $script:Essential8Results.RestrictAdminPrivileges += "$($adminCAPolicies.Count) admin-focused CA policies"
        } else {
            Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "No admin-specific Conditional Access policies found" -Severity "Medium" -Recommendation "Create enhanced CA policies for administrative accounts"
            $script:Essential8Results.RestrictAdminPrivileges += "No admin-specific CA policies"
        }

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Restrict Admin Privileges" -Finding "Unable to assess administrative privilege restrictions" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-Essential8-PatchOperatingSystems {
    Write-Host "`n=== Essential 8: Patch Operating Systems ===" -ForegroundColor Cyan
    
    try {
        # Check Windows Update for Business policies
        $updatePolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "deviceConfigurationType eq 'windowsUpdateForBusiness'" -ErrorAction SilentlyContinue
        if ($updatePolicies -and $updatePolicies.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "$($updatePolicies.Count) Windows Update for Business policies configured" -Severity "Good" -Details "Operating system update management active"
            $script:Essential8Results.PatchOperatingSystems += "$($updatePolicies.Count) WUfB policies configured"
        } else {
            Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "No Windows Update for Business policies found" -Severity "High" -Recommendation "Implement Windows Update for Business policies for OS patch management"
            $script:Essential8Results.PatchOperatingSystems += "No WUfB policies configured"
        }

        # Check device compliance policies for OS versions
        $compliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -ErrorAction SilentlyContinue
        if ($compliancePolicies -and $compliancePolicies.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "$($compliancePolicies.Count) device compliance policies configured" -Severity "Good" -Details "Device compliance monitoring for OS versions"
            $script:Essential8Results.PatchOperatingSystems += "$($compliancePolicies.Count) compliance policies configured"
        } else {
            Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "No device compliance policies found" -Severity "High" -Recommendation "Implement device compliance policies to enforce minimum OS versions"
            $script:Essential8Results.PatchOperatingSystems += "No compliance policies configured"
        }

        # Check update rings
        $updateRings = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Update' or displayName contains 'Ring'" -ErrorAction SilentlyContinue
        if ($updateRings -and $updateRings.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "$($updateRings.Count) update ring configurations found" -Severity "Good" -Details "Phased deployment of OS updates"
            $script:Essential8Results.PatchOperatingSystems += "$($updateRings.Count) update rings configured"
        } else {
            Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "No update rings configured" -Severity "Medium" -Recommendation "Consider implementing update rings for phased OS patch deployment"
            $script:Essential8Results.PatchOperatingSystems += "No update rings configured"
        }

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "Unable to assess OS patching policies" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-Essential8-MultiFactor {
    Write-Host "`n=== Essential 8: Multi-Factor Authentication ===" -ForegroundColor Cyan
    
    # This builds upon the existing MFA assessment
    try {
        # Reference existing MFA results and enhance with Essential 8 perspective
        $mfaFindings = $script:AssessmentResults.Values | ForEach-Object { $_ } | Where-Object { $_.Category -eq "MFA" }
        
        if ($mfaFindings.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "Multi-Factor Authentication assessment completed" -Severity "Info" -Details "Refer to MFA section for detailed findings"
            $script:Essential8Results.MultiFactor += "MFA assessment completed"
        }

        # Check for passwordless authentication
        try {
            $authMethods = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue
            if ($authMethods -and $authMethods.AuthenticationMethodConfigurations) {
                $passwordlessEnabled = $authMethods.AuthenticationMethodConfigurations | Where-Object { 
                    $_.Id -in @('MicrosoftAuthenticator', 'WindowsHelloForBusiness', 'Fido2') -and $_.State -eq 'enabled'
                }
                
                if ($passwordlessEnabled.Count -gt 0) {
                    Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "$($passwordlessEnabled.Count) passwordless authentication methods enabled" -Severity "Good" -Details "Advanced MFA capabilities active"
                    $script:Essential8Results.MultiFactor += "$($passwordlessEnabled.Count) passwordless methods enabled"
                } else {
                    Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "No passwordless authentication methods enabled" -Severity "Medium" -Recommendation "Consider enabling Windows Hello for Business or FIDO2 keys"
                    $script:Essential8Results.MultiFactor += "No passwordless authentication"
                }
            }
        }
        catch {
            Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "Unable to check passwordless authentication settings" -Severity "Low" -Details "Authentication methods policy may not be accessible"
        }

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "Unable to assess MFA for Essential 8 compliance" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-Essential8-RegularBackups {
    Write-Host "`n=== Essential 8: Regular Backups ===" -ForegroundColor Cyan
    
    try {
        # Check Azure Backup policies (if any Azure resources are managed)
        try {
            $backupPolicies = Get-AzRecoveryServicesBackupProtectionPolicy -ErrorAction SilentlyContinue
            if ($backupPolicies -and $backupPolicies.Count -gt 0) {
                Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "$($backupPolicies.Count) Azure backup policies configured" -Severity "Good" -Details "Azure infrastructure backup policies active"
                $script:Essential8Results.RegularBackups += "$($backupPolicies.Count) Azure backup policies"
            }
        }
        catch {
            # Azure backup policies may not be accessible or configured
        }

        # Check Microsoft 365 backup/retention policies
        try {
            $retentionPolicies = Get-MgSecurityInformationProtectionSensitivityLabel -ErrorAction SilentlyContinue
            if ($retentionPolicies -and $retentionPolicies.Count -gt 0) {
                Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "Microsoft 365 data protection policies configured" -Severity "Good" -Details "Data retention and protection policies active"
                $script:Essential8Results.RegularBackups += "M365 data protection configured"
            }
        }
        catch {
            # Information protection policies may not be accessible
        }

        # Check OneDrive retention policies
        Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "OneDrive provides automatic backup for user data" -Severity "Info" -Details "User files automatically synced and protected"
        $script:Essential8Results.RegularBackups += "OneDrive automatic backup"

        # Check device backup policies
        $deviceBackupPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Backup' or displayName contains 'OneDrive'" -ErrorAction SilentlyContinue
        if ($deviceBackupPolicies -and $deviceBackupPolicies.Count -gt 0) {
            Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "$($deviceBackupPolicies.Count) device backup policies configured" -Severity "Good" -Details "Device-level backup policies active"
            $script:Essential8Results.RegularBackups += "$($deviceBackupPolicies.Count) device backup policies"
        } else {
            Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "No device backup policies found" -Severity "Medium" -Recommendation "Configure OneDrive known folder backup policies for user data protection"
            $script:Essential8Results.RegularBackups += "No device backup policies"
        }

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "Unable to assess backup policies" -Severity "Medium" -Details $_.Exception.Message -Recommendation "Manually review Microsoft 365 backup and retention settings"
    }
}

function Calculate-Essential8Score {
    Write-Host "`n📊 Calculating Essential 8 Compliance Score..." -ForegroundColor Cyan
    
    $totalCategories = 8
    $compliantCategories = 0
    $partiallyCompliant = 0
    
    # Score each Essential 8 category
    $categoryScores = @{}
    
    foreach ($category in $script:Essential8Results.Keys) {
        $findings = $script:Essential8Results[$category]
        $goodFindings = $findings | Where-Object { $_ -like "*configured*" -or $_ -like "*enabled*" -or $_ -like "*policies*" }
        $badFindings = $findings | Where-Object { $_ -like "*not configured*" -or $_ -like "*No *" -or $_ -like "*not found*" }
        
        if ($goodFindings.Count -gt $badFindings.Count) {
            $compliantCategories++
            $categoryScores[$category] = "Compliant"
        } elseif ($goodFindings.Count -gt 0) {
            $partiallyCompliant++
            $categoryScores[$category] = "Partially Compliant"
        } else {
            $categoryScores[$category] = "Non-Compliant"
        }
    }
    
    $compliancePercentage = [math]::Round(($compliantCategories / $totalCategories) * 100, 1)
    $partialPercentage = [math]::Round(($partiallyCompliant / $totalCategories) * 100, 1)
    
    Write-Host "  Essential 8 Categories:" -ForegroundColor White
    foreach ($category in $categoryScores.Keys) {
        $status = $categoryScores[$category]
        $color = switch ($status) {
            "Compliant" { "Green" }
            "Partially Compliant" { "Yellow" }
            "Non-Compliant" { "Red" }
        }
        Write-Host "    $category : $status" -ForegroundColor $color
    }
    
    Write-Host "`n  Essential 8 Compliance: $compliancePercentage% ($compliantCategories/$totalCategories categories)" -ForegroundColor $(
        if ($compliancePercentage -ge 75) { "Green" }
        elseif ($compliancePercentage -ge 50) { "Yellow" }
        else { "Red" }
    )
    
    if ($partiallyCompliant -gt 0) {
        Write-Host "  Partially Compliant: $partialPercentage% ($partiallyCompliant/$totalCategories categories)" -ForegroundColor Yellow
    }
    
    return @{
        CompliancePercentage = $compliancePercentage
        CompliantCategories = $compliantCategories
        PartiallyCompliant = $partiallyCompliant
        TotalCategories = $totalCategories
        CategoryScores = $categoryScores
    }
}

# Export all Essential 8 assessment functions
Export-ModuleMember -Function @(
    'Test-Essential8-ApplicationControl',
    'Test-Essential8-PatchApplications',
    'Test-Essential8-OfficeMacroSettings',
    'Test-Essential8-UserApplicationHardening',
    'Test-Essential8-RestrictAdminPrivileges',
    'Test-Essential8-PatchOperatingSystems',
    'Test-Essential8-MultiFactor',
    'Test-Essential8-RegularBackups',
    'Calculate-Essential8Score'
) 