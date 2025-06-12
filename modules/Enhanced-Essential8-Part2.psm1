# Enhanced Essential 8 Security Framework Assessments Module - Part 2
# Contains the remaining 3 Essential 8 strategies with maturity level assessments

# Initialize Global Essential 8 Results if not exists (Part 2)
if (-not $Global:Essential8Results) {
    $Global:Essential8Results = @{}
}

# Add Part 2 strategies if not exists
if (-not $Global:Essential8Results.ContainsKey('PatchOperatingSystems')) {
    $Global:Essential8Results.PatchOperatingSystems = @{ MaturityLevel = 0; MaxLevel = 3; Findings = @(); Compliance = "Non-Compliant" }
}
if (-not $Global:Essential8Results.ContainsKey('MultiFactor')) {
    $Global:Essential8Results.MultiFactor = @{ MaturityLevel = 0; MaxLevel = 3; Findings = @(); Compliance = "Non-Compliant" }
}
if (-not $Global:Essential8Results.ContainsKey('RegularBackups')) {
    $Global:Essential8Results.RegularBackups = @{ MaturityLevel = 0; MaxLevel = 3; Findings = @(); Compliance = "Non-Compliant" }
}

function Test-Essential8-PatchOperatingSystems-Enhanced {
    Write-Host "`n=== Essential 8: Patch Operating Systems (Enhanced) ===" -ForegroundColor Cyan
    
    $maturityLevel = 0
    $maturityFindings = @()
    
    try {
        # Maturity Level 1: Automated asset discovery and vulnerability scanning for operating systems
        Write-Host "  Checking Maturity Level 1: OS asset discovery and vulnerability scanning..." -ForegroundColor Yellow
        
        # Check for device inventory and compliance
        try {
            $managedDevices = Get-MgDeviceManagementManagedDevice -ErrorAction SilentlyContinue
            $compliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -ErrorAction SilentlyContinue
            
            if ($managedDevices.Count -gt 0 -and $compliancePolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 1)
                $maturityFindings += "✓ Level 1: OS asset discovery and compliance monitoring configured ($($managedDevices.Count) devices, $($compliancePolicies.Count) policies)"
                Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "OS asset discovery and vulnerability scanning implemented" -Severity "Good" -Details "Device inventory and compliance policies active"
            } else {
                $maturityFindings += "✗ Level 1: Limited OS asset discovery or compliance monitoring"
                Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "OS asset discovery not fully implemented" -Severity "High" -Recommendation "Implement comprehensive device inventory and compliance monitoring"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 1: Unable to check OS asset discovery"
        }

        # Maturity Level 2: Vulnerability scanning and patch management for critical OS vulnerabilities
        Write-Host "  Checking Maturity Level 2: OS patch management for critical vulnerabilities..." -ForegroundColor Yellow
        
        # Check for Windows Update for Business policies
        try {
            $updatePolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "deviceConfigurationType eq 'windowsUpdateForBusiness'" -ErrorAction SilentlyContinue
            if ($updatePolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 2)
                $maturityFindings += "✓ Level 2: Windows Update for Business policies configured ($($updatePolicies.Count) policies)"
                Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "Automated OS patch management configured" -Severity "Good" -Details "Windows Update for Business managing OS updates"
            } else {
                $maturityFindings += "✗ Level 2: No Windows Update for Business policies found"
                Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "Automated OS patch management not configured" -Severity "High" -Recommendation "Implement Windows Update for Business policies for OS patching"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 2: Unable to check OS update policies"
        }

        # Maturity Level 3: Comprehensive OS patch management with 48-hour critical patch deployment
        Write-Host "  Checking Maturity Level 3: Comprehensive OS patch management..." -ForegroundColor Yellow
        
        # Check for expedited update rings for critical OS patches
        try {
            $updateRings = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Ring' or displayName contains 'Expedited' or displayName contains 'Critical'" -ErrorAction SilentlyContinue
            if ($updateRings.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 3)
                $maturityFindings += "✓ Level 3: Expedited OS update rings configured for critical patches"
                Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "Expedited OS patch deployment configured" -Severity "Good" -Details "Update rings support rapid critical OS patch deployment"
            } else {
                $maturityFindings += "✗ Level 3: No expedited OS update rings found"
                Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "Expedited OS patch deployment not configured" -Severity "Medium" -Recommendation "Configure update rings for 48-hour critical OS patch deployment"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 3: Unable to check expedited OS update capabilities"
        }

        # Store results in script scope
        if (Get-Variable -Name "Essential8Results" -Scope Script -ErrorAction SilentlyContinue) {
            $script:Essential8Results.PatchOperatingSystems.Maturity = $maturityLevel
            $script:Essential8Results.PatchOperatingSystems.Details = $maturityFindings
            $script:Essential8Results.PatchOperatingSystems.Findings = $maturityFindings
        }
        
        # Store results in global scope for backward compatibility
        $Global:Essential8Results.PatchOperatingSystems = @{
            MaturityLevel = $maturityLevel
            MaxLevel = 3
            Findings = $maturityFindings
            Compliance = if ($maturityLevel -ge 2) { "Compliant" } elseif ($maturityLevel -eq 1) { "Partially Compliant" } else { "Non-Compliant" }
        }

        Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "Maturity Level $maturityLevel of 3 achieved" -Severity $(if ($maturityLevel -ge 2) { "Good" } elseif ($maturityLevel -eq 1) { "Medium" } else { "High" }) -Details "Based on Essential 8 maturity model"

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: OS Patching" -Finding "Unable to assess OS patching maturity" -Severity "Medium" -Details $_.Exception.Message
        $Global:Essential8Results.PatchOperatingSystems = @{
            MaturityLevel = 0
            MaxLevel = 3
            Findings = @("Assessment failed: $($_.Exception.Message)")
            Compliance = "Non-Compliant"
        }
    }
}

function Test-Essential8-MultiFactor-Enhanced {
    Write-Host "`n=== Essential 8: Multi-Factor Authentication (Enhanced) ===" -ForegroundColor Cyan
    
    $maturityLevel = 0
    $maturityFindings = @()
    
    try {
        # Maturity Level 1: MFA enabled for privileged users and remote access
        Write-Host "  Checking Maturity Level 1: MFA for privileged users and remote access..." -ForegroundColor Yellow
        
        # Check for MFA enforcement via Conditional Access
        try {
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
            $mfaPolicies = $caPolicies | Where-Object { 
                $_.GrantControls.BuiltInControls -contains 'mfa' -and $_.State -eq 'enabled'
            }
            
            if ($mfaPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 1)
                $maturityFindings += "✓ Level 1: MFA enforcement policies configured ($($mfaPolicies.Count) policies)"
                Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "MFA enforcement implemented via Conditional Access" -Severity "Good" -Details "MFA policies active for user access"
            } else {
                $maturityFindings += "✗ Level 1: No MFA enforcement policies found"
                Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "MFA enforcement not configured" -Severity "High" -Recommendation "Implement Conditional Access policies requiring MFA"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 1: Unable to check MFA policies"
        }

        # Maturity Level 2: MFA for all users accessing important data repositories
        Write-Host "  Checking Maturity Level 2: MFA for all users accessing important data..." -ForegroundColor Yellow
        
        # Check for comprehensive MFA policies covering all users
        try {
            $allUserMFAPolicies = $caPolicies | Where-Object { 
                $_.GrantControls.BuiltInControls -contains 'mfa' -and 
                $_.State -eq 'enabled' -and
                ($_.Conditions.Users.IncludeUsers -contains 'All' -or $_.Conditions.Users.IncludeUsers.Count -eq 0)
            }
            
            if ($allUserMFAPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 2)
                $maturityFindings += "✓ Level 2: MFA policies covering all users configured"
                Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "Comprehensive MFA coverage implemented" -Severity "Good" -Details "MFA required for all user access to important data"
            } else {
                $maturityFindings += "✗ Level 2: MFA not required for all users"
                Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "Comprehensive MFA coverage missing" -Severity "Medium" -Recommendation "Extend MFA requirements to all users accessing important data"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 2: Unable to check comprehensive MFA coverage"
        }

        # Maturity Level 3: Phishing-resistant MFA for all users
        Write-Host "  Checking Maturity Level 3: Phishing-resistant MFA for all users..." -ForegroundColor Yellow
        
        # Check for passwordless/phishing-resistant authentication methods
        try {
            $authMethods = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue
            if ($authMethods -and $authMethods.AuthenticationMethodConfigurations) {
                $phishingResistantMethods = $authMethods.AuthenticationMethodConfigurations | Where-Object { 
                    $_.Id -in @('Fido2', 'WindowsHelloForBusiness', 'X509Certificate') -and $_.State -eq 'enabled'
                }
                
                if ($phishingResistantMethods.Count -gt 0) {
                    $maturityLevel = [Math]::Max($maturityLevel, 3)
                    $maturityFindings += "✓ Level 3: Phishing-resistant authentication methods enabled ($($phishingResistantMethods.Count) methods)"
                    Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "Phishing-resistant MFA implemented" -Severity "Good" -Details "FIDO2, Windows Hello, or certificate-based authentication available"
                } else {
                    $maturityFindings += "✗ Level 3: No phishing-resistant authentication methods enabled"
                    Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "Phishing-resistant MFA not implemented" -Severity "Medium" -Recommendation "Enable FIDO2 keys, Windows Hello for Business, or certificate-based authentication"
                }
            }
        }
        catch {
            $maturityFindings += "⚠ Level 3: Unable to check phishing-resistant authentication methods"
        }

        # Store results in script scope
        if (Get-Variable -Name "Essential8Results" -Scope Script -ErrorAction SilentlyContinue) {
            $script:Essential8Results.MultiFactor.Maturity = $maturityLevel
            $script:Essential8Results.MultiFactor.Details = $maturityFindings
            $script:Essential8Results.MultiFactor.Findings = $maturityFindings
        }
        
        # Store results in global scope for backward compatibility
        $Global:Essential8Results.MultiFactor = @{
            MaturityLevel = $maturityLevel
            MaxLevel = 3
            Findings = $maturityFindings
            Compliance = if ($maturityLevel -ge 2) { "Compliant" } elseif ($maturityLevel -eq 1) { "Partially Compliant" } else { "Non-Compliant" }
        }

        Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "Maturity Level $maturityLevel of 3 achieved" -Severity $(if ($maturityLevel -ge 2) { "Good" } elseif ($maturityLevel -eq 1) { "Medium" } else { "High" }) -Details "Based on Essential 8 maturity model"

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Multi-Factor Auth" -Finding "Unable to assess MFA maturity" -Severity "Medium" -Details $_.Exception.Message
        $Global:Essential8Results.MultiFactor = @{
            MaturityLevel = 0
            MaxLevel = 3
            Findings = @("Assessment failed: $($_.Exception.Message)")
            Compliance = "Non-Compliant"
        }
    }
}

function Test-Essential8-RegularBackups-Enhanced {
    Write-Host "`n=== Essential 8: Regular Backups (Enhanced) ===" -ForegroundColor Cyan
    
    $maturityLevel = 0
    $maturityFindings = @()
    
    try {
        # Maturity Level 1: Backups of important data, software, and configuration settings are performed and retained
        Write-Host "  Checking Maturity Level 1: Basic backup implementation..." -ForegroundColor Yellow
        
        # Check for OneDrive backup policies (Known Folder Move)
        try {
            $oneDrivePolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'OneDrive'" -ErrorAction SilentlyContinue
            if ($oneDrivePolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 1)
                $maturityFindings += "✓ Level 1: OneDrive backup policies configured ($($oneDrivePolicies.Count) policies)"
                Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "OneDrive backup policies implemented" -Severity "Good" -Details "User data backup via OneDrive configured"
            } else {
                $maturityFindings += "✗ Level 1: No OneDrive backup policies found"
                Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "OneDrive backup not configured" -Severity "High" -Recommendation "Implement OneDrive Known Folder Move policies for user data backup"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 1: Unable to check OneDrive backup policies"
        }

        # Maturity Level 2: Backups are performed at least daily with offline storage
        Write-Host "  Checking Maturity Level 2: Daily backups with offline storage..." -ForegroundColor Yellow
        
        # Check for comprehensive backup policies
        try {
            $backupPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Backup'" -ErrorAction SilentlyContinue
            if ($backupPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 2)
                $maturityFindings += "✓ Level 2: Comprehensive backup policies configured"
                Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "Daily backup policies implemented" -Severity "Good" -Details "Regular backup schedules configured"
            } else {
                $maturityFindings += "✗ Level 2: No comprehensive backup policies found"
                Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "Daily backup policies not configured" -Severity "Medium" -Recommendation "Implement daily backup policies with offline storage"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 2: Unable to check comprehensive backup policies"
        }

        # Maturity Level 3: Backups are tested and can be restored within Recovery Time Objectives
        Write-Host "  Checking Maturity Level 3: Tested backups with RTO compliance..." -ForegroundColor Yellow
        
        # Check for backup testing and recovery policies
        try {
            $recoveryPolicies = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName contains 'Recovery' or displayName contains 'Restore'" -ErrorAction SilentlyContinue
            if ($recoveryPolicies.Count -gt 0) {
                $maturityLevel = [Math]::Max($maturityLevel, 3)
                $maturityFindings += "✓ Level 3: Backup recovery and testing policies configured"
                Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "Backup testing and recovery procedures implemented" -Severity "Good" -Details "Recovery policies ensure RTO compliance"
            } else {
                $maturityFindings += "✗ Level 3: No backup testing/recovery policies found"
                Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "Backup testing procedures not configured" -Severity "Medium" -Recommendation "Implement backup testing and recovery procedures to meet RTO requirements"
            }
        }
        catch {
            $maturityFindings += "⚠ Level 3: Unable to check backup testing policies"
        }

        # Store results in script scope
        if (Get-Variable -Name "Essential8Results" -Scope Script -ErrorAction SilentlyContinue) {
            $script:Essential8Results.RegularBackups.Maturity = $maturityLevel
            $script:Essential8Results.RegularBackups.Details = $maturityFindings
            $script:Essential8Results.RegularBackups.Findings = $maturityFindings
        }
        
        # Store results in global scope for backward compatibility
        $Global:Essential8Results.RegularBackups = @{
            MaturityLevel = $maturityLevel
            MaxLevel = 3
            Findings = $maturityFindings
            Compliance = if ($maturityLevel -ge 2) { "Compliant" } elseif ($maturityLevel -eq 1) { "Partially Compliant" } else { "Non-Compliant" }
        }

        Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "Maturity Level $maturityLevel of 3 achieved" -Severity $(if ($maturityLevel -ge 2) { "Good" } elseif ($maturityLevel -eq 1) { "Medium" } else { "High" }) -Details "Based on Essential 8 maturity model"

    }
    catch {
        Write-AssessmentResult -Category "Essential 8: Regular Backups" -Finding "Unable to assess backup maturity" -Severity "Medium" -Details $_.Exception.Message
        $Global:Essential8Results.RegularBackups = @{
            MaturityLevel = 0
            MaxLevel = 3
            Findings = @("Assessment failed: $($_.Exception.Message)")
            Compliance = "Non-Compliant"
        }
    }
}

function Calculate-Essential8Score-Enhanced {
    Write-Host "`n📊 Calculating Enhanced Essential 8 Compliance Score..." -ForegroundColor Cyan
    
    $totalCategories = 8
    $totalMaturityPoints = 0
    $maxMaturityPoints = 24  # 8 categories × 3 max maturity level each
    
    # Calculate maturity scores for each category
    $categoryScores = @{}
    $maturityLevelSummary = @{}
    
    # Use script scope if available, fallback to global scope
    $results = if (Get-Variable -Name "Essential8Results" -Scope Script -ErrorAction SilentlyContinue) {
        $script:Essential8Results
    } else {
        $Global:Essential8Results
    }
    
    foreach ($category in $results.Keys) {
        $result = $results[$category]
        $maturityLevel = 0
        $maxLevel = 3
        $compliance = "Non-Compliant"
        
        if ($result -is [hashtable]) {
            # Check for new structure (Maturity property)
            if ($result.ContainsKey('Maturity')) {
                $maturityLevel = $result.Maturity
                $compliance = if ($maturityLevel -ge 2) { "Compliant" } elseif ($maturityLevel -eq 1) { "Partially Compliant" } else { "Non-Compliant" }
            }
            # Check for old structure (MaturityLevel property)
            elseif ($result.ContainsKey('MaturityLevel')) {
                $maturityLevel = $result.MaturityLevel
                $maxLevel = if ($result.ContainsKey('MaxLevel')) { $result.MaxLevel } else { 3 }
                $compliance = if ($result.ContainsKey('Compliance')) { $result.Compliance } else { 
                    if ($maturityLevel -ge 2) { "Compliant" } elseif ($maturityLevel -eq 1) { "Partially Compliant" } else { "Non-Compliant" }
                }
            }
        }
        
        $totalMaturityPoints += $maturityLevel
        $categoryScores[$category] = @{
            MaturityLevel = $maturityLevel
            MaxLevel = $maxLevel
            Compliance = $compliance
            Percentage = [math]::Round(($maturityLevel / $maxLevel) * 100, 1)
        }
        
        # Track maturity level distribution
        if (-not $maturityLevelSummary.ContainsKey($maturityLevel)) {
            $maturityLevelSummary[$maturityLevel] = 0
        }
        $maturityLevelSummary[$maturityLevel]++
    }
    
    $overallMaturityPercentage = [math]::Round(($totalMaturityPoints / $maxMaturityPoints) * 100, 1)
    
    Write-Host "  Essential 8 Maturity Assessment:" -ForegroundColor White
    foreach ($category in $categoryScores.Keys) {
        $score = $categoryScores[$category]
        $status = $score.Compliance
        $color = switch ($status) {
            "Compliant" { "Green" }
            "Partially Compliant" { "Yellow" }
            "Non-Compliant" { "Red" }
        }
        Write-Host "    $category : Level $($score.MaturityLevel)/$($score.MaxLevel) ($($score.Percentage)%) - $status" -ForegroundColor $color
    }
    
    Write-Host "`n  Overall Essential 8 Maturity: $overallMaturityPercentage% ($totalMaturityPoints/$maxMaturityPoints points)" -ForegroundColor $(
        if ($overallMaturityPercentage -ge 75) { "Green" }
        elseif ($overallMaturityPercentage -ge 50) { "Yellow" }
        else { "Red" }
    )
    
    # Maturity level distribution
    Write-Host "`n  Maturity Level Distribution:" -ForegroundColor White
    for ($level = 0; $level -le 3; $level++) {
        $count = if ($maturityLevelSummary.ContainsKey($level)) { $maturityLevelSummary[$level] } else { 0 }
        $levelName = switch ($level) {
            0 { "Not Implemented" }
            1 { "Basic (Level 1)" }
            2 { "Standard (Level 2)" }
            3 { "Advanced (Level 3)" }
        }
        Write-Host "    $levelName : $count categories" -ForegroundColor $(
            switch ($level) {
                0 { "Red" }
                1 { "Yellow" }
                2 { "Green" }
                3 { "Cyan" }
            }
        )
    }
    
    return @{
        OverallMaturityPercentage = $overallMaturityPercentage
        TotalMaturityPoints = $totalMaturityPoints
        MaxMaturityPoints = $maxMaturityPoints
        CategoryScores = $categoryScores
        MaturityLevelDistribution = $maturityLevelSummary
        ComplianceLevel = if ($overallMaturityPercentage -ge 75) { "High" } elseif ($overallMaturityPercentage -ge 50) { "Medium" } else { "Low" }
    }
}

# Export functions
Export-ModuleMember -Function Test-Essential8-PatchOperatingSystems-Enhanced, Test-Essential8-MultiFactor-Enhanced, Test-Essential8-RegularBackups-Enhanced, Calculate-Essential8Score-Enhanced 